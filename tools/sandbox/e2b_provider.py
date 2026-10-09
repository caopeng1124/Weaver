"""Explicit E2B backend. No automatic fallback from Docker or host execution."""

from __future__ import annotations

import base64
import json
import shlex
import uuid

from common.config import settings
from tools.sandbox.docker_provider import SandboxUnavailable, snapshot_script
from tools.sandbox.provider import ExecutionResult
from tools.sandbox.workspace_files import validate_path

_RUNNER = r"""
import json,subprocess,selectors,os,time,sys,tempfile
payload=json.load(open(sys.argv[1]))
with tempfile.TemporaryFile() as source:
    import base64
    source.write(base64.b64decode(payload['stdin'])); source.seek(0)
    p=subprocess.Popen(payload['command'],stdin=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,cwd='/workspace')
buffers={'stdout':bytearray(),'stderr':bytearray()}; truncated=False
selector=selectors.DefaultSelector()
for name in buffers:
    pipe=getattr(p,name); os.set_blocking(pipe.fileno(),False); selector.register(pipe,selectors.EVENT_READ,name)
deadline=time.monotonic()+payload['timeout']; timed_out=False
try:
    while selector.get_map():
        if time.monotonic()>deadline:
            timed_out=True; break
        for key,_ in selector.select(0.1):
            chunk=os.read(key.fd,65536)
            if not chunk: selector.unregister(key.fileobj); continue
            available=max(0,payload['limit']-len(buffers[key.data]))
            buffers[key.data].extend(chunk[:available]); truncated |= len(chunk)>available
    if not timed_out:
        try: p.wait(timeout=max(0.1,deadline-time.monotonic()))
        except subprocess.TimeoutExpired: timed_out=True
finally:
    import signal
    try: os.killpg(p.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    p.wait(); selector.close()
print(json.dumps(dict(exit_code=p.returncode,stdout=buffers['stdout'].decode(errors='replace'),stderr=buffers['stderr'].decode(errors='replace'),truncated=truncated,timed_out=timed_out)))
"""


class E2BSandboxProvider:
    def __init__(self, installation: str):
        self.installation = installation
        self._sessions = {}

    def _sdk(self):
        if not settings.e2b_api_key or not settings.e2b_api_key.startswith("e2b_"):
            raise SandboxUnavailable(
                "E2B mode requires E2B_API_KEY; Docker is not used as an implicit fallback"
            )
        from common.e2b_env import prepare_e2b_env

        prepare_e2b_env()
        from e2b import Sandbox

        return Sandbox

    def diagnose(self):
        try:
            self._sdk()
            return {
                "available": True,
                "backend": "e2b",
                "template": settings.sandbox_e2b_template,
                "connectivity_verified": False,
            }
        except (ImportError, RuntimeError) as exc:
            return {"available": False, "backend": "e2b", "error": str(exc)}

    def create(self, session_id: str) -> str:
        sandbox = self._sdk().create(
            api_key=settings.e2b_api_key,
            template=settings.sandbox_e2b_template,
            timeout=settings.sandbox_idle_seconds + settings.sandbox_timeout_seconds,
            metadata={
                "weaver.installation": self.installation,
                "weaver.role": "sandbox",
                "weaver.session": session_id,
            },
            allow_internet_access=settings.sandbox_allow_internet,
        )
        try:
            sandbox.commands.run(
                "mkdir -p /workspace && chown user:user /workspace", user="root", timeout=30
            )
        except Exception:
            sandbox.kill()
            raise
        self._sessions[sandbox.sandbox_id] = sandbox
        return sandbox.sandbox_id

    def _owned(self, container: str):
        if container not in self._sessions:
            sandbox = self._sdk().connect(container, api_key=settings.e2b_api_key)
            if sandbox.get_info().metadata.get("weaver.installation") != self.installation:
                raise PermissionError("E2B sandbox is not owned by this installation")
            self._sessions[container] = sandbox
        return self._sessions[container]

    def _execute(self, container, command, *, timeout, stdin=b"", limit=None):
        sandbox = self._owned(container)
        timeout = min(max(1, timeout), settings.sandbox_timeout_seconds)
        sandbox.set_timeout(settings.sandbox_idle_seconds + timeout)
        token = uuid.uuid4().hex
        runner, payload_path = f"/tmp/weaver-{token}.py", f"/tmp/weaver-{token}.json"
        sandbox.files.write(runner, _RUNNER)
        sandbox.files.write(
            payload_path,
            json.dumps(
                {
                    "command": command,
                    "stdin": base64.b64encode(stdin).decode(),
                    "timeout": timeout,
                    "limit": limit or settings.sandbox_max_output_bytes,
                }
            ),
        )
        try:
            result = sandbox.commands.run(
                shlex.join(["python3", "-I", "-S", runner, payload_path]),
                user="user",
                timeout=timeout + 5,
                request_timeout=timeout + 10,
            )
            value = json.loads(result.stdout)
            if value.pop("timed_out"):
                raise TimeoutError("Execution timed out; E2B sandbox destroyed")
            return ExecutionResult(**value)
        except Exception:
            # A lost RPC must not leave arbitrary code running in the cloud.
            self.destroy(container)
            raise
        finally:
            if container in self._sessions:
                sandbox.files.remove(runner)
                sandbox.files.remove(payload_path)

    def execute(self, container, command, *, timeout, stdin=b""):
        return self._execute(container, command, timeout=timeout, stdin=stdin)

    def import_files(self, container, files):
        if (
            len(files) > settings.sandbox_max_files
            or sum(map(len, files.values())) > settings.sandbox_max_import_bytes
        ):
            raise ValueError("Import exceeds configured limits")
        sandbox = self._owned(container)
        for path, data in files.items():
            validate_path(path)
            if len(data) > settings.sandbox_max_file_bytes:
                raise ValueError("File exceeds configured size limit")
            sandbox.files.write("/workspace/" + path, data, user="user")

    def snapshot(self, container):
        result = self._execute(
            container,
            ["python3", "-I", "-S", "-c", snapshot_script()],
            timeout=settings.sandbox_timeout_seconds,
            limit=settings.sandbox_max_import_bytes * 2 + settings.sandbox_max_files * 1024,
        )
        if result.exit_code or result.truncated:
            raise ValueError("Cannot export sandbox workspace within configured limits")
        values = json.loads(result.stdout)
        if not isinstance(values, dict) or len(values) > settings.sandbox_max_files:
            raise ValueError("Invalid workspace snapshot")
        files = {path: base64.b64decode(data, validate=True) for path, data in values.items()}
        if (
            any(len(data) > settings.sandbox_max_file_bytes for data in files.values())
            or sum(map(len, files.values())) > settings.sandbox_max_import_bytes
        ):
            raise ValueError("Workspace exceeds export limits")
        return files

    def destroy(self, container):
        from e2b import NotFoundException

        try:
            sandbox = self._owned(container)
            sandbox.kill()
        except NotFoundException:
            pass
        self._sessions.pop(container, None)

    def recover(self):
        from e2b import SandboxQuery

        paginator = self._sdk().list(
            api_key=settings.e2b_api_key,
            query=SandboxQuery(
                metadata={"weaver.installation": self.installation, "weaver.role": "sandbox"}
            ),
        )
        while paginator.has_next:
            for sandbox in paginator.next_items():
                self.destroy(sandbox.sandbox_id)
