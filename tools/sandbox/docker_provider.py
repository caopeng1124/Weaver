"""Offline, unprivileged containers with no host mounts or inherited credentials."""

from __future__ import annotations

import base64
import json
import os
import re
import selectors
import shutil
import subprocess
import time

from common.config import settings
from tools.sandbox.provider import ExecutionResult


class SandboxUnavailable(RuntimeError):
    pass


class DockerSandboxProvider:
    def __init__(self, installation: str):
        self.installation = installation
        self.binary = shutil.which("docker") or "docker"

    def _run(
        self, args: list[str], *, timeout: int = 30, stdin: bytes = b"", limit: int | None = None
    ) -> ExecutionResult:
        limit = limit or settings.sandbox_max_output_bytes
        # Docker's own config is needed to locate the local Desktop socket. None of
        # this environment is forwarded into the container.
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT", "TMPDIR"}
        }
        if env.get("DOCKER_HOST", "").startswith(("tcp:", "ssh:", "http:", "https:")):
            raise SandboxUnavailable("Local sandbox requires a local Unix Docker socket")
        try:
            # A regular input file avoids a pipe deadlock for large imports.
            import tempfile

            with tempfile.TemporaryFile() as input_file:
                input_file.write(stdin)
                input_file.seek(0)
                process = subprocess.Popen(
                    [self.binary, *args],
                    stdin=input_file,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
        except OSError as exc:
            raise SandboxUnavailable(
                "Docker is unavailable; install/start Docker Desktop. No host fallback."
            ) from exc
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = False
        deadline = time.monotonic() + timeout
        selector = selectors.DefaultSelector()
        try:
            for name in buffers:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                if time.monotonic() > deadline:
                    raise TimeoutError("Sandbox command timed out")
                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    available = max(0, limit - len(buffer))
                    buffer.extend(chunk[:available])
                    truncated |= len(chunk) > available
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise TimeoutError("Sandbox command timed out") from None
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()
        return ExecutionResult(
            process.returncode,
            buffers["stdout"].decode(errors="replace"),
            buffers["stderr"].decode(errors="replace"),
            truncated,
        )

    def diagnose(self) -> dict:
        try:
            # Resolve named contexts too: a 'local' sandbox must never silently use a remote daemon.
            context = self._run(["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"])
            endpoint = os.environ.get("DOCKER_HOST") or context.stdout.strip()
            if context.exit_code or not endpoint.startswith("unix://"):
                raise SandboxUnavailable("Select a local Docker context with a Unix socket")
            info = self._run(["info", "--format", "{{.ServerVersion}}"], timeout=10)
            if info.exit_code:
                raise SandboxUnavailable(
                    "Docker Desktop is not running or its socket is inaccessible"
                )
            image = self._run(["image", "inspect", settings.sandbox_image, "--format", "{{.Id}}"])
            return {
                "available": image.exit_code == 0,
                "docker_version": info.stdout.strip(),
                "image": settings.sandbox_image,
                "image_ready": image.exit_code == 0,
                "error": ""
                if image.exit_code == 0
                else "Build the sandbox image with make sandbox-build",
            }
        except (SandboxUnavailable, TimeoutError) as exc:
            return {"available": False, "error": str(exc), "image": settings.sandbox_image}

    def create(self, session_id: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{32}", session_id):
            raise ValueError("Invalid session id")
        diagnostic = self.diagnose()
        if not diagnostic["available"]:
            raise SandboxUnavailable(diagnostic["error"])
        name = f"weaver-sandbox-{session_id}"
        args = [
            "create",
            "--pull=never",
            "--name",
            name,
            "--label",
            f"weaver.installation={self.installation}",
            "--label",
            "weaver.role=sandbox",
            "--network",
            "none",
            "--read-only",
            "--init",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--user",
            "65534:65534",
            "--cpus",
            str(settings.sandbox_cpus),
            "--memory",
            f"{settings.sandbox_memory_mb}m",
            "--memory-swap",
            f"{settings.sandbox_memory_mb}m",
            "--pids-limit",
            "128",
            "--ulimit",
            "nofile=256:256",
            "--log-driver",
            "none",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777",
            "--tmpfs",
            f"/workspace:rw,nosuid,nodev,size={settings.sandbox_workspace_mb}m,mode=1777",
            "--workdir",
            "/workspace",
            "--env",
            "HOME=/tmp",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint",
            "python3",
            settings.sandbox_image,
            "-I",
            "-S",
            "-c",
            "import time; time.sleep(86400)",
        ]
        result = self._run(args)
        if result.exit_code:
            raise SandboxUnavailable(f"Cannot create sandbox: {result.stderr[:500]}")
        try:
            started = self._run(["start", name])
            if started.exit_code:
                raise SandboxUnavailable(f"Cannot start sandbox: {started.stderr[:500]}")
        except Exception:
            self.destroy(name)
            raise
        return name

    def _owned(self, container: str, *, missing_ok: bool = False) -> bool:
        if not re.fullmatch(r"weaver-sandbox-[a-f0-9]{32}", container):
            raise PermissionError("Invalid managed container")
        result = self._run(
            ["inspect", "--format", '{{index .Config.Labels "weaver.installation"}}', container]
        )
        if result.exit_code and missing_ok:
            # A missing container is already cleaned up; a dead daemon is not.
            listed = self._run(
                ["ps", "-a", "--filter", f"name=^/{container}$", "--format", "{{.Names}}"]
            )
            if listed.exit_code:
                raise SandboxUnavailable("Docker is unavailable during cleanup")
            if not listed.stdout.strip():
                return False
        if result.exit_code or result.stdout.strip() != self.installation:
            raise PermissionError("Container is not owned by this Weaver installation")
        return True

    def execute(
        self, container: str, command: list[str], *, timeout: int, stdin: bytes = b""
    ) -> ExecutionResult:
        self._owned(container)
        try:
            return self._run(
                ["exec", "-i", "--workdir", "/workspace", container, *command],
                timeout=min(max(1, timeout), settings.sandbox_timeout_seconds),
                stdin=stdin,
            )
        except (TimeoutError, subprocess.TimeoutExpired):
            # Killing docker exec alone would leave child processes running.
            try:
                self.destroy(container)
            except (RuntimeError, OSError) as exc:
                raise TimeoutError("Execution timed out; sandbox cleanup must be retried") from exc
            raise TimeoutError("Execution timed out; the entire sandbox was destroyed") from None

    def import_files(self, container: str, files: dict[str, bytes]) -> None:
        from tools.sandbox.workspace_files import validate_path

        for path in files:
            validate_path(path)
        if (
            len(files) > settings.sandbox_max_files
            or any(len(data) > settings.sandbox_max_file_bytes for data in files.values())
            or sum(map(len, files.values())) > settings.sandbox_max_import_bytes
        ):
            raise ValueError("Import exceeds configured limits")
        # docker cp rejects a read-only rootfs even when /workspace is a tmpfs.
        # Import through a fixed program as the unprivileged container user.
        payload = json.dumps(
            {path: base64.b64encode(data).decode() for path, data in files.items()}
        ).encode()
        script = """import base64,json,pathlib,sys
for path, data in json.load(sys.stdin).items():
    target = pathlib.Path('/workspace') / path
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(base64.b64decode(data,validate=True))
"""
        result = self.execute(
            container,
            ["python3", "-I", "-S", "-c", script],
            stdin=payload,
            timeout=settings.sandbox_timeout_seconds,
        )
        if result.exit_code:
            raise SandboxUnavailable(f"Import failed: {result.stderr[:500]}")

    def snapshot(self, container: str) -> dict[str, bytes]:
        self._owned(container)
        # Never extract a container-generated tar onto the host. Read only regular
        # files with no symlink traversal and bounded total bytes/file counts.
        script = snapshot_script()
        try:
            result = self._run(
                ["exec", container, "python3", "-I", "-S", "-c", script],
                timeout=settings.sandbox_timeout_seconds,
                limit=settings.sandbox_max_import_bytes * 2 + settings.sandbox_max_files * 1024,
            )
        except TimeoutError:
            try:
                self.destroy(container)
            except (RuntimeError, OSError) as exc:
                raise TimeoutError("Export timed out; sandbox cleanup must be retried") from exc
            raise TimeoutError("Export timed out; the entire sandbox was destroyed") from None
        if result.exit_code or result.truncated:
            raise ValueError("Cannot export sandbox workspace within configured limits")
        values = json.loads(result.stdout)
        if not isinstance(values, dict) or len(values) > settings.sandbox_max_files:
            raise ValueError("Invalid workspace snapshot")
        files = {path: base64.b64decode(data, validate=True) for path, data in values.items()}
        if sum(map(len, files.values())) > settings.sandbox_max_import_bytes:
            raise ValueError("Workspace exceeds export limits")
        return files

    def destroy(self, container: str) -> None:
        if not self._owned(container, missing_ok=True):
            return
        result = self._run(["rm", "--force", container])
        if result.exit_code:
            raise SandboxUnavailable("Failed to remove managed sandbox")

    def recover(self) -> None:
        result = self._run(
            [
                "ps",
                "-a",
                "--filter",
                f"label=weaver.installation={self.installation}",
                "--filter",
                "label=weaver.role=sandbox",
                "--format",
                "{{.Names}}",
            ],
            timeout=10,
        )
        if result.exit_code:
            raise SandboxUnavailable("Docker is unavailable during orphan cleanup")
        for name in result.stdout.splitlines():
            self.destroy(name)


def snapshot_script() -> str:
    script = r"""
import os, stat, json, base64
root = '/workspace'
result = {}
total = 0
for directory, dirs, files in os.walk(root, followlinks=False):
    dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(directory, d)))
    for name in sorted(files):
        path = os.path.join(directory, name)
        if not stat.S_ISREG(os.lstat(path).st_mode):
            continue
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                continue
            data = handle.read(MAX_FILE + 1)
        total += len(data)
        if len(data) > MAX_FILE or total > MAX_TOTAL or len(result) >= MAX_FILES:
            raise ValueError('Workspace exceeds export limits')
        result[os.path.relpath(path, root)] = base64.b64encode(data).decode('ascii')
print(json.dumps(result))
"""
    script = (
        f"MAX_FILE={settings.sandbox_max_file_bytes}; MAX_TOTAL={settings.sandbox_max_import_bytes}; MAX_FILES={settings.sandbox_max_files}\n"
        + script
    )
    return script
