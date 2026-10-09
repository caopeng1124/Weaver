"""SDK contract tests without API keys, cloud calls or quota consumption."""

import json
from types import SimpleNamespace

import pytest

from common.config import settings
from tools.sandbox.e2b_provider import E2BSandboxProvider


class Files:
    def __init__(self):
        self.values = {}

    def write(self, path, content, **kwargs):
        self.values[path] = content

    def remove(self, path):
        self.values.pop(path, None)


@pytest.fixture
def cloud(monkeypatch):
    monkeypatch.setattr(settings, "e2b_api_key", "e2b_contract_test")
    monkeypatch.setattr(settings, "sandbox_allow_internet", False)
    calls = []
    sandbox = SimpleNamespace(sandbox_id="test-cloud", files=Files(), killed=False)
    sandbox.set_timeout = lambda value: calls.append(("timeout", value))

    def kill():
        sandbox.killed = True

    sandbox.kill = kill
    sandbox.commands = SimpleNamespace(
        run=lambda *a, **kw: SimpleNamespace(
            stdout=json.dumps(
                {
                    "exit_code": 0,
                    "stdout": "ok",
                    "stderr": "",
                    "truncated": False,
                    "timed_out": False,
                }
            )
        )
    )
    sandbox.get_info = lambda: SimpleNamespace(metadata={"weaver.installation": "owned"})

    def create(**kwargs):
        calls.append(("create", kwargs))
        return sandbox

    sdk = SimpleNamespace(create=create, connect=lambda *a, **kw: sandbox)
    provider = E2BSandboxProvider("owned")
    monkeypatch.setattr(provider, "_sdk", lambda: sdk)
    return provider, sandbox, sdk, calls


def test_explicit_cloud_session_contract(cloud):
    provider, sandbox, _, calls = cloud
    container = provider.create("session")
    params = calls[0][1]
    assert params["allow_internet_access"] is False
    assert params["metadata"]["weaver.installation"] == "owned"
    assert "envs" not in params
    provider.import_files(container, {"sub/file.txt": b"input"})
    assert sandbox.files.values["/workspace/sub/file.txt"] == b"input"
    assert (
        provider.execute(container, ["python3", "-"], timeout=1, stdin=b"print(1)").stdout == "ok"
    )
    assert not any(path.startswith("/tmp/weaver-") for path in sandbox.files.values)
    provider.destroy(container)
    assert sandbox.killed


def test_cloud_timeout_kills_entire_instance(cloud):
    provider, sandbox, _, _ = cloud
    container = provider.create("session")
    sandbox.commands.run = lambda *a, **kw: SimpleNamespace(stdout=json.dumps({"timed_out": True}))
    with pytest.raises(TimeoutError):
        provider.execute(container, ["sleep", "60"], timeout=1)
    assert sandbox.killed and container not in provider._sessions


def test_recovery_uses_sdk_query_and_installation_ownership(cloud):
    from e2b import SandboxQuery

    provider, sandbox, sdk, _ = cloud

    class Pages:
        has_next = True

        def next_items(self):
            self.has_next = False
            return [SimpleNamespace(sandbox_id=sandbox.sandbox_id)]

    def list_sandboxes(**kwargs):
        assert isinstance(kwargs["query"], SandboxQuery)
        assert kwargs["query"].metadata["weaver.installation"] == "owned"
        return Pages()

    sdk.list = list_sandboxes
    provider.recover()
    assert sandbox.killed
    sandbox.get_info = lambda: SimpleNamespace(metadata={"weaver.installation": "other"})
    with pytest.raises(PermissionError):
        provider._owned("not-ours")
