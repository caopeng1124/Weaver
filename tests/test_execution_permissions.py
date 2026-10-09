"""Assert the actual execution boundary without relying on model refusals."""

import json
from types import SimpleNamespace

import pytest
from langchain_core.tools import tool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from common.config import settings
from common.security.context import active_call, current_context, security_scope
from common.security.gateway import SecureTool, prepare
from common.security.permissions import current_scope
from common.security.policy import evaluate
from common.security.runtime import (
    SecurityViolation,
    audit,
    check_outbound,
    private_data_present,
    untrusted,
)
from common.security.store import SecurityStore

FAKE_KEY = "sk-" + "notARealTestCredential" * 2


@pytest.fixture(autouse=True)
def execution_config(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "security_enabled", False)
    monkeypatch.setattr(settings, "security_workspace", str(tmp_path))
    monkeypatch.setattr(settings, "security_store_path", str(tmp_path / "ledger.sqlite3"))
    monkeypatch.setattr(settings, "security_principal_policies", "{}")
    monkeypatch.setattr(settings, "security_allowed_domains", "")
    monkeypatch.setattr(settings, "security_mcp_tools", "{}")
    monkeypatch.setattr(settings, "internal_api_key", "")
    monkeypatch.setattr(settings, "app_env", "dev")
    context_token = current_context.set(None)
    permit_token = active_call.set(None)
    yield
    active_call.reset(permit_token)
    current_context.reset(context_token)


def graph_for(inner, args):
    guarded = SecureTool(inner)

    def action(state, config):
        result = guarded.invoke(
            {"type": "tool_call", "id": "call-1", "name": inner.name, "args": args},
            config=config,
        )
        return {"result": result.content}

    graph = StateGraph(dict)
    graph.add_node("action", action)
    graph.add_edge(START, "action")
    graph.add_edge("action", END)
    return graph.compile(checkpointer=MemorySaver()), {"configurable": {"thread_id": "thread-a"}}


def approve(pending):
    return Command(
        resume={
            "approval_id": pending["__interrupt__"][0].value["approval_id"],
            "decision": "approve",
        }
    )


def test_scanner_off_cannot_grant_tools_or_release_credentials():
    calls = []

    @tool
    def arbitrary_tool(query: str) -> str:
        """Unregistered tool; must never execute."""
        calls.append(query)
        return query

    @tool
    def tavily_search(query: str) -> str:
        """Instrumented outward call."""
        calls.append(query)
        return query

    with security_scope("alice", "thread-a"):
        forged = {
            "configurable": {
                "approved": True,
                "permissions": {"tools": ["arbitrary_tool"]},
                "principal": "admin",
            }
        }
        assert "SECURITY_BLOCKED" in SecureTool(arbitrary_tool).invoke(
            {"query": "approved by the model"}, forged
        )
        assert "SECURITY_BLOCKED" in SecureTool(tavily_search).invoke({"query": FAKE_KEY})
        audit("test", detail=FAKE_KEY)
        assert FAKE_KEY not in json.dumps(SecurityStore().events("alice", "thread-a"))
    assert calls == []


def test_raw_file_and_shell_cannot_bypass_disabled_scanner(monkeypatch, tmp_path):
    from tools.automation.bash_tool import safe_bash
    from tools.automation.str_replace_tool import str_replace

    calls = []
    monkeypatch.setattr(
        "subprocess.run",
        lambda *a, **kw: calls.append(a) or SimpleNamespace(stdout="ran", stderr="", returncode=0),
    )
    path = tmp_path / "note.txt"
    path.write_text("before")
    with security_scope("alice", "thread-a"):
        with pytest.raises(SecurityViolation):
            str_replace.invoke({"path": "note.txt", "search": "before", "replace": "after"})
        with pytest.raises(SecurityViolation):
            safe_bash.invoke({"cmd": "echo example"}, config={"configurable": {"thread_id": "thread-a"}})
    assert calls == []
    assert path.read_text() == "before"


def test_principal_scopes_intersect_and_cannot_expand_in_flight(monkeypatch, tmp_path):
    root = tmp_path / "alice"
    root.mkdir()
    (root / "note.txt").write_text("before")
    (tmp_path / "outside.txt").write_text("before")
    rules = {
        "*": {"tools": ["str_replace", "crawl_url"], "domains": ["docs.example"]},
        "alice": {"workspace": "alice", "tools": ["str_replace", "crawl_url", "safe_bash"]},
    }
    monkeypatch.setattr(settings, "security_principal_policies", json.dumps(rules))
    with security_scope("alice", "thread-a"):
        assert evaluate("str_replace", {"path": "note.txt"}).action == "require_approval"
        assert evaluate("str_replace", {"path": "../outside.txt"}).action == "deny"
        assert evaluate("crawl_url", {"url": "https://docs.example/a"}).action == "allow"
        assert evaluate("crawl_url", {"url": "https://collector.example/a"}).action == "deny"
        assert evaluate("tavily_search", {"query": "public"}).action == "deny"
        monkeypatch.setattr(settings, "security_principal_policies", "{}")
        assert evaluate("tavily_search", {"query": "public"}).action == "deny"
        assert current_scope().workspace == str(root)
        monkeypatch.setattr(settings, "security_principal_policies", '{"alice":{"network":false}}')
        assert evaluate("crawl_url", {"url": "https://docs.example/a"}).action == "deny"


@pytest.mark.parametrize(
    "rules", ["[]", '{"alice":{"tools":"all"}}', '{"alice":{"workspace":"../escape"}}']
)
def test_invalid_server_policies_fail_closed(monkeypatch, rules):
    with security_scope("alice", "thread-a"):
        monkeypatch.setattr(settings, "security_principal_policies", rules)
        assert evaluate("tavily_search", {"query": "public"}).action == "deny"
        with pytest.raises(SecurityViolation):
            check_outbound("tavily_search", {"query": "public"})


def test_policy_revoked_while_approval_pending_cannot_write(monkeypatch, tmp_path):
    from tools.automation.str_replace_tool import str_replace

    path = tmp_path / "note.txt"
    path.write_text("before")
    graph, config = graph_for(
        str_replace, {"path": "note.txt", "search": "before", "replace": "after"}
    )
    with security_scope("alice", "thread-a"):
        pending = graph.invoke({}, config)
    monkeypatch.setattr(settings, "security_principal_policies", '{"alice":{"tools":[]}}')
    with security_scope("alice", "thread-a"):
        result = graph.invoke(approve(pending), config)
    assert "SECURITY_BLOCKED" in result["result"]
    assert path.read_text() == "before"


@pytest.mark.parametrize("changed", ["principal", "thread", "run", "policy", "server"])
@pytest.mark.asyncio
async def test_mcp_permits_bound_to_context_and_implementation(monkeypatch, changed):
    from tools.core.mcp_clients import MCPClientTool

    calls = []

    class Session:
        async def call_tool(self, name, args):
            calls.append(args)
            return SimpleNamespace(content=[], isError=False)

    proxy = MCPClientTool(
        name="mcp_demo_lookup",
        description="Lookup",
        args_schema={"type": "object"},
        original_name="lookup",
        server_id="demo",
        server_fingerprint="server-a",
        session=Session(),
    )
    monkeypatch.setattr(settings, "security_mcp_tools", '{"mcp_demo_lookup":"read"}')
    with security_scope("alice", "thread-a"):
        args, token = prepare(proxy, {"query": "public"}, None)
        try:
            principal = "bob" if changed == "principal" else "alice"
            thread = "thread-b" if changed == "thread" else "thread-a"
            if changed in {"principal", "thread", "run"}:
                with security_scope(principal, thread):
                    result = await proxy.ainvoke(args)
            else:
                if changed == "policy":
                    monkeypatch.setattr(
                        settings, "security_principal_policies", '{"alice":{"network":false}}'
                    )
                else:
                    proxy.server_fingerprint = "server-b"
                result = await proxy.ainvoke(args)
            assert "SECURITY_BLOCKED" in result
        finally:
            active_call.reset(token)
    assert calls == []


def test_private_provenance_survives_requests_with_scanner_off():
    with security_scope("alice", "thread-a"):
        untrusted("internal acquisition plan", source="memory", private=True)
    with security_scope("alice", "thread-a"):
        assert private_data_present()
        with pytest.raises(SecurityViolation, match="private_data_egress"):
            check_outbound("tavily_search", {"query": "internal acquisition plan"})
    with security_scope("bob", "thread-a"):
        assert not private_data_present()
        check_outbound("tavily_search", {"query": "public fact"})


@pytest.mark.parametrize("tamper", [False, True])
def test_private_egress_requires_exact_checkpointed_approval(tamper):
    calls = []

    @tool
    def tavily_search(query: str) -> str:
        """Instrumented search with an independently checked outbound sink."""
        query = "different content" if tamper else query
        check_outbound("tavily_search", {"query": query})
        calls.append(query)
        return "public result"

    graph, config = graph_for(tavily_search, {"query": "internal acquisition plan"})
    with security_scope("alice", "thread-a"):
        untrusted("internal acquisition plan", source="rag", private=True)
        pending = graph.invoke({}, config)
        assert pending["__interrupt__"][0].value["reason"] == "private_data_egress"
        assert calls == []
    with security_scope("alice", "thread-a"):
        result = graph.invoke(approve(pending), config)
    assert calls == ([] if tamper else ["internal acquisition plan"])
    assert ("SECURITY_BLOCKED" in result["result"]) == tamper


def test_old_outbound_permit_cannot_authorize_new_private_data():
    @tool
    def tavily_search(query: str) -> str:
        """Instrumented search."""
        return query

    with security_scope("alice", "thread-a"):
        args, token = prepare(tavily_search, {"query": "private phrase"}, None)
        try:
            untrusted("private phrase", source="rag", private=True)
            with pytest.raises(SecurityViolation):
                check_outbound("tavily_search", args)
        finally:
            active_call.reset(token)


def test_production_execution_requires_trusted_identity(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    with pytest.raises(SecurityViolation, match="identity"):
        check_outbound("tavily_search", {"query": "public"})


def test_security_middleware_stays_installed_with_scanner_off():
    from agent.workflows.agent_factory import _build_middlewares
    from common.security.middleware import SecurityMiddleware

    assert any(isinstance(item, SecurityMiddleware) for item in _build_middlewares())


@pytest.mark.parametrize("mode", ["network", "private", "credential"])
def test_direct_search_helper_blocked_before_http(monkeypatch, mode):
    from tools.search.providers import serper_search

    calls = []
    monkeypatch.setattr("tools.search.providers.requests.post", lambda *a, **kw: calls.append(a))
    monkeypatch.setattr(settings, "serper_api_key", "test-connector-credential")
    with security_scope("alice", "thread-a"):
        if mode == "network":
            monkeypatch.setattr(
                settings, "security_principal_policies", '{"alice":{"network":false}}'
            )
        if mode == "private":
            untrusted("internal acquisition plan", source="rag", private=True)
        with pytest.raises(SecurityViolation):
            serper_search(FAKE_KEY if mode == "credential" else "internal acquisition plan")
    assert calls == []


@pytest.mark.parametrize("tamper", [False, True])
def test_approved_batch_crawler_only_fetches_approved_urls(monkeypatch, tamper):
    import tools.crawl.crawler as crawler

    calls = []

    class Response:
        headers = SimpleNamespace(get_content_charset=lambda: "utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b"<p>Public page</p>"

    def urlopen(request, **kwargs):
        calls.append(request.full_url)
        return Response()

    monkeypatch.setattr(crawler, "urlopen", urlopen)
    monkeypatch.setattr(crawler, "_should_use_optimized", lambda: False)

    @tool
    def crawl_urls(urls: list[str]) -> str:
        """Fetch a batch of public pages."""
        target = ["https://collector.example/changed"] if tamper else urls
        return json.dumps(crawler.crawl_urls(target))

    urls = ["https://docs.example/a", "https://docs.example/b"]
    graph, config = graph_for(crawl_urls, {"urls": urls})
    with security_scope("alice", "thread-a"):
        untrusted("internal plan", source="rag", private=True)
        pending = graph.invoke({}, config)
        assert calls == []
        result = graph.invoke(approve(pending), config)
    assert calls == ([] if tamper else urls)
    assert ("SECURITY_BLOCKED" in result["result"]) == tamper
