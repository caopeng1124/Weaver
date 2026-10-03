from types import SimpleNamespace

import pytest

from agent.core import smart_router
from agent.workflows.nodes import route_node
from common.config import settings
from main import ChatRequest, _normalize_search_mode


@pytest.mark.parametrize("payload", ["auto", {"autoRoute": True}, {"mode": "auto"}])
@pytest.mark.parametrize("chosen", ["direct", "web", "agent", "deep"])
def test_auto_request_reaches_router_and_preserves_decision(monkeypatch, payload, chosen):
    request = ChatRequest(
        messages=[{"role": "user", "content": "help with this task"}], search_mode=payload
    )
    mode = _normalize_search_mode(request.search_mode)
    # Streaming normalizes once at the endpoint and again at execution time.
    assert _normalize_search_mode(mode) == mode
    calls = []

    def choose(*args):
        calls.append(args)
        return SimpleNamespace(
            route=chosen, confidence=0.9, reasoning="chosen by router", suggested_queries=[]
        )

    monkeypatch.setattr(settings, "domain_routing_enabled", False)
    monkeypatch.setattr(smart_router, "get_smart_router", lambda: SimpleNamespace(route=choose))
    result = route_node({"input": "help with this task"}, {"configurable": {"search_mode": mode}})
    assert calls and result["route"] == chosen


def test_deep_research_remains_an_explicit_override(monkeypatch):
    def unexpected():
        pytest.fail("Explicit Deep Research must not call the automatic classifier")

    monkeypatch.setattr(settings, "domain_routing_enabled", False)
    monkeypatch.setattr(smart_router, "get_smart_router", unexpected)
    request = ChatRequest(messages=[], search_mode={"useAgent": True, "useDeepSearch": True})
    result = route_node(
        {"input": "research this"},
        {"configurable": {"search_mode": _normalize_search_mode(request.search_mode)}},
    )
    assert result["route"] == "deep"


def test_auto_low_confidence_still_requests_clarification(monkeypatch):
    monkeypatch.setattr(settings, "domain_routing_enabled", False)
    monkeypatch.setattr(
        smart_router, "smart_route", lambda **kwargs: {"route": "web", "routing_confidence": 0.2}
    )
    result = route_node(
        {"input": "unclear"}, {"configurable": {"search_mode": _normalize_search_mode("auto")}}
    )
    assert result["route"] == "clarify" and result["needs_clarification"]
