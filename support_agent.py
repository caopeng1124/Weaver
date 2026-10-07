"""
Customer Support Agent with Mem0 memory.

Provides a simple LangGraph that:
- Retrieves relevant memories for the user
- Builds application instructions separately from recalled context
- Stores the interaction back to memory
"""

import json
from typing import Annotated, List, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from agent.core.context_builder import ContextBlock, build_context
from common.config import settings
from common.security.models import ChatOpenAI
from tools.core.memory_client import fetch_memories, store_interaction


class SupportState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    user_id: str


def _support_model() -> ChatOpenAI:
    params = {
        "temperature": 0.3,
        "model": settings.primary_model,
        "api_key": settings.openai_api_key,
        "timeout": settings.openai_timeout or None,
    }
    if settings.use_azure:
        params.update(
            {
                "azure_endpoint": settings.azure_endpoint or None,
                "azure_deployment": settings.primary_model,
                "api_version": settings.azure_api_version or None,
                "api_key": settings.azure_api_key or settings.openai_api_key,
            }
        )
    elif settings.openai_base_url:
        params["base_url"] = settings.openai_base_url

    extra = {}
    if settings.openai_extra_body:
        try:
            extra.update(json.loads(settings.openai_extra_body))
        except Exception:
            pass
    if extra:
        params["extra_body"] = extra
    return ChatOpenAI(**params)


def support_node(state: SupportState):
    messages = state["messages"]
    user_id = state.get("user_id") or settings.memory_user_id
    last_user_message = ""
    task_index = None
    for index in range(len(messages) - 1, -1, -1):
        msg = messages[index]
        if isinstance(msg, HumanMessage) and msg.name not in {"context_data", "agent_preferences"}:
            last_user_message = msg.content
            task_index = index
            break

    # Retrieve memories
    mem_entries = fetch_memories(query=last_user_message, user_id=user_id)
    llm = _support_model()
    history = [msg for index, msg in enumerate(messages) if index != task_index]
    response = llm.invoke(
        build_context(
            "support",
            history=history,
            user=last_user_message,
            data=[ContextBlock("recalled_memory", mem_entries)] if mem_entries else [],
        )
    )
    reply_text = response.content if hasattr(response, "content") else str(response)

    # Store interaction
    if last_user_message:
        store_interaction(last_user_message, reply_text, user_id=user_id)

    return {"messages": [AIMessage(content=reply_text)]}


def create_support_graph(checkpointer=None, store=None):
    graph = StateGraph(SupportState)
    graph.add_node("support", support_node)
    graph.add_edge(START, "support")
    graph.add_edge("support", END)
    return graph.compile(checkpointer=checkpointer, store=store)
