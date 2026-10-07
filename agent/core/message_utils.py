import logging
from typing import List

from langchain_core.messages import BaseMessage, HumanMessage

from agent.core.context_builder import ContextBlock, build_context, data_message
from agent.core.llm_factory import create_summary_model
from common.config import settings

logger = logging.getLogger(__name__)

# Use shared factory
_chat_model_summary = create_summary_model


def _messages_to_text(messages: List[BaseMessage]) -> str:
    lines = []
    for m in messages:
        role = m.type if hasattr(m, "type") else m.__class__.__name__
        content = getattr(m, "content", "")
        if isinstance(content, list):
            # for multimodal, keep text parts only
            text_parts = [p.get("text", "") for p in content if isinstance(p, dict)]
            content = "\n".join(text_parts)
        lines.append(f"[{role}] {content}")
    return "\n".join(lines)


def summarize_messages(messages: List[BaseMessage]) -> HumanMessage:
    """Summarize history as untrusted data, retaining that status on fallback."""
    if not messages:
        return data_message("Conversation summary: (empty)", source="conversation_summary")

    llm = _chat_model_summary()
    word_limit = int(settings.summary_messages_word_limit or 200)
    convo_text = _messages_to_text(messages)
    try:
        resp = llm.invoke(
            build_context(
                "summary", data=[ContextBlock("conversation", convo_text)], max_items=word_limit
            )
        )
        content = getattr(resp, "content", "") or convo_text[:500]
    except Exception as e:
        logger.warning(f"Summarization failed, falling back to truncation: {e}")
        content = convo_text[:500]

    return data_message(content.strip(), source="conversation_summary")
