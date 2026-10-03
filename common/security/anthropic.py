"""Optional provider adapter, imported only when Anthropic is installed."""

from langchain_anthropic import ChatAnthropic as _ChatAnthropic

from common.security.content import enabled
from common.security.models import SAFETY_INSTRUCTION, _OutputProtection, protect_payload


class ChatAnthropic(_OutputProtection, _ChatAnthropic):
    def _get_request_payload(self, input_, *, stop=None, **kwargs):
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        if not enabled():
            return payload
        # Anthropic has a separate system field and disallows system-role messages.
        messages = payload.pop("messages", [])
        payload = protect_payload(payload)
        from common.security.content import redact

        payload["messages"] = redact(messages)
        system = payload.get("system")
        payload["system"] = (
            [{"type": "text", "text": SAFETY_INSTRUCTION}, *system]
            if isinstance(system, list)
            else SAFETY_INSTRUCTION + "\n" + (system or "")
        )
        return payload
