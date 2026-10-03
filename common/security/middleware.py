"""Cover middleware-created tools as well as statically registered tools."""

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.config import get_config

from common.security.context import active_call, call_id
from common.security.gateway import denied, prepare
from common.security.runtime import SecurityViolation
from common.security.store import ApprovalError


class SecurityMiddleware(AgentMiddleware):
    def wrap_tool_call(self, request, handler):
        token = None
        call_token = call_id.set(request.tool_call["id"])
        try:
            args, token = prepare(request.tool, request.tool_call["args"], get_config())
            return handler(request.override(tool_call={**request.tool_call, "args": args}))
        except (SecurityViolation, ApprovalError) as error:
            return ToolMessage(
                content=denied(request.tool_call["name"], error),
                tool_call_id=request.tool_call["id"],
                status="error",
            )
        finally:
            call_id.reset(call_token)
            if token is not None:
                active_call.reset(token)

    async def awrap_tool_call(self, request, handler):
        token = None
        call_token = call_id.set(request.tool_call["id"])
        try:
            args, token = prepare(request.tool, request.tool_call["args"], get_config())
            return await handler(request.override(tool_call={**request.tool_call, "args": args}))
        except (SecurityViolation, ApprovalError) as error:
            return ToolMessage(
                content=denied(request.tool_call["name"], error),
                tool_call_id=request.tool_call["id"],
                status="error",
            )
        finally:
            call_id.reset(call_token)
            if token is not None:
                active_call.reset(token)
