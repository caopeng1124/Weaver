"""Bind sandbox capabilities to the trusted request and one-use tool permit."""

from dataclasses import dataclass

from langchain_core.runnables import RunnableConfig

from common.config import settings
from common.security.context import active_call, current_context
from common.security.policy import digest
from common.security.runtime import SecurityViolation

SANDBOX_TOOLS = {
    "execute_python_code": ("tools.code.code_executor", "sandbox.execute"),
    "safe_bash": ("tools.automation.bash_tool", "sandbox.execute"),
    "sandbox_list_files": ("tools.sandbox.local_tools", "sandbox.read"),
    "sandbox_read_file": ("tools.sandbox.local_tools", "sandbox.read"),
    "sandbox_write_file": ("tools.sandbox.local_tools", "sandbox.write"),
}


@dataclass(frozen=True)
class ExecutionContext:
    principal_id: str
    thread_id: str
    run_id: str
    profile: str = "sandbox"


@dataclass(frozen=True)
class Decision:
    effect: str
    reason: str = ""


class PolicyEngine:
    def evaluate(self, action: str, context: ExecutionContext) -> Decision:
        if settings.sandbox_mode not in {"docker", "e2b", "local"}:
            return Decision("deny", "Sandbox execution is disabled")
        if not context.principal_id or not context.thread_id:
            return Decision("deny", "Trusted identity and thread are required")
        if context.profile not in {"read_only", "sandbox"}:
            return Decision("deny", "Unknown sandbox profile")
        if action == "sandbox.read":
            return Decision("allow")
        if context.profile == "sandbox":
            if action in {"sandbox.execute", "sandbox.write"}:
                return Decision("allow")
            if action == "workspace.apply":
                return Decision("ask")
        return Decision("deny", "Sandbox profile does not authorize this action")


def authorize(action: str, config: RunnableConfig, tool: str, args: dict) -> ExecutionContext:
    from common.security.content import contains_secret
    from common.security.store import SecurityStore

    ctx = current_context.get()
    thread = str((config or {}).get("configurable", {}).get("thread_id") or "")
    if not ctx or not ctx.principal or not thread or ctx.thread_id != thread:
        raise SecurityViolation("Sandbox requires a matching trusted principal and thread")
    if tool not in SANDBOX_TOOLS or SANDBOX_TOOLS[tool][1] != action:
        raise SecurityViolation("Unknown sandbox capability")
    if settings.security_enabled:
        if contains_secret(args) or ctx.risk or SecurityStore().has_risk(ctx.principal, thread):
            raise SecurityViolation("Sensitive or untrusted context cannot execute sandbox tools")
        permit = active_call.get()
        if not permit or not permit.consume(digest({"tool": tool, "args": args})):
            raise SecurityViolation("Sandbox tool requires a single-use execution permit")
    context = ExecutionContext(ctx.principal, thread, ctx.run_id, settings.sandbox_default_profile)
    decision = PolicyEngine().evaluate(action, context)
    if decision.effect != "allow":
        raise SecurityViolation(decision.reason)
    return context


def is_trusted_sandbox_tool(tool) -> bool:
    # Match callable identity, not only a model-visible name or claimed module.
    from tools.automation.bash_tool import safe_bash
    from tools.code.code_executor import execute_python_code
    from tools.sandbox.local_tools import sandbox_list_files, sandbox_read_file, sandbox_write_file

    known = {
        t.name: t
        for t in (
            safe_bash,
            execute_python_code,
            sandbox_list_files,
            sandbox_read_file,
            sandbox_write_file,
        )
    }
    from common.security.gateway import SecureTool
    from tools.core.wrappers import EventedTool

    while type(tool) in {SecureTool, EventedTool}:
        tool = tool.original
    return tool is known.get(tool.name)
