"""A common execution boundary for LangChain tools and agent middleware."""

from contextvars import Token
from typing import Any

from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool
from langgraph.types import interrupt

from common.config import settings
from common.security.content import redact_sensitive as redact
from common.security.context import (
    ExecutionPermit,
    SecurityContext,
    active_call,
    call_id,
    current_context,
)
from common.security.permissions import current_scope
from common.security.policy import NETWORK_TOOLS, digest, evaluate, resource_version
from common.security.runtime import (
    SecurityViolation,
    audit,
    private_data_present,
    risk_present,
    untrusted,
)
from common.security.store import ApprovalError, SecurityStore


def execution_context(config: RunnableConfig | None) -> SecurityContext:
    ctx = current_context.get()
    if ctx is None:
        if settings.internal_api_key or settings.app_env in {"prod", "production"}:
            raise SecurityViolation("Trusted execution identity is required")
        try:
            ctx = SecurityContext(principal="local")
        except (ValueError, TypeError) as error:
            raise SecurityViolation("Invalid execution policy") from error
        current_context.set(ctx)
    thread = str((config or {}).get("configurable", {}).get("thread_id") or ctx.thread_id)
    if ctx.thread_id and thread and ctx.thread_id != thread:
        raise SecurityViolation("Execution thread does not match its security context")
    if thread and not ctx.thread_id and ctx.private_data_seen:
        ctx.thread_id = thread
        audit("private_data_loaded", source="request_context")
    ctx.thread_id = thread
    return ctx


def _validated_args(tool: BaseTool, args: dict) -> dict:
    schema = tool.args_schema
    if schema and isinstance(schema, type) and hasattr(schema, "model_validate"):
        return schema.model_validate(args).model_dump()
    if isinstance(schema, dict):
        from jsonschema import ValidationError, validate

        try:
            validate(args, schema)
        except ValidationError as error:
            raise ValueError("Invalid tool arguments") from error
    return args


def tool_identity(tool: BaseTool) -> str:
    while isinstance(getattr(tool, "original", None), BaseTool):
        tool = tool.original
    schema = tool.args_schema
    if isinstance(schema, type) and hasattr(schema, "model_json_schema"):
        schema = schema.model_json_schema()
    return digest(
        {
            "name": tool.name,
            "description": tool.description,
            "schema": schema,
            "implementation": type(tool).__module__ + "." + type(tool).__qualname__,
            "server": getattr(tool, "server_fingerprint", ""),
            "remote_name": getattr(tool, "original_name", ""),
            "function": [
                (getattr(function, "__module__", ""), getattr(function, "__qualname__", ""))
                for function in (getattr(tool, "func", None), getattr(tool, "coroutine", None))
            ],
        }
    )


def policy_binding() -> dict:
    try:
        scope = current_scope().as_dict()
    except (ValueError, TypeError) as error:
        raise SecurityViolation("Invalid execution policy") from error
    return {
        "version": settings.security_policy_version,
        "scope": scope,
        "mcp_tools": settings.security_mcp_tools,
        "private_data": private_data_present(),
        "risk": risk_present(),
    }


def execution_key(tool, args, context=None):
    context = context or execution_context(None)
    return digest(
        {
            "principal": context.principal,
            "thread": context.thread_id,
            "run": context.run_id,
            "tool": tool_identity(tool),
            "args": args,
            "policy": policy_binding(),
        }
    )


def outbound_key(tool, args):
    context = execution_context(None)
    return digest(
        {
            "principal": context.principal,
            "thread": context.thread_id,
            "run": context.run_id,
            "tool": tool,
            "args": args,
            "policy": policy_binding(),
        }
    )


def consume_execution_permit(tool, args):
    context = execution_context(None)
    permit = active_call.get()
    decision = evaluate(tool.name, args, risk=risk_present(), private_data=private_data_present())
    if (
        decision.action == "deny"
        or permit is None
        or not permit.consume(execution_key(tool, args, context))
    ):
        raise SecurityViolation(
            "Execution requires permission for this identity, tool and exact arguments"
        )
    return permit


def _permit(tool, args, context, version=""):
    outbound = None
    if tool.name in NETWORK_TOOLS:
        values = {key: args[key] for key in ("query", "url", "urls") if key in args}
        operation = (
            "crawl_urls"
            if "urls" in values
            else "crawl_url"
            if "url" in values
            else "tavily_search"
        )
        outbound = {"tool": operation, "args": values}
    return ExecutionPermit(
        execution_key(tool, args, context),
        version,
        outbound=outbound,
        outbound_key=outbound_key(outbound["tool"], outbound["args"]) if outbound else "",
    )


def prepare(tool: BaseTool, args: dict, config: RunnableConfig | None) -> tuple[dict, Token | None]:
    try:
        args = _validated_args(tool, args)
    except ValueError as error:
        raise SecurityViolation("Tool arguments do not match the input schema") from error
    ctx = execution_context(config)
    original_key = execution_key(tool, args, ctx)
    permit = active_call.get()
    if permit and permit.key == original_key:
        if permit.consumed:
            raise SecurityViolation("Execution permission has already been consumed")
        return args, None
    store = SecurityStore()
    # A resumed request must not erase a previous source risk finding.
    for _ in range(4):
        risk = ctx.risk or store.has_risk(ctx.principal, ctx.thread_id)
        decision = evaluate(tool.name, args, risk=risk, private_data=private_data_present())
        audit(
            "policy_decision",
            tool=tool.name,
            action=decision.action,
            reason=decision.reason,
            resource=decision.resource,
            policy_version=settings.security_policy_version,
        )
        if decision.action == "deny":
            raise SecurityViolation(decision.reason)
        if decision.action == "allow":
            return args, active_call.set(_permit(tool, args, ctx))
        if not ctx.thread_id or not call_id.get():
            raise SecurityViolation("Approval requires a checkpointed tool call")
        version = resource_version(decision)
        approved_policy = policy_binding()
        binding = digest(
            {
                "principal": ctx.principal,
                "thread": ctx.thread_id,
                "call_id": call_id.get(),
                "tool": tool.name,
                "args": args,
                "resource_version": version,
                "tool_identity": tool_identity(tool),
                "policy": approved_policy,
            }
        )
        request = store.request(binding, ctx.principal, ctx.thread_id)
        response = interrupt(
            {
                "type": "security_approval",
                **request,
                "tool": tool.name,
                "args": redact(args),
                "resource": redact(decision.resource),
                "reason": decision.reason,
                "allowed_decisions": ["approve", "reject", "edit"],
            }
        )
        if not isinstance(response, dict) or response.get("approval_id") != request["approval_id"]:
            raise SecurityViolation("Approval response does not match the pending action")
        action = response.get("decision")
        if action not in {"approve", "reject", "edit"}:
            raise SecurityViolation("Invalid approval decision")
        store.consume(request["approval_id"], binding, ctx.principal, ctx.thread_id, action)
        audit(
            "approval_consumed", tool=tool.name, action=action, approval_id=request["approval_id"]
        )
        if action == "reject":
            raise SecurityViolation("User rejected the action")
        if action == "edit":
            if not isinstance(response.get("args"), dict):
                raise SecurityViolation("Edited arguments must be an object")
            args = _validated_args(tool, response["args"])
            # Editing never implicitly approves a different operation.
            continue
        # Resource/permission checks are repeated after resume, immediately before execution.
        fresh = evaluate(
            tool.name,
            args,
            risk=ctx.risk or store.has_risk(ctx.principal, ctx.thread_id),
            private_data=private_data_present(),
        )
        if (
            fresh.action == "deny"
            or resource_version(fresh) != version
            or policy_binding() != approved_policy
        ):
            raise SecurityViolation("Action or resource changed after approval")
        return args, active_call.set(_permit(tool, args, ctx, version))
    raise SecurityViolation("Too many approval edits; start a new action")


def denied(tool: str, error: Exception) -> str:
    audit("blocked", tool=tool, reason=str(error))
    return f"[SECURITY_BLOCKED] {redact(str(error))}"


class SecureTool(BaseTool):
    original: Any

    def __init__(self, original: BaseTool):
        super().__init__(
            name=original.name,
            description=original.description,
            args_schema=original.args_schema,
            original=original,
            return_direct=original.return_direct,
        )

    def invoke(self, input, config=None, **kwargs):
        token = call_id.set(str(input.get("id", "")) if isinstance(input, dict) else "")
        try:
            return super().invoke(input, config=config, **kwargs)
        finally:
            call_id.reset(token)

    async def ainvoke(self, input, config=None, **kwargs):
        token = call_id.set(str(input.get("id", "")) if isinstance(input, dict) else "")
        try:
            return await super().ainvoke(input, config=config, **kwargs)
        finally:
            call_id.reset(token)

    def _run(self, config: RunnableConfig, **kwargs):
        token = None
        try:
            args, token = prepare(self.original, kwargs, config)
            audit("execution_started", tool=self.name)
            result = self.original.invoke(args, config=config)
            result = untrusted(
                result,
                source=f"tool:{self.name}",
                private=self.name == "rag_search" or self.name.startswith("mcp_"),
            )
            audit("execution_completed", tool=self.name)
            return result
        except (SecurityViolation, ApprovalError) as error:
            return denied(self.name, error)
        finally:
            if token is not None:
                active_call.reset(token)

    async def _arun(self, config: RunnableConfig, **kwargs):
        token = None
        try:
            args, token = prepare(self.original, kwargs, config)
            audit("execution_started", tool=self.name)
            result = await self.original.ainvoke(args, config=config)
            result = untrusted(
                result,
                source=f"tool:{self.name}",
                private=self.name == "rag_search" or self.name.startswith("mcp_"),
            )
            audit("execution_completed", tool=self.name)
            return result
        except (SecurityViolation, ApprovalError) as error:
            return denied(self.name, error)
        finally:
            if token is not None:
                active_call.reset(token)


def secure_tools(tools):
    return [tool if isinstance(tool, SecureTool) else SecureTool(tool) for tool in tools]
