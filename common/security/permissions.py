"""Immutable execution scopes loaded only from deployment configuration.

Neither model arguments, agent profiles nor checkpoint dictionaries can grant a
scope. Per-principal rules can only narrow deployment defaults. Live policy is
intersected with the request snapshot so revocations apply before execution.
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from common.config import settings


def _intersection(left, right):
    if left is None:
        return right
    if right is None:
        return left
    return tuple(sorted(set(left) & set(right)))


@dataclass(frozen=True)
class ExecutionScope:
    workspace: str
    tools: tuple[str, ...] | None = None
    domains: tuple[str, ...] | None = None
    network: bool = True

    def intersect(self, other):
        first, second = Path(self.workspace).resolve(), Path(other.workspace).resolve()
        if first.is_relative_to(second):
            workspace = first
        elif second.is_relative_to(first):
            workspace = second
        else:
            raise ValueError("Execution workspaces do not overlap")
        return ExecutionScope(
            str(workspace),
            _intersection(self.tools, other.tools),
            _intersection(self.domains, other.domains),
            self.network and other.network,
        )

    def as_dict(self):
        return asdict(self)


def _names(value, *, domains=False):
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError("Execution scope names must be a list of nonempty strings")
    names = tuple(
        sorted({item.strip().lower().rstrip(".") if domains else item.strip() for item in value})
    )
    if domains and any(any(char in name for char in "/:@* ") for name in names):
        raise ValueError("Allowed destinations must be exact host names")
    return names


def load_scope(principal):
    """Load server rules. An absent principal inherits the wildcard/default scope."""
    root = Path(settings.security_workspace).resolve()
    domains = [
        item.strip() for item in settings.security_allowed_domains.split(",") if item.strip()
    ]
    scope = ExecutionScope(str(root), domains=_names(domains, domains=True) if domains else None)
    rules = json.loads(settings.security_principal_policies)
    if not isinstance(rules, dict):
        raise ValueError("Principal policies must be a JSON object")
    for name in ("*", principal):
        rule = rules.get(name, {})
        if not isinstance(rule, dict) or set(rule) - {"tools", "workspace", "domains", "network"}:
            raise ValueError("Invalid principal execution policy")
        workspace = rule.get("workspace", str(root))
        if not isinstance(workspace, str) or not workspace:
            raise ValueError("Invalid workspace")
        workspace = Path(workspace)
        workspace = workspace if workspace.is_absolute() else root / workspace
        if not workspace.resolve().is_relative_to(root):
            raise ValueError("Principal workspace escapes deployment workspace")
        network = rule.get("network", True)
        if not isinstance(network, bool):
            raise ValueError("Network permission must be boolean")
        scope = scope.intersect(
            ExecutionScope(
                str(workspace.resolve()),
                _names(rule["tools"]) if "tools" in rule else None,
                _names(rule["domains"], domains=True) if "domains" in rule else None,
                network,
            )
        )
    return scope


def current_scope():
    from common.security.context import current_context

    context = current_context.get()
    live = load_scope(context.principal if context else "local")
    return context.scope.intersect(live) if context else live
