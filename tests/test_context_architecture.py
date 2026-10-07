"""Architectural gate: application nodes cannot manufacture privileged messages."""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Provider adapters own fixed transport safety instructions, not task context.
PRIVILEGED_OWNERS = {
    "agent/core/context_builder.py",
    "common/security/models.py",
    "common/security/anthropic.py",
}
CONSTRUCTORS = {
    "SystemMessage",
    "SystemMessageChunk",
    "SystemMessagePromptTemplate",
    "DeveloperMessage",
}
ROLES = {"system", "developer"}


def privileged_constructions(source):
    tree = ast.parse(source)
    aliases = {
        alias.asname or alias.name: alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = node.func
            # Include constructors accessed via an imported module or alias.
            while isinstance(target, ast.Attribute) and target.attr in {
                "from_template",
                "from_messages",
                "model_validate",
            }:
                target = target.value
            name = (
                target.id
                if isinstance(target, ast.Name)
                else target.attr
                if isinstance(target, ast.Attribute)
                else ""
            )
            if aliases.get(name, name) in CONSTRUCTORS:
                findings.append(node.lineno)
            for keyword in node.keywords:
                if (
                    keyword.arg == "role"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value in ROLES
                ):
                    findings.append(node.lineno)
        elif isinstance(node, (ast.Tuple, ast.List)) and len(node.elts) == 2:
            if isinstance(node.elts[0], ast.Constant) and node.elts[0].value in ROLES:
                findings.append(node.lineno)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "role"
                    and isinstance(value, ast.Constant)
                    and value.value in ROLES
                ):
                    findings.append(node.lineno)
    return findings


@pytest.mark.parametrize(
    "source",
    [
        "SystemMessage(content=user_input)",
        "from langchain_core.messages import SystemMessage as SM; SM(content=x)",
        "messages.SystemMessage(content=x)",
        "SystemMessagePromptTemplate.from_template(x)",
        'ChatPromptTemplate.from_messages([("system", x)])',
        'ChatPromptTemplate.from_messages([["developer", x]])',
        '{"role": "developer", "content": x}',
        'ChatMessage(role="system", content=x)',
    ],
)
def test_gate_detects_privileged_construction_forms(source):
    assert privileged_constructions(source)


def test_privileged_messages_are_only_constructed_at_context_boundary():
    paths = [ROOT / "main.py", ROOT / "support_agent.py"]
    for folder in ("agent", "common", "tools", "prompts", "triggers"):
        paths.extend((ROOT / folder).rglob("*.py"))
    findings = []
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        if relative in PRIVILEGED_OWNERS:
            continue
        findings.extend(f"{relative}:{line}" for line in privileged_constructions(path.read_text()))
    assert not findings, (
        "Use build_context(policy, ...) instead of constructing privileged messages: "
        + ", ".join(findings)
    )
