"""Shell execution is always confined to the selected sandbox backend."""

import shlex

from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool

from tools.sandbox.permissions import authorize
from tools.sandbox.workspace_files import validate_path

DEFAULT_TIMEOUT = 20


@tool
def safe_bash(
    cmd: str, config: RunnableConfig, cwd: str | None = None, timeout: int = DEFAULT_TIMEOUT
) -> str:
    """Run a shell command inside the current sandbox. cwd is relative to /workspace.

    Files persist for this session; networking and host paths are unavailable in Docker mode.
    """
    context = authorize(
        "sandbox.execute", config, "safe_bash", {"cmd": cmd, "cwd": cwd, "timeout": timeout}
    )
    if cwd and cwd != ".":
        validate_path(cwd)
        cmd = "cd -- " + shlex.quote(cwd) + " && {\n" + cmd + "\n}"
    from tools.sandbox.local_service import get_local_service

    result = get_local_service().execute(
        context, ["/bin/sh", "-s"], stdin=cmd.encode(), timeout=timeout
    )
    output = result["stdout"] + result["stderr"]
    if result["truncated"]:
        output += "\n[output truncated]"
    return (
        f"[exit {result['exit_code']}] {output}"
        if not result["success"]
        else output or "(no output)"
    )
