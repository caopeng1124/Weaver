from typing import Optional

from langchain.tools import tool


@tool
def safe_bash(cmd: str, cwd: Optional[str] = None, timeout: int = 20) -> str:
    """Host shell execution is unavailable under the tool execution policy."""
    return "[SECURITY_BLOCKED] Host shell execution is disabled by the security policy"
