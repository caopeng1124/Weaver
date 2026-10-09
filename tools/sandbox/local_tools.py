"""Tools can operate only on the current sandbox, never choose host paths."""

import json

from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool

from tools.sandbox.local_service import get_local_service
from tools.sandbox.permissions import authorize
from tools.sandbox.workspace_files import validate_path


@tool
def sandbox_list_files(config: RunnableConfig) -> list[str]:
    """List exportable files in this session's isolated workspace."""
    context = authorize("sandbox.read", config, "sandbox_list_files", {})
    service = get_local_service()
    session = service.ensure(context)
    return list(service.files(session["id"], context.principal_id))


@tool
def sandbox_read_file(path: str, config: RunnableConfig) -> str:
    """Read a UTF-8 file using a relative path within the isolated workspace."""
    validate_path(path)
    context = authorize("sandbox.read", config, "sandbox_read_file", {"path": path})
    service = get_local_service()
    session = service.ensure(context)
    files = service.files(session["id"], context.principal_id)
    if path not in files:
        raise FileNotFoundError(path)
    return files[path].decode("utf-8")


@tool
def sandbox_write_file(path: str, content: str, config: RunnableConfig) -> dict:
    """Write a UTF-8 file inside the sandbox. Host files are never changed."""
    validate_path(path)
    context = authorize(
        "sandbox.write", config, "sandbox_write_file", {"path": path, "content": content}
    )
    from common.config import settings

    if len(content.encode()) > settings.sandbox_max_file_bytes:
        raise ValueError("File exceeds size limit")
    # Fixed trusted program; arguments arrive as JSON over stdin, not shell interpolation.
    script = "import json,sys,pathlib; p=json.load(sys.stdin); f=pathlib.Path(p['path']); f.parent.mkdir(parents=True,exist_ok=True); f.write_text(p['content'],encoding='utf-8')"
    return get_local_service().execute(
        context,
        ["python3", "-I", "-S", "-c", script],
        stdin=json.dumps({"path": path, "content": content}).encode(),
    )
