from pathlib import Path

from langchain.tools import tool

from common.security.content import contains_secret, enabled
from common.security.context import active_call
from common.security.policy import digest, open_workspace_file
from common.security.runtime import SecurityViolation


@tool
def str_replace(path: str, search: str, replace: str, encoding: str = "utf-8") -> str:
    """
    Replace all occurrences of `search` with `replace` in a text file.
    """
    if enabled():
        expected = digest({"tool": "str_replace", "args": {
            "path": path, "search": search, "replace": replace, "encoding": encoding}})
        permit = active_call.get()
        if permit is None or not permit.consume(expected):
            raise SecurityViolation("File editing requires approval for these exact arguments")
        with open_workspace_file(path, encoding, permit.resource_version) as file:
            text = file.read()
            if contains_secret(text):
                raise SecurityViolation("Sensitive file content cannot be modified")
            file.seek(0)
            file.write(text.replace(search, replace))
            file.truncate()
        return f"Replaced occurrences in {path}"
    p = Path(path)
    if not p.exists():
        return f"File not found: {path}"
    text = p.read_text(encoding=encoding)
    new_text = text.replace(search, replace)
    p.write_text(new_text, encoding=encoding)
    return f"Replaced occurrences in {path}"
