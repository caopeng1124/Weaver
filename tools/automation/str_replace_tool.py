from langchain.tools import tool

from common.security.content import contains_secret
from common.security.gateway import consume_execution_permit
from common.security.policy import open_workspace_file
from common.security.runtime import SecurityViolation


@tool
def str_replace(path: str, search: str, replace: str, encoding: str = "utf-8") -> str:
    """Replace all occurrences of `search` in an approved workspace file."""
    args = {"path": path, "search": search, "replace": replace, "encoding": encoding}
    permit = consume_execution_permit(str_replace, args)
    with open_workspace_file(path, encoding, permit.resource_version) as file:
        text = file.read()
        if contains_secret(text):
            raise SecurityViolation("Sensitive file content cannot be modified")
        file.seek(0)
        file.write(text.replace(search, replace))
        file.truncate()
    return f"Replaced occurrences in {path}"
