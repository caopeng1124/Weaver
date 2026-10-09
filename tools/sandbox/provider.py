"""Backend-independent execution contract; providers never fall back to host exec."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool = False

    def to_dict(self):
        return {
            "success": self.exit_code == 0,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "truncated": self.truncated,
        }


class SandboxProvider(Protocol):
    def diagnose(self) -> dict: ...
    def create(self, session_id: str) -> str: ...
    def execute(
        self, container: str, command: list[str], *, timeout: int, stdin: bytes = b""
    ) -> ExecutionResult: ...
    def import_files(self, container: str, files: dict[str, bytes]) -> None: ...
    def snapshot(self, container: str) -> dict[str, bytes]: ...
    def destroy(self, container: str) -> None: ...
    def recover(self) -> None: ...
