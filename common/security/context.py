"""Trusted request context; never deserialize permissions from model arguments."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock
from uuid import uuid4


@dataclass
class SecurityContext:
    principal: str
    run_id: str = field(default_factory=lambda: uuid4().hex)
    thread_id: str = ""
    risk: bool = False
    sources: dict = field(default_factory=dict)
    lock: Lock = field(default_factory=Lock, repr=False)


@dataclass
class ExecutionPermit:
    key: str
    resource_version: str = ""
    consumed: bool = False
    lock: Lock = field(default_factory=Lock, repr=False)

    def consume(self, key: str) -> bool:
        with self.lock:
            if self.key != key or self.consumed:
                return False
            self.consumed = True
            return True


current_context: ContextVar[SecurityContext | None] = ContextVar("security_context", default=None)
active_call: ContextVar[ExecutionPermit | None] = ContextVar("security_active_call", default=None)
call_id: ContextVar[str] = ContextVar("security_call_id", default="")


@contextmanager
def security_scope(principal: str, thread_id: str = ""):
    context = SecurityContext(principal=principal, thread_id=thread_id)
    token = current_context.set(context)
    try:
        yield context
    finally:
        current_context.reset(token)
