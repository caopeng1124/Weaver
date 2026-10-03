"""
Evented MCP multi-server client (SSE + stdio).

- Connect/disconnect multiple MCP servers
- List and register remote tools with server-prefixed names
- Emit start/result/error events for front-end visibility
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

from langchain.tools import BaseTool

from agent.core.events import ToolEventType, get_emitter_sync

logger = logging.getLogger(__name__)

try:  # Optional dependency
    from mcp import ClientSession, StdioServerParameters  # type: ignore
    from mcp.client.sse import sse_client  # type: ignore
    from mcp.client.stdio import stdio_client  # type: ignore
    from mcp.types import ListToolsResult  # type: ignore
except Exception:  # pragma: no cover
    ClientSession = None  # type: ignore
    StdioServerParameters = None  # type: ignore
    sse_client = None  # type: ignore
    stdio_client = None  # type: ignore
    ListToolsResult = None  # type: ignore


class MCPClientTool(BaseTool):
    """Proxy for a remote MCP tool; emits events on execution."""

    session: Any = None
    server_id: str = ""
    original_name: str = ""
    thread_id: str = "default"
    server_fingerprint: str = ""
    owner_loop: Any = None

    def _run(self, **kwargs):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            return "Error: use asynchronous MCP execution on the server event loop"
        if self.owner_loop and self.owner_loop.is_running():
            future = asyncio.run_coroutine_threadsafe(self._arun(**kwargs), self.owner_loop)
            try:
                return future.result(timeout=60)
            except TimeoutError:
                future.cancel()
                return "Error: MCP execution timed out"
        return asyncio.run(self._arun(**kwargs))

    async def _arun(self, **kwargs):
        from common.security.content import enabled
        from common.security.context import active_call, current_context
        from common.security.policy import digest
        from common.security.runtime import untrusted
        if not self.session:
            return f"Error: not connected to MCP server {self.server_id}"
        if self.owner_loop and asyncio.get_running_loop() is not self.owner_loop:
            future = asyncio.run_coroutine_threadsafe(self._arun(**kwargs), self.owner_loop)
            return await asyncio.wrap_future(future)
        permit = active_call.get()
        expected = digest({"tool": self.name, "args": kwargs})
        if enabled() and (permit is None or not permit.consume(expected)):
            return "[SECURITY_BLOCKED] MCP calls require permission for these exact arguments"
        context = current_context.get()
        emitter = get_emitter_sync(context.thread_id if context and context.thread_id else self.thread_id)
        await emitter.emit(ToolEventType.TOOL_START, {"tool": self.name, "args": kwargs, "server": self.server_id})
        result = await asyncio.wait_for(self.session.call_tool(self.original_name, kwargs), timeout=60)
        parts = [getattr(item, "text", "") for item in (getattr(result, "content", None) or [])]
        content = untrusted("\n".join(part for part in parts if isinstance(part, str)) or "No text output", source=f"mcp:{self.server_id}")
        await emitter.emit(ToolEventType.TOOL_RESULT, {"tool": self.name, "result": content,
                           "server": self.server_id, "success": not bool(getattr(result, "isError", False))})
        return content


class MCPClients:
    """Manage multiple MCP server connections and expose their tools."""

    def __init__(self, thread_id: str = "default"):
        self.sessions: Dict[str, Any] = {}
        self.exit_stacks: Dict[str, asyncio.AbstractEventLoop] = {}
        self.tools: List[BaseTool] = []
        self.thread_id = thread_id
        self.server_fingerprints: Dict[str, str] = {}

    async def connect_sse(self, server_url: str, server_id: str = "") -> None:
        if sse_client is None or ClientSession is None:
            raise RuntimeError("Missing dependency: mcp. Install with `pip install mcp`.")
        server_id = server_id or server_url
        from common.security.policy import digest
        self.server_fingerprints[server_id] = digest({"transport": "sse", "url": server_url})
        if server_id in self.sessions:
            await self.disconnect(server_id)

        streams_context = sse_client(url=server_url)
        streams = await streams_context.__aenter__()
        session = await ClientSession(*streams).__aenter__()
        self.sessions[server_id] = session
        self.exit_stacks[server_id] = streams_context

        await self._initialize(server_id)

    async def connect_stdio(self, command: str, args: List[str], server_id: str = "") -> None:
        if stdio_client is None or ClientSession is None or StdioServerParameters is None:
            raise RuntimeError("Missing dependency: mcp. Install with `pip install mcp`.")
        server_id = server_id or command
        from common.security.policy import digest
        self.server_fingerprints[server_id] = digest({"transport": "stdio", "command": command, "args": args})
        if server_id in self.sessions:
            await self.disconnect(server_id)

        server_params = StdioServerParameters(command=command, args=args)
        stdio_transport = await stdio_client(server_params).__aenter__()
        read, write = stdio_transport
        session = await ClientSession(read, write).__aenter__()
        self.sessions[server_id] = session
        self.exit_stacks[server_id] = stdio_transport

        await self._initialize(server_id)

    async def _initialize(self, server_id: str) -> None:
        session = self.sessions.get(server_id)
        if not session:
            return
        await session.initialize()
        response = await session.list_tools()
        self._register_tools(response, server_id)

    def _register_tools(self, tools_result: Any, server_id: str) -> None:
        for tool in tools_result.tools:
            original_name = tool.name
            tool_name = f"mcp_{server_id}_{original_name}".replace(" ", "_")
            proxy = MCPClientTool(
                name=tool_name,
                description=tool.description,
                args_schema=tool.inputSchema,
            )
            proxy.session = self.sessions.get(server_id)
            proxy.server_id = server_id
            proxy.original_name = original_name
            proxy.thread_id = self.thread_id
            proxy.server_fingerprint = self.server_fingerprints.get(server_id, "")
            proxy.owner_loop = asyncio.get_running_loop()
            self.tools.append(proxy)
        logger.info(f"[mcp] registered {len(tools_result.tools)} tools from {server_id}")

    async def disconnect(self, server_id: str = "") -> None:
        targets = [server_id] if server_id else list(self.sessions.keys())
        for sid in targets:
            session = self.sessions.pop(sid, None)
            if session:
                try:
                    await session.__aexit__(None, None, None)
                except Exception as e:
                    logger.warning(f"[mcp] closing session {sid} failed: {e}")
            ctx = self.exit_stacks.pop(sid, None)
            if ctx:
                try:
                    await ctx.__aexit__(None, None, None)
                except Exception:
                    pass
            # prune tools
            self.tools = [t for t in self.tools if getattr(t, "server_id", "") != sid]

    async def list_tools(self) -> ListToolsResult:
        tools_result = ListToolsResult(tools=[])
        for session in self.sessions.values():
            resp = await session.list_tools()
            tools_result.tools += resp.tools
        return tools_result
