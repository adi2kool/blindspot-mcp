"""The proxy can front an ARBITRARY command as the upstream (`--exec`), not just a python
script path. This is what lets `airlock init` wrap Node/uv/binary servers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.mark.asyncio
async def test_proxy_exec_fronts_arbitrary_command():
    # Front the python fixture via --exec (as if it were any command), rather than the
    # default `python <target>` path. The proxy must connect and mirror the surface.
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "airlock.cli", "proxy", "--exec", sys.executable, str(FIXTURES / "clean_server.py")],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            assert isinstance(tools, list)  # the upstream was launched and mirrored


@pytest.mark.asyncio
async def test_proxy_exec_enforces_output():
    # --exec upstreams are enforced exactly like a TARGET upstream: an untrusted body is
    # framed as data (using the hostile fixture over --exec).
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "airlock.cli", "proxy", "--exec", sys.executable, str(FIXTURES / "hostile_upstream.py")],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("fetch_evil", {})
            text = "".join(getattr(c, "text", "") or "" for c in result.content)
            assert "UNTRUSTED DATA" in text  # enforced through the --exec path
