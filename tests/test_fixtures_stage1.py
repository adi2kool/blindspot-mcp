"""Stage 1 integration tests.

Each test spins up a real fixture server as a stdio subprocess through an MCP
client, which proves the server starts over stdio and that the client can
enumerate and fetch its prompts and resources. This is the Stage 1 Definition of
Done. No detector or enforcer logic is asserted here.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULNERABLE = FIXTURES / "vulnerable_server.py"
CLEAN = FIXTURES / "clean_server.py"

# The tag-character block used by the invisible-unicode payload: U+E0000..U+E007F.
TAG_RANGE = range(0xE0000, 0xE0080)
ZERO_WIDTH = {"​", "‌", "‍", "﻿"}


@asynccontextmanager
async def connect(server_script: Path):
    params = StdioServerParameters(command=sys.executable, args=[str(server_script)])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def _has_zero_width(text: str) -> bool:
    return any(ch in ZERO_WIDTH for ch in text)


def _has_tag_char(text: str) -> bool:
    return any(ord(ch) in TAG_RANGE for ch in text)


async def _read_resource_text(session: ClientSession, uri) -> str:
    result = await session.read_resource(uri)
    return "".join(getattr(c, "text", "") for c in result.contents)


@pytest.mark.parametrize("server", [VULNERABLE, CLEAN], ids=["vulnerable", "clean"])
async def test_server_starts_and_exposes_surface(server: Path):
    async with connect(server) as session:
        tools = {t.name for t in (await session.list_tools()).tools}
        prompts = {p.name for p in (await session.list_prompts()).prompts}
        resources = {str(r.uri) for r in (await session.list_resources()).resources}

    assert tools == {"send_email", "create_ticket"}
    assert "summarize_ticket" in prompts
    assert any(uri.startswith("notes://internal") for uri in resources)


async def test_vulnerable_resource_carries_hidden_payload():
    async with connect(VULNERABLE) as session:
        resource = (await session.list_resources()).resources[0]
        text = await _read_resource_text(session, resource.uri)

    assert _has_zero_width(text), "expected a zero-width code point in the poisoned resource"
    assert _has_tag_char(text), "expected a unicode tag character in the poisoned resource"


async def test_clean_resource_has_no_invisible_chars():
    async with connect(CLEAN) as session:
        resource = (await session.list_resources()).resources[0]
        text = await _read_resource_text(session, resource.uri)

    assert not _has_zero_width(text)
    assert not _has_tag_char(text)
    assert text.isascii(), "the clean control must be plain ASCII"


@pytest.mark.parametrize("server", [VULNERABLE, CLEAN], ids=["vulnerable", "clean"])
async def test_get_prompt_returns_full_text(server: Path):
    async with connect(server) as session:
        result = await session.get_prompt("summarize_ticket", arguments={"ticket_id": "TCK-1"})
        texts = [getattr(m.content, "text", "") for m in result.messages]

    assert any("Summarize ticket TCK-1" in t for t in texts)
