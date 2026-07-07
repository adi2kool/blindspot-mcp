"""Emit helpers: turn (body, origin) into MCP content objects that carry
provenance in `_meta`, per spec/convention.md section 5.

This is the author-facing library. A server author building a low-level MCP
`Server` returns these objects from their handlers, and the provenance metadata
rides to the wire in the reserved `_meta` field, where a provenance-aware client
enforcer reads it. Each helper sanitizes at emit and computes integrity via
`tagger.tag`, so a server cannot accidentally emit an invisible-unicode payload.

The `_meta` field is the natural home in current MCP: `TextResourceContents`,
`TextContent`, `CallToolResult`, and `GetPromptResult` all carry it (verified
against the installed SDK).
"""

from __future__ import annotations

from mcp import types
from mcp.server.lowlevel.helper_types import ReadResourceContents

from airlock.models import Origin, Trust
from airlock.provenance.tagger import tag_meta


def tagged_resource_contents(
    body: str,
    origin: Origin,
    *,
    mime_type: str = "text/plain",
    source: str | None = None,
    fence: bool = False,
    inputs: list[Trust] | None = None,
    sign_key: bytes | None = None,
    sig_alg: str = "hmac-sha256",
    keyid: str | None = None,
) -> ReadResourceContents:
    """A resource read result carrying provenance `_meta`.

    Return this (in a list) from a low-level `read_resource` handler.
    """
    emitted, meta = tag_meta(
        body, origin, source=source, fence=fence, inputs=inputs,
        sign_key=sign_key, sig_alg=sig_alg, keyid=keyid,
    )
    return ReadResourceContents(content=emitted, mime_type=mime_type, meta=meta)


def tagged_text_content(
    body: str,
    origin: Origin,
    *,
    source: str | None = None,
    fence: bool = False,
    inputs: list[Trust] | None = None,
    sign_key: bytes | None = None,
    sig_alg: str = "hmac-sha256",
    keyid: str | None = None,
) -> types.TextContent:
    """A tool-output text block carrying provenance `_meta`."""
    emitted, meta = tag_meta(
        body, origin, source=source, fence=fence, inputs=inputs,
        sign_key=sign_key, sig_alg=sig_alg, keyid=keyid,
    )
    return types.TextContent(type="text", text=emitted, _meta=meta)


def tagged_prompt_result(
    body: str,
    origin: Origin,
    *,
    role: str = "user",
    description: str | None = None,
    source: str | None = None,
    fence: bool = False,
    inputs: list[Trust] | None = None,
    sign_key: bytes | None = None,
    sig_alg: str = "hmac-sha256",
    keyid: str | None = None,
) -> types.GetPromptResult:
    """A prompt result whose message content carries provenance `_meta`.

    PromptMessage itself has no `_meta`, so provenance rides on the message's
    TextContent and is mirrored on the result for convenience.
    """
    emitted, meta = tag_meta(
        body, origin, source=source, fence=fence, inputs=inputs,
        sign_key=sign_key, sig_alg=sig_alg, keyid=keyid,
    )
    message = types.PromptMessage(
        role=role,
        content=types.TextContent(type="text", text=emitted, _meta=meta),
    )
    return types.GetPromptResult(description=description, messages=[message], _meta=meta)
