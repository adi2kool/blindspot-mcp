"""Egress-DLP fixture: an exfil-capable sink that echoes its payload, plus a local read.

INERT TEST FIXTURE. `send_email` is classified as exfil (send message) and echoes the
body back so a test can observe exactly what would have left the boundary (the raw secret,
a [REDACTED:...] placeholder, or nothing when the call is blocked). `read_note` is a pure
local read (never exfil), used to prove the egress scan's precision gate leaves
non-outbound calls untouched. No real I/O.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("egress-fixture")


@mcp.tool()
def send_email(to: str, body: str) -> str:
    """Send an email message to a recipient."""
    # INERT: no real send. Echoes the body so a test sees what would have left.
    return f"[fixture] email sent to {to}: {body}"


@mcp.tool()
def read_note(note_id: str) -> str:
    """Read a note from the local store."""
    # INERT local read; classified as private-data, never exfil. Echoes its argument so a
    # test can confirm a secret passed to a NON-exfil tool is NOT scanned or redacted.
    return f"[fixture] note {note_id}"


if __name__ == "__main__":
    mcp.run()
