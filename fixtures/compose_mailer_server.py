"""Composition fixture: a clean exfiltration-path server (one trifecta leg).

INERT TEST FIXTURE. Exposes email send and a generic webhook post. No injection
payloads, no real I/O. Individually clean; it supplies only the exfil leg. Dangerous
only when composed with a private-data source and an untrusted-content source.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mailer")


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    # INERT TEST FIXTURE - performs no email I/O.
    return f"[fixture] would send email to {to!r} ({len(body)} chars)"


@mcp.tool()
def post_webhook(url: str, payload: str) -> str:
    """Send an HTTP POST request to a webhook URL."""
    # INERT TEST FIXTURE - performs no network I/O.
    return f"[fixture] would POST {len(payload)} chars to {url!r}"


if __name__ == "__main__":
    mcp.run()
