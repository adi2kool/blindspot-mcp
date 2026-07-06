"""Composition fixture: a clean private-data server (one trifecta leg).

INERT TEST FIXTURE. Exposes read access to local files and an internal notes
resource. No injection payloads, no real I/O. Individually clean; it supplies only
the private-data leg. Its danger is emergent only when composed with an
untrusted-content source and an exfiltration path (see fixtures/compose_web_server.py
and fixtures/compose_mailer_server.py).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")


@mcp.resource("notes://internal")
def internal_notes() -> str:
    """Internal onboarding notes (fixture, benign)."""
    return "Internal note (fixture): staging credentials are in the team vault."


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the local filesystem and return its contents."""
    # INERT TEST FIXTURE - performs no filesystem I/O.
    return f"[fixture] would read the file at {path!r}"


@mcp.tool()
def list_files(directory: str) -> str:
    """List files in a local directory."""
    # INERT TEST FIXTURE - performs no filesystem I/O.
    return f"[fixture] would list files under {directory!r}"


if __name__ == "__main__":
    mcp.run()
