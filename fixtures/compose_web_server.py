"""Composition fixture: a clean untrusted-content server (one trifecta leg).

INERT TEST FIXTURE. Exposes web search and page fetch. No injection payloads, no
real network I/O. Individually clean; it supplies only the untrusted-content leg (the
content it returns is attacker-influenceable). Dangerous only when composed with a
private-data source and an exfiltration path.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("web")


@mcp.tool()
def web_search(query: str) -> str:
    """Search the web and return result snippets."""
    # INERT TEST FIXTURE - performs no network I/O.
    return f"[fixture] would search the web for {query!r}"


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a web page and return its text."""
    # INERT TEST FIXTURE - performs no network I/O.
    return f"[fixture] would fetch {url!r}"


if __name__ == "__main__":
    mcp.run()
