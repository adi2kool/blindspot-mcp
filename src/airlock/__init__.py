"""Airlock: an author-side trust-boundary layer for MCP.

The instruction and data boundary for MCP. Airlock tags the provenance of what
an MCP server emits, enforces that boundary on the consuming client (a reference
enforcer and a drop-in enforcing proxy), scans the neglected Prompt and Resource
surfaces as an on-ramp, and measures how well the boundary holds under adaptive
attack.
"""

__version__ = "0.2.1"
