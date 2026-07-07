"""A2b tests: SEP-1913 trust-annotation alignment.

Airlock emits and reads the MCP SEP-1913 hint vocabulary (openWorldHint,
sensitiveHint, privateHint, attribution) alongside its own origin/trust, so a
standard-aware client can read our provenance. The hints are additive and do not
change the enforcement decision (which is driven by `trust`); they feed the action
gating in A3.
"""

from __future__ import annotations

from airlock.enforce.middleware import parse_provenance
from airlock.models import PROVENANCE_NAMESPACE as NS
from airlock.models import Origin
from airlock.provenance.tagger import tag_meta


def test_open_world_hint_derived_from_trust():
    _, author = tag_meta("operator policy", Origin.AUTHOR)
    _, external = tag_meta("web content", Origin.EXTERNAL)
    assert author[NS]["openWorldHint"] is False
    assert external[NS]["openWorldHint"] is True


def test_server_can_set_sensitivity_hints():
    _, meta = tag_meta("SSN 123", Origin.AUTHOR, sensitive_hint="high", private_hint=True)
    assert meta[NS]["sensitiveHint"] == "high"
    assert meta[NS]["privateHint"] is True


def test_source_becomes_attribution():
    _, meta = tag_meta("article", Origin.EXTERNAL, source="https://forum.example/42")
    assert meta[NS]["attribution"] == ["https://forum.example/42"]


def test_hints_round_trip_through_parse():
    _, meta = tag_meta("web", Origin.EXTERNAL, sensitive_hint="medium")
    prov = parse_provenance(meta)
    assert prov.open_world_hint is True
    assert prov.sensitive_hint == "medium"


def test_hints_are_additive_not_enforcement_changing():
    """A trusted item stays instruction-eligible; the hints do not alter the decision."""
    from airlock.enforce.middleware import enforce

    body, meta = tag_meta("operator policy", Origin.AUTHOR)
    e = enforce(body, meta)
    assert e.instruction_allowed is True  # openWorldHint False, no change


def test_malformed_hints_are_ignored():
    meta = {NS: {"origin": "external", "trust": "untrusted", "openWorldHint": "yes",
                 "sensitiveHint": 5, "privateHint": "x"}}
    prov = parse_provenance(meta)  # wrong types -> None, never raises
    assert prov.open_world_hint is None and prov.sensitive_hint is None and prov.private_hint is None
