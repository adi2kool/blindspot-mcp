"""Phase 3 tests: cross-server composition analysis (the lethal trifecta).

Unit tests are pure over synthetic surfaces. Integration tests connect to the clean
single-leg composition fixtures over stdio and prove the trifecta is enabled only by
the composition, not by any server alone. No network, no model.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from airlock.compose import (
    ResourceInfo,
    ServerSurface,
    ToolInfo,
    TrifectaLeg,
    analyze_composition,
    capture_surface,
    classify_server,
    render_human,
    render_json,
)
from airlock.models import Severity
from airlock.scan.client import connect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _legs(surface: ServerSurface) -> set[str]:
    return {sig.leg.value for sig in classify_server(surface)}


_FILES = ServerSurface(
    "files",
    tools=[ToolInfo("read_file", "Read a file from disk"), ToolInfo("list_files", "list a directory")],
    resources=[ResourceInfo("notes://internal", "internal", "internal onboarding notes")],
)
_WEB = ServerSurface(
    "web",
    tools=[ToolInfo("web_search", "Search the web"), ToolInfo("fetch_url", "Fetch a web page and return its text")],
)
_MAILER = ServerSurface(
    "mailer",
    tools=[ToolInfo("send_email", "Send an email"), ToolInfo("post_webhook", "HTTP POST to a webhook url")],
)


# --- classification ---

def test_each_server_supplies_its_own_leg():
    assert _legs(_FILES) == {"private_data"}
    assert TrifectaLeg.UNTRUSTED_CONTENT.value in _legs(_WEB)
    assert _legs(_MAILER) == {"exfil"}


def test_web_search_is_ingest_only_and_fetch_is_dual():
    web_signals = {(s.name, s.leg.value) for s in classify_server(_WEB)}
    assert ("web_search", "exfil") not in web_signals  # search is not an exfil channel
    assert ("fetch_url", "untrusted_content") in web_signals
    assert ("fetch_url", "exfil") in web_signals  # arbitrary-URL fetch is dual-use


def test_outbound_post_is_exfil_only_not_ingest():
    mailer_signals = {(s.name, s.leg.value) for s in classify_server(_MAILER)}
    assert ("post_webhook", "untrusted_content") not in mailer_signals
    assert ("post_webhook", "exfil") in mailer_signals


# --- composition logic ---

def test_no_single_server_enables_the_trifecta():
    for surface in (_FILES, _WEB, _MAILER):
        assert analyze_composition([surface]).trifecta_enabled is False


def test_composition_jointly_enables_the_trifecta():
    report = analyze_composition([_FILES, _WEB, _MAILER])
    assert report.trifecta_enabled is True
    assert report.jointly_enabled is True
    assert report.single_server_culprits == []
    assert report.severity is Severity.ERROR
    for leg in TrifectaLeg:
        assert report.legs_present[leg], f"missing leg {leg}"


def test_single_server_culprit_is_flagged_not_jointly():
    kitchen_sink = ServerSurface(
        "everything",
        tools=[
            ToolInfo("read_file", "read a file"),
            ToolInfo("fetch_url", "fetch a web page"),
            ToolInfo("send_email", "send an email"),
        ],
    )
    report = analyze_composition([kitchen_sink])
    assert report.trifecta_enabled is True
    assert report.jointly_enabled is False
    assert "everything" in report.single_server_culprits


def test_two_leg_composition_is_a_warning_not_enabled():
    report = analyze_composition([_FILES, _MAILER])  # private + exfil, no untrusted
    assert report.trifecta_enabled is False
    assert report.severity is Severity.WARNING


def test_harmless_servers_do_not_enable_the_trifecta():
    calc = ServerSurface("calc", tools=[ToolInfo("add", "add two numbers"), ToolInfo("multiply", "multiply")])
    clock = ServerSurface("clock", tools=[ToolInfo("now", "current time")])
    report = analyze_composition([calc, clock])
    assert report.trifecta_enabled is False
    assert report.severity in (Severity.NONE, Severity.NOTE)


def test_provenance_emitter_supplies_untrusted_leg_and_is_noted():
    tagged = ServerSurface("tagged", tools=[], resources=[], untrusted_emitter=True)
    report = analyze_composition([_FILES, tagged, _MAILER])
    assert TrifectaLeg.UNTRUSTED_CONTENT in report.server_legs["tagged"]
    assert "tagged" in report.provenance_aware_sources
    assert report.trifecta_enabled is True
    assert any("already tag provenance" in m for m in report.mitigations)


def test_renderers_do_not_crash():
    report = analyze_composition([_FILES, _WEB, _MAILER])
    human = render_human(report)
    assert "lethal trifecta: ENABLED" in human
    assert "\"trifecta_enabled\": true" in render_json(report)


# --- integration: the clean single-leg fixtures over stdio ---

@pytest.mark.asyncio
async def test_live_fixtures_jointly_enable_trifecta():
    surfaces = []
    for script, name in (
        ("compose_files_server.py", "files"),
        ("compose_web_server.py", "web"),
        ("compose_mailer_server.py", "mailer"),
    ):
        async with connect(str(FIXTURES / script), is_http=False) as (session, _init):
            surfaces.append(await capture_surface(session, name))
    # Each fixture alone is clean.
    for surface in surfaces:
        assert analyze_composition([surface]).trifecta_enabled is False
    # Together they enable the trifecta, and no single one is the culprit.
    report = analyze_composition(surfaces)
    assert report.trifecta_enabled is True
    assert report.jointly_enabled is True


@pytest.mark.asyncio
async def test_tagged_server_detected_as_untrusted_emitter():
    async with connect(str(FIXTURES / "tagged_server.py"), is_http=False) as (session, _init):
        surface = await capture_surface(session, "tagged")
    assert surface.untrusted_emitter is True
    assert TrifectaLeg.UNTRUSTED_CONTENT in {s.leg for s in classify_server(surface)}
