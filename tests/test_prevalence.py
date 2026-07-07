"""Phase C prevalence harness: safety gates, aggregation, and end-to-end over fixtures.

The integration tests spawn the repo's own inert fixture servers over stdio (like
test_proxy). No network, no third-party downloads, no tool calls.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp import ClientSession

from airlock.prevalence.harness import (
    FAILED,
    MANIFEST_VERSION,
    REFUSED_REMOTE,
    SCANNED,
    SKIPPED_LICENSE,
    ServerResult,
    ServerSpec,
    _is_loopback,
    _study_http_client_factory,
    aggregate,
    license_permits_analysis,
    load_manifest,
    render_study,
    render_study_json,
    run_study,
    scan_one,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def _spec(name: str, fname: str, **kw) -> ServerSpec:
    kw.setdefault("license", "Apache-2.0")
    return ServerSpec(name=name, target=str(FIXTURES / fname), **kw)


def _manifest(tmp_path: Path, servers: list[dict]) -> str:
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"version": MANIFEST_VERSION, "servers": servers}))
    return str(p)


# --- pure safety gates -------------------------------------------------------

def test_license_gate_allowlist_and_override():
    assert license_permits_analysis(ServerSpec("a", "x.py", license="MIT"))
    assert license_permits_analysis(ServerSpec("a", "x.py", license="apache-2.0"))  # case-insensitive
    assert license_permits_analysis(ServerSpec("a", "x.py", license="GPL-3.0"))  # copyleft: analysis ok
    assert not license_permits_analysis(ServerSpec("a", "x.py", license=""))  # missing -> skip
    assert not license_permits_analysis(ServerSpec("a", "x.py", license="Proprietary"))
    assert license_permits_analysis(ServerSpec("a", "x.py", license="Weird-1.0", analysis_ok=True))


def test_loopback_detection_covers_block_and_mapped_forms():
    assert _is_loopback("http://127.0.0.1:3001/mcp")
    assert _is_loopback("http://127.0.0.2:8000/")  # 127.0.0.0/8, not just .1
    assert _is_loopback("http://localhost:8000/")
    assert _is_loopback("http://[::1]:9000/mcp")
    assert _is_loopback("http://[::ffff:127.0.0.1]:9000/mcp")  # IPv4-mapped IPv6
    # refused:
    assert not _is_loopback("http://0.0.0.0:8000/")  # wildcard, not loopback
    assert not _is_loopback("http://example.com/mcp")
    assert not _is_loopback("http://127.0.0.1.evil.com/mcp")  # subdomain trick
    assert not _is_loopback("https://api.someserver.io/mcp")
    assert not _is_loopback("http://localhost.evil.com/")


def test_study_http_client_disables_redirects():
    # The fix for the loopback->remote redirect bypass: the study client must not follow
    # redirects, so a loopback server cannot 3xx-bounce us to a remote host.
    client = _study_http_client_factory()
    assert client.follow_redirects is False


@pytest.mark.asyncio
async def test_scan_one_skips_unlicensed_without_connecting():
    r = await scan_one(ServerSpec("u", str(FIXTURES / "clean_server.py"), license=""))
    assert r.status == SKIPPED_LICENSE
    assert r.items_scanned == 0


@pytest.mark.asyncio
async def test_scan_one_refuses_remote_by_default():
    r = await scan_one(ServerSpec("r", "http://example.com/mcp", transport="http", license="MIT"))
    assert r.status == REFUSED_REMOTE


@pytest.mark.asyncio
async def test_scan_one_refuses_wildcard_address():
    r = await scan_one(ServerSpec("w", "http://0.0.0.0:8000/mcp", transport="http", license="MIT"))
    assert r.status == REFUSED_REMOTE


@pytest.mark.asyncio
async def test_scan_one_issues_no_tool_call(monkeypatch):
    """The core safety invariant: the study path never calls a tool. Spy on call_tool and
    assert it is untouched (and the scan still completes)."""
    calls: list = []

    async def spy_call_tool(self, *a, **k):  # pragma: no cover - must not run
        calls.append((a, k))
        raise AssertionError("prevalence study must never call a tool")

    monkeypatch.setattr(ClientSession, "call_tool", spy_call_tool, raising=True)
    r = await scan_one(_spec("c", "clean_server.py"))
    assert r.status == SCANNED
    assert calls == []


# --- end to end over fixtures ------------------------------------------------

@pytest.mark.asyncio
async def test_scan_one_flags_poisoned_fixture():
    r = await scan_one(_spec("v", "vulnerable_server.py"))
    assert r.status == SCANNED
    assert r.items_scanned > 0
    assert r.has_error_finding
    assert "data_exfiltration" in r.classes


@pytest.mark.asyncio
async def test_scan_one_clean_fixture_is_clean():
    r = await scan_one(_spec("c", "clean_server.py"))
    assert r.status == SCANNED
    assert not r.has_error_finding


@pytest.mark.asyncio
async def test_run_study_prevalence_and_denominator():
    specs = [_spec("v", "vulnerable_server.py"), _spec("c", "clean_server.py")]
    study = await run_study(specs)
    assert study.servers_scanned == 2
    assert study.servers_with_error_findings == 1
    assert study.prevalence == pytest.approx(0.5)
    assert study.by_class.get("data_exfiltration") == 1  # one server exhibits it


# --- aggregation math + anonymization ----------------------------------------

def test_aggregate_excludes_skipped_and_failed_from_denominator():
    results = [
        ServerResult("a", "MIT", SCANNED, items_scanned=3, n_findings=2,
                     classes=["data_exfiltration"], severities=["error"]),
        ServerResult("b", "MIT", SCANNED, items_scanned=4, n_findings=1,
                     classes=["homoglyph"], severities=["warning"]),
        ServerResult("c", "", SKIPPED_LICENSE),
        ServerResult("d", "MIT", FAILED, detail="boom"),
    ]
    study = aggregate([ServerSpec(r.name, "x.py") for r in results], results)
    assert study.servers_total == 4
    assert study.servers_scanned == 2  # skipped + failed excluded
    assert study.servers_skipped == 1
    assert study.servers_failed == 1
    assert study.servers_with_error_findings == 1  # only 'a'
    assert study.prevalence == pytest.approx(0.5)
    assert study.by_class == {"data_exfiltration": 1, "homoglyph": 1}
    assert study.by_severity == {"error": 1, "warning": 1}


def test_by_class_counts_servers_not_detections():
    # A server the scanner flagged nine times for one class contributes 1, not 9, so the
    # published aggregate is not inflated by detector multiplicity.
    r = ServerResult("a", "MIT", SCANNED, items_scanned=1, n_findings=9,
                     classes=["data_exfiltration"], severities=["error"])
    study = aggregate([ServerSpec("a", "x.py")], [r])
    assert study.by_class == {"data_exfiltration": 1}


def test_anonymize_hides_identity():
    results = [ServerResult("secret-internal-server", "MIT", SCANNED, items_scanned=1,
                            n_findings=1, classes=["data_exfiltration"], severities=["error"])]
    study = aggregate([ServerSpec("secret-internal-server", "x.py")], results)
    human = render_study(study, anonymize=True)
    assert "secret-internal-server" not in human
    assert "server-000" in human
    doc = json.loads(render_study_json(study, anonymize=True))
    assert doc["servers"][0]["name"] == "server-000"
    assert "license" not in doc["servers"][0]
    assert "detail" not in doc["servers"][0]


# --- manifest loading + validation -------------------------------------------

def test_load_example_manifest():
    specs = load_manifest(str(ROOT / "study" / "example_manifest.json"))
    assert len(specs) == 7
    assert specs[0].name == "vulnerable_server"
    assert any(s.license == "" for s in specs)  # the license-gate demo entry


def test_load_manifest_normalizes_transport(tmp_path):
    m = _manifest(tmp_path, [{"name": "a", "target": "http://127.0.0.1:1/mcp",
                              "transport": "HTTP", "license": "MIT"}])
    assert load_manifest(m)[0].transport == "http"


def test_load_manifest_rejects_bad_version(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"version": "nope", "servers": []}))
    with pytest.raises(ValueError, match="unsupported manifest version"):
        load_manifest(str(p))


def test_load_manifest_requires_name_and_target(tmp_path):
    with pytest.raises(ValueError, match="string 'name' and 'target'"):
        load_manifest(_manifest(tmp_path, [{"name": "x"}]))


def test_load_manifest_rejects_non_string_license(tmp_path):
    with pytest.raises(ValueError, match="license"):
        load_manifest(_manifest(tmp_path, [{"name": "a", "target": "x.py", "license": 123}]))


def test_load_manifest_rejects_non_bool_analysis_ok(tmp_path):
    with pytest.raises(ValueError, match="analysis_ok"):
        load_manifest(_manifest(tmp_path, [
            {"name": "a", "target": "x.py", "license": "Proprietary", "analysis_ok": "yes"}]))


def test_load_manifest_rejects_bad_transport(tmp_path):
    with pytest.raises(ValueError, match="transport"):
        load_manifest(_manifest(tmp_path, [
            {"name": "a", "target": "x.py", "license": "MIT", "transport": "ftp"}]))


@pytest.mark.asyncio
async def test_scan_one_times_out_on_hanging_server():
    # A command that never speaks MCP would hang initialize forever; the per-server timeout
    # records it FAILED instead of stalling the whole study.
    r = await scan_one(
        ServerSpec("hang", "sleep", command="sleep", args=["30"], license="MIT"), timeout=0.5
    )
    assert r.status == FAILED


@pytest.mark.asyncio
async def test_scan_one_supports_launch_command():
    # The launch-command form (used for npx/uvx servers): here we spawn the clean fixture
    # via an explicit command instead of the default `python <path>`.
    import sys

    r = await scan_one(ServerSpec("c", "label", command=sys.executable,
                                  args=[str(FIXTURES / "clean_server.py")], license="MIT"))
    assert r.status == SCANNED


def test_load_manifest_parses_command_and_args(tmp_path):
    m = _manifest(tmp_path, [{"name": "e", "target": "npm:x", "command": "npx",
                              "args": ["-y", "@scope/x"], "license": "MIT"}])
    spec = load_manifest(m)[0]
    assert spec.command == "npx" and spec.args == ("-y", "@scope/x")


def test_load_manifest_rejects_non_string_args(tmp_path):
    with pytest.raises(ValueError, match="args"):
        load_manifest(_manifest(tmp_path, [{"name": "e", "target": "x", "license": "MIT",
                                            "command": "npx", "args": [1, 2]}]))


def test_load_manifest_rejects_malformed_shapes(tmp_path):
    with pytest.raises(ValueError, match="must be an object"):
        load_manifest(_manifest(tmp_path, ["oops"]))
    p = tmp_path / "n.json"
    p.write_text(json.dumps({"version": MANIFEST_VERSION, "servers": 5}))
    with pytest.raises(ValueError, match="'servers' must be a list"):
        load_manifest(str(p))
    p.write_text(json.dumps(["not", "an", "object"]))
    with pytest.raises(ValueError, match="must be a JSON object"):
        load_manifest(str(p))
