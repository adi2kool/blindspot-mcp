"""Tests for the flight-recorder report renderer (`airlock report`)."""

from __future__ import annotations

import json

from airlock import cli
from airlock.ledger import (
    EV_DRIFT,
    EV_ENFORCE,
    EV_SAMPLING,
    Ledger,
)
from airlock.ledger_report import build_report, render_html, render_human, render_json


def _make_ledger(path):
    """A mixed, valid, hash-chained ledger covering every summarized event type."""
    led = Ledger(path)
    led.append(EV_ENFORCE, surface="resource", ident="notes://policy", disposition="trusted")
    led.append(EV_ENFORCE, surface="tool", ident="fetch_evil", disposition="untrusted")
    led.append(EV_ENFORCE, surface="prompt", ident="evil", disposition="quarantined")
    led.record_action("send_email", "block", gated=True, side_effecting=True)
    led.record_egress("send_email", "block", ["aws_access_key"], 1, blocked=True, tainted=True)
    led.append(EV_DRIFT, surface="server", ident="srv", detail={"mode": "block", "category": "tools"})
    led.append(EV_SAMPLING, surface="sampling", ident="message[0]",
               disposition="untrusted", detail={"mode": "frame"})
    return led


def test_summary_counts(tmp_path):
    path = tmp_path / "audit.jsonl"
    _make_ledger(path)
    rep = build_report(path)
    s = rep.summary
    assert rep.chain.ok and rep.chain.entries == 7
    assert s.trusted == 1
    assert s.demoted == 2  # untrusted + quarantined
    assert s.quarantined == 1
    assert s.actions_seen == 1 and s.actions_gated == 1
    assert s.egress_events == 1 and s.egress_blocked == 1
    assert s.egress_detectors == {"aws_access_key": 1}
    assert s.drift_events == 1
    assert s.sampling == 1


def test_render_human_reads_cleanly(tmp_path):
    path = tmp_path / "audit.jsonl"
    _make_ledger(path)
    text = render_human(build_report(path))
    assert "INTACT" in text
    assert "demoted to data" in text
    assert "BLOCKED egress: aws_access_key" in text
    assert "gated (block)" in text


def test_render_json_is_valid_and_complete(tmp_path):
    path = tmp_path / "audit.jsonl"
    _make_ledger(path)
    doc = json.loads(render_json(build_report(path)))
    assert doc["chain"]["ok"] is True
    assert doc["summary"]["enforced"]["demoted"] == 2
    assert doc["summary"]["egress"]["blocked"] == 1
    assert doc["summary"]["egress"]["detectors"] == {"aws_access_key": 1}


def test_render_html_is_self_contained_and_escapes(tmp_path):
    path = tmp_path / "audit.jsonl"
    led = _make_ledger(path)
    # An entry whose ident carries HTML metacharacters, to prove escaping.
    led.append(EV_ENFORCE, surface="tool", ident="<img src=x onerror=alert(1)>", disposition="untrusted")
    html_out = render_html(build_report(path))
    assert html_out.lstrip().startswith("<!doctype")
    assert "chain intact" in html_out
    assert "Airlock flight recorder" in html_out
    # Self-contained: no external resource references.
    assert "http://" not in html_out and "https://" not in html_out
    assert "<script" not in html_out.lower().replace("&lt;script", "")  # only escaped forms
    # The hostile ident is escaped, never live markup.
    assert "<img src=x" not in html_out
    assert "&lt;img src=x" in html_out


def test_broken_chain_is_reflected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _make_ledger(path)
    lines = path.read_text().splitlines()
    obj = json.loads(lines[1])
    obj["disposition"] = "trusted"  # tamper without recomputing the hash
    lines[1] = json.dumps(obj)
    path.write_text("\n".join(lines) + "\n")
    rep = build_report(path)
    assert rep.chain.ok is False
    assert "BROKEN" in render_human(rep)
    assert "chain BROKEN" in render_html(rep)


def test_missing_ledger_does_not_crash(tmp_path):
    rep = build_report(tmp_path / "does-not-exist.jsonl")
    assert rep.chain.ok is False
    assert rep.summary.entries == 0
    # Renderers must tolerate an empty/unreadable ledger.
    assert "BROKEN" in render_human(rep)
    assert render_html(rep).lstrip().startswith("<!doctype")


def test_cli_report_json_and_html(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    _make_ledger(path)
    rc = cli.main(["report", str(path), "--format", "json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["egress"]["blocked"] == 1

    html_path = tmp_path / "report.html"
    rc = cli.main(["report", str(path), "--format", "html", "--out", str(html_path)])
    assert rc == 0
    assert html_path.read_text().lstrip().startswith("<!doctype")


def test_cli_report_broken_chain_exits_nonzero(tmp_path):
    path = tmp_path / "audit.jsonl"
    _make_ledger(path)
    lines = path.read_text().splitlines()
    del lines[2]  # drop an entry -> chain break
    path.write_text("\n".join(lines) + "\n")
    assert cli.main(["report", str(path), "--format", "json"]) == 1
