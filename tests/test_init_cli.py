"""End-to-end tests for `airlock init` (config rewrite, backup, idempotency, dry-run).

Discovery is monkeypatched to a temp config so the test never touches a real client config.
"""

from __future__ import annotations

import json

import pytest

from airlock import cli, onboard

CONFIG = {
    "mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"], "env": {"X": "1"}},
        "remote": {"url": "https://example.invalid/mcp", "type": "http"},
        "weird": {"note": "neither command nor url"},
    },
    "globalShortcut": "preserved",
}


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    path = tmp_path / "claude_desktop_config.json"
    path.write_text(json.dumps(CONFIG, indent=2), encoding="utf-8")
    monkeypatch.setattr(onboard, "discover", lambda *a, **k: [("claude-desktop", path)])
    return path


def test_init_dry_run_changes_nothing(cfg, capsys):
    before = cfg.read_text()
    rc = cli.main(["init", "--dry-run", "--no-lock", "--no-audit"])
    assert rc == 0
    assert cfg.read_text() == before  # untouched
    assert "dry run" in capsys.readouterr().out


def test_init_wraps_and_backs_up(cfg, capsys):
    rc = cli.main(["init", "--no-lock", "--no-audit"])
    assert rc == 0
    doc = json.loads(cfg.read_text())
    servers = doc["mcpServers"]
    # stdio server routed through the proxy via --exec, preserving the original command + env.
    files = servers["files"]
    assert files["command"] == "airlock"
    assert files["args"] == ["proxy", "--exec", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    assert files["env"] == {"X": "1"}
    # remote server routed via --http.
    assert servers["remote"]["args"] == ["proxy", "--http", "https://example.invalid/mcp"]
    # unwrappable entry left alone; unrelated top-level keys preserved.
    assert servers["weird"] == {"note": "neither command nor url"}
    assert doc["globalShortcut"] == "preserved"
    # A backup of the original was written.
    backup = cfg.with_name(cfg.name + ".airlock.bak")
    assert backup.exists()
    assert json.loads(backup.read_text())["mcpServers"]["files"]["command"] == "npx"


def test_init_is_idempotent(cfg, capsys):
    cli.main(["init", "--no-lock", "--no-audit"])
    capsys.readouterr()
    rc = cli.main(["init", "--no-lock", "--no-audit"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "already wrapped" in out
    assert "wrapped 0 server(s)" in out
    # A second run must not double-wrap: still a single `proxy` and `--exec`.
    files = json.loads(cfg.read_text())["mcpServers"]["files"]
    assert files["args"].count("proxy") == 1 and files["args"].count("--exec") == 1


def test_init_bakes_audit_log_by_default(cfg, tmp_path):
    # Without --no-audit, wrapped servers get an --audit-log so `report` has data to render.
    cli.main(["init", "--no-lock", "--audit-dir", str(tmp_path / "audit")])
    files = json.loads(cfg.read_text())["mcpServers"]["files"]
    assert "--audit-log" in files["args"]
    assert str(tmp_path / "audit" / "files.jsonl") in files["args"]


def test_init_no_config_found_returns_1(monkeypatch, capsys):
    monkeypatch.setattr(onboard, "discover", lambda *a, **k: [])
    assert cli.main(["init"]) == 1
    assert "no MCP client config" in capsys.readouterr().err
