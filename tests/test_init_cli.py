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
    rc = cli.main(["init", "--no-lock", "--no-audit", "--no-shared-taint"])
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


def test_init_hostile_server_name_cannot_escape_audit_dir(tmp_path, monkeypatch):
    from pathlib import Path

    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"../../escaped": {"command": "npx", "args": ["x"]}}}))
    monkeypatch.setattr(onboard, "discover", lambda *a, **k: [("claude-code", path)])
    audit = tmp_path / "audit"
    cli.main(["init", "--no-lock", "--audit-dir", str(audit)])
    files = json.loads(path.read_text())["mcpServers"]["../../escaped"]
    baked = files["args"][files["args"].index("--audit-log") + 1]
    # The baked audit path must resolve to INSIDE audit_dir, not escape via the hostile key.
    assert Path(baked).resolve().is_relative_to(audit.resolve())


def test_init_bakes_a_shared_taint_context_by_default(cfg):
    cli.main(["init", "--no-lock", "--no-audit"])
    servers = json.loads(cfg.read_text())["mcpServers"]
    files_args = servers["files"]["args"]
    remote_args = servers["remote"]["args"]
    assert "--taint-context" in files_args
    # Every server in ONE config shares the SAME context (so A gates C).
    ctx_files = files_args[files_args.index("--taint-context") + 1]
    ctx_remote = remote_args[remote_args.index("--taint-context") + 1]
    assert ctx_files == ctx_remote


def test_init_no_shared_taint_omits_context(cfg):
    cli.main(["init", "--no-lock", "--no-audit", "--no-shared-taint"])
    files_args = json.loads(cfg.read_text())["mcpServers"]["files"]["args"]
    assert "--taint-context" not in files_args


def test_init_no_config_found_returns_1(monkeypatch, capsys):
    monkeypatch.setattr(onboard, "discover", lambda *a, **k: [])
    assert cli.main(["init"]) == 1
    assert "no MCP client config" in capsys.readouterr().err


def test_init_default_never_launches_upstream_but_bakes_pin_on_start(cfg, tmp_path, monkeypatch):
    """SECURITY regression: default init must NOT execute any upstream (launching an unvetted
    server was a confused-deputy RCE). Rug-pull defense is deferred to --pin-on-start on the
    first PROXIED run instead."""
    launched = []
    monkeypatch.setattr(cli, "_pin_upstream", lambda *a, **k: launched.append(a) or True)
    rc = cli.main(["init", "--no-audit", "--no-shared-taint", "--lock-dir", str(tmp_path / "locks")])
    assert rc == 0
    assert launched == []  # nothing was executed
    files = json.loads(cfg.read_text())["mcpServers"]["files"]["args"]
    assert "--pin-on-start" in files and "--lock" not in files


def test_init_pin_flag_opts_into_eager_launch(cfg, tmp_path, monkeypatch):
    """--pin restores the eager launch-to-pin, for configs whose servers are already trusted."""
    launched = []

    def fake_pin(command, cargs, lockpath):
        launched.append(command)
        lockpath.parent.mkdir(parents=True, exist_ok=True)
        lockpath.write_text("{}")
        return True

    monkeypatch.setattr(cli, "_pin_upstream", fake_pin)
    rc = cli.main(["init", "--pin", "--no-audit", "--no-shared-taint", "--lock-dir", str(tmp_path / "locks")])
    assert rc == 0
    assert "npx" in launched  # the stdio server WAS launched to pin, on explicit opt-in
    files = json.loads(cfg.read_text())["mcpServers"]["files"]["args"]
    assert "--lock" in files  # eagerly pinned -> --lock baked instead of --pin-on-start


def test_init_config_flag_targets_explicit_file_and_skips_discovery(tmp_path, monkeypatch):
    """A project-local config is wrapped ONLY when named with --config; auto-discovery (which
    excludes the cwd) is not consulted at all."""
    def _boom(*a, **k):
        raise AssertionError("discovery must not run when --config is given")

    monkeypatch.setattr(onboard, "discover", _boom)
    proj = tmp_path / ".mcp.json"
    proj.write_text(json.dumps({"mcpServers": {"x": {"command": "npx", "args": ["s"]}}}))
    rc = cli.main(["init", "--config", str(proj), "--no-lock", "--no-audit", "--no-shared-taint"])
    assert rc == 0
    x = json.loads(proj.read_text())["mcpServers"]["x"]
    assert x["command"] == "airlock" and "--exec" in x["args"]
