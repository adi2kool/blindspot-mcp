"""Tests for the `airlock init` onboarding logic (pure, no filesystem/network)."""

from __future__ import annotations

from pathlib import Path

from airlock import onboard


def test_candidate_configs_per_platform():
    home = Path("/home/u")
    cwd = Path("/proj")
    mac = onboard.candidate_configs(home, "darwin", cwd)
    assert mac["claude-desktop"][0] == home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    lin = onboard.candidate_configs(home, "linux", cwd)
    assert lin["claude-desktop"][0] == home / ".config" / "Claude" / "claude_desktop_config.json"
    win = onboard.candidate_configs(home, "win32", cwd, appdata="C:/Users/u/AppData/Roaming")
    assert win["claude-desktop"][0] == Path("C:/Users/u/AppData/Roaming") / "Claude" / "claude_desktop_config.json"
    # Cursor + Claude Code look in home and cwd.
    assert home / ".cursor" / "mcp.json" in mac["cursor"]
    assert cwd / ".mcp.json" in mac["claude-code"]


def test_read_servers_tolerates_absent_or_malformed():
    assert onboard.read_servers({"mcpServers": {"a": {}}}) == {"a": {}}
    assert onboard.read_servers({}) == {}
    assert onboard.read_servers({"mcpServers": "nope"}) == {}
    assert onboard.read_servers("not a dict") == {}


def test_wrap_spec_stdio_preserves_command_and_env():
    spec = {"command": "npx", "args": ["-y", "@scope/server"], "env": {"API_KEY": "x"}}
    flags = ["--on-egress", "block", "--audit-log", "/a/srv.jsonl"]
    new = onboard.wrap_spec(spec, ["airlock"], flags)
    assert new["command"] == "airlock"
    assert new["args"] == [
        "proxy", "--on-egress", "block", "--audit-log", "/a/srv.jsonl",
        "--exec", "npx", "-y", "@scope/server",
    ]
    assert new["env"] == {"API_KEY": "x"}  # env carried through to the real upstream
    # --exec is last so everything after it is the upstream command line.
    assert new["args"][-3:] == ["npx", "-y", "@scope/server"]


def test_wrap_spec_http_uses_http_flag():
    spec = {"url": "https://host/mcp", "type": "http"}
    new = onboard.wrap_spec(spec, ["airlock"], ["--audit-log", "/a/h.jsonl"])
    assert new["command"] == "airlock"
    assert new["args"] == ["proxy", "--http", "https://host/mcp", "--audit-log", "/a/h.jsonl"]
    assert "url" not in new and "type" not in new


def test_wrap_spec_launcher_prefix():
    spec = {"command": "node", "args": ["server.js"]}
    new = onboard.wrap_spec(spec, ["uvx", "airlock-mcp"], [])
    assert new["command"] == "uvx"
    assert new["args"] == ["airlock-mcp", "proxy", "--exec", "node", "server.js"]


def test_is_wrapped_idempotency():
    spec = {"command": "npx", "args": ["-y", "@scope/server"]}
    wrapped = onboard.wrap_spec(spec, ["airlock"], ["--audit-log", "/a/s.jsonl"])
    assert onboard.is_wrapped(wrapped, ["airlock"]) is True
    assert onboard.is_wrapped(spec, ["airlock"]) is False
    # Recognized regardless of the exact launcher, by an airlock command + a proxy subcommand.
    assert onboard.is_wrapped({"command": "airlock", "args": ["proxy", "--exec", "x"]}, ["uvx", "airlock-mcp"]) is True


def test_plan_servers_categorizes():
    spec_stdio = {"command": "npx", "args": ["-y", "@a/s"]}
    servers = {
        "stdio": spec_stdio,
        "remote": {"url": "https://h/mcp"},
        "already": onboard.wrap_spec(spec_stdio, ["airlock"], []),
        "broken": {"note": "no command or url"},
    }
    plans = {p.name: p for p in onboard.plan_servers(servers, ["airlock"], lambda n, s: ["--audit-log", f"/a/{n}.jsonl"])}
    assert plans["stdio"].action == "wrap"
    assert plans["stdio"].upstream == ("npx", ["-y", "@a/s"])
    assert plans["remote"].action == "wrap" and plans["remote"].upstream is None
    assert plans["already"].action == "skip-wrapped"
    assert plans["broken"].action == "skip-unwrappable"
    # The wrapped stdio plan carries the per-server flags from flags_for.
    assert "--audit-log" in plans["stdio"].new_spec["args"]
    assert "/a/stdio.jsonl" in plans["stdio"].new_spec["args"]
