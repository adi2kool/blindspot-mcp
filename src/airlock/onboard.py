"""`airlock init`: wrap a client's MCP servers behind the enforcing proxy in one command.

The onboarding cliff is real: to protect a server today you must know your own MCP topology
and hand-wire `airlock proxy` in front of each one. This module reads a client's config
(Claude Desktop / Cursor / Claude Code all share the `mcpServers` shape), and rewrites every
server's launch command to route through `airlock proxy` - preserving the original command
as the upstream via `--exec` (stdio) or `--http` (remote). The original config is backed up
first, so the change is reversible.

The logic here is PURE over given config dicts and paths (no filesystem, no network), so it
is easy to test and reason about; the CLI (`_cmd_init`) does the IO and, best-effort, launches
each server once to pin its surface into a lockfile (rug-pull defense) in the same pass.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

CLIENTS = ("claude-desktop", "cursor", "claude-code")


def taint_context_id(config_path: str) -> str:
    """A short, stable id for the cross-server taint context of one client config. Every server
    in the SAME config shares it (one client = one agent = one taint context), so an injection
    into any of that client's servers gates a side-effecting call to another; different configs
    get different ids so unrelated clients do not share taint."""
    return hashlib.sha256(str(config_path).encode("utf-8")).hexdigest()[:16]

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def safe_component(name: str) -> str:
    """A filesystem-safe single path component derived from a server name.

    A server name is a config KEY controlled by whoever authored the config (including a
    project-local `.mcp.json` in a cloned repo), and `airlock init` uses it to build lockfile
    and audit-log paths. Left raw, a name like `../../x` or `/etc/x` would traverse or escape
    to an absolute path and write outside the intended directory. This replaces every
    character outside [A-Za-z0-9._-] with `_` (so no path separator survives), strips leading
    dots (no hidden or `..` names), bounds the length, and falls back to `server` if nothing
    is left - guaranteeing the result is a plain component that stays inside its directory."""
    safe = _UNSAFE_NAME.sub("_", str(name)).lstrip(".")
    return safe[:100] or "server"

# Command basenames that mean "this entry is already an airlock proxy" (idempotency).
_AIRLOCK_LAUNCHERS = frozenset({"airlock", "airlock-mcp"})


def candidate_configs(home: Path, platform: str, cwd: Path, appdata: str | None = None) -> dict[str, list[Path]]:
    """The candidate config path(s) per client, resolved for a home dir + platform. Pure, so
    discovery is testable without touching the real filesystem. `platform` is os.sys.platform
    ('darwin' / 'win32' / 'linux'); `appdata` is %APPDATA% on Windows.

    SECURITY: only USER-level config locations are auto-discovered. Project-local configs
    (`./.mcp.json`, `./.cursor/mcp.json`) are deliberately NOT scanned: `airlock init`'s pin
    step can launch a server, so auto-discovering a config from the current directory would let
    a cloned/downloaded repo's checked-in `mcpServers` run an attacker command merely because
    the user ran `init` inside it. A project-local config must be named explicitly with
    `--config PATH`, which is a deliberate, per-file opt-in. `cwd` is accepted for signature
    stability but no longer contributes candidates."""
    if platform == "darwin":
        desktop = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif platform.startswith("win"):
        base = Path(appdata) if appdata else home / "AppData" / "Roaming"
        desktop = base / "Claude" / "claude_desktop_config.json"
    else:
        desktop = home / ".config" / "Claude" / "claude_desktop_config.json"
    return {
        "claude-desktop": [desktop],
        "cursor": [home / ".cursor" / "mcp.json"],
        "claude-code": [home / ".claude.json"],
    }


def discover(clients, home: Path, platform: str, cwd: Path, appdata: str | None = None) -> list[tuple[str, Path]]:
    """Existing (client, config-path) pairs for the requested clients."""
    cands = candidate_configs(home, platform, cwd, appdata)
    found: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for client in clients:
        for path in cands.get(client, []):
            try:
                if path.is_file() and path not in seen:
                    seen.add(path)
                    found.append((client, path))
            except OSError:
                continue
    return found


def read_servers(doc: dict) -> dict:
    """The `mcpServers` block of a parsed config, or empty if absent/malformed."""
    servers = doc.get("mcpServers") if isinstance(doc, dict) else None
    return servers if isinstance(servers, dict) else {}


def _launcher_command(command) -> bool:
    if not isinstance(command, str):
        return False
    base = Path(command).name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base in _AIRLOCK_LAUNCHERS


def is_wrapped(spec: dict, launcher: list[str]) -> bool:
    """True if this entry already routes through an airlock proxy (so init is idempotent).

    Recognized by an airlock-launcher plus a `proxy` subcommand in the args - independent of
    which flags follow. The launcher may be the COMMAND (`airlock proxy ...`) or a token in the
    args before `proxy` when a runner fronts it (`uvx airlock-mcp proxy ...`, `python -m
    airlock.cli proxy ...`). Checking the args too keeps init idempotent even when a LATER run
    uses a different --launcher than the one that first wrapped the config (otherwise the
    unrecognized wrap gets wrapped again - `airlock proxy --exec uvx airlock-mcp proxy ...`)."""
    if not isinstance(spec, dict):
        return False
    args = spec.get("args") or []
    if not isinstance(args, list) or "proxy" not in args:
        return False
    command = spec.get("command")
    if _launcher_command(command) or (bool(launcher) and command == launcher[0]):
        return True
    # A wrap fronted by a runner: look for an airlock launcher token among the args that
    # precede `proxy` (e.g. `uvx airlock-mcp proxy`, `python -m airlock.cli proxy`).
    lead = args[: args.index("proxy")]
    return any(_launcher_command(tok) for tok in lead) or "airlock.cli" in lead


def wrap_spec(spec: dict, launcher: list[str], proxy_flags: list[str]) -> dict:
    """Return a new server spec that runs the original server behind `airlock proxy`.

    `launcher` is the token list that invokes airlock (e.g. ['airlock'] or ['uvx',
    'airlock-mcp']). `proxy_flags` are the fully-resolved proxy flags for THIS server (any
    --audit-log / --lock / --on-egress already included). A stdio server (has `command`) is
    fronted via `--exec <command> <args...>`; a remote server (has `url`) via `--http <url>`.
    The original `env` is preserved so the upstream still gets its keys."""
    new = dict(spec)
    new["command"] = launcher[0]
    prefix = list(launcher[1:])
    url = spec.get("url")
    if url and not spec.get("command"):
        new["args"] = prefix + ["proxy", "--http", str(url), *proxy_flags]
        new.pop("url", None)
        new.pop("type", None)
    else:
        orig_command = spec.get("command")
        orig_args = list(spec.get("args") or [])
        # --exec MUST be last: everything after it is the upstream command line.
        new["args"] = prefix + ["proxy", *proxy_flags, "--exec", orig_command, *orig_args]
    return new


def is_wrappable(spec: dict) -> bool:
    """True if we know how to front this server (it declares a stdio command or a url)."""
    return isinstance(spec, dict) and bool(spec.get("command") or spec.get("url"))


@dataclass
class ServerPlan:
    name: str
    action: str  # "wrap" | "skip-wrapped" | "skip-unwrappable"
    new_spec: dict | None = None
    upstream: tuple[str, list[str]] | None = None  # (command, args) for a stdio server, for pinning


def plan_servers(servers: dict, launcher: list[str], flags_for) -> list[ServerPlan]:
    """Decide what happens to each server. `flags_for(name, spec) -> list[str]` supplies the
    per-server proxy flags (so the caller can inject a per-server --audit-log / --lock). Pure."""
    plans: list[ServerPlan] = []
    for name, spec in servers.items():
        if not is_wrappable(spec):
            plans.append(ServerPlan(name, "skip-unwrappable"))
            continue
        if is_wrapped(spec, launcher):
            plans.append(ServerPlan(name, "skip-wrapped"))
            continue
        flags = list(flags_for(name, spec))
        new = wrap_spec(spec, launcher, flags)
        upstream = None
        if spec.get("command") and not spec.get("url"):
            upstream = (spec["command"], list(spec.get("args") or []))
        plans.append(ServerPlan(name, "wrap", new_spec=new, upstream=upstream))
    return plans
