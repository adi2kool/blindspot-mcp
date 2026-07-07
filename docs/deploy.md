# Deploy Airlock

Airlock is the enforcing proxy for MCP: point your client at Airlock instead of the server,
and untrusted content arrives framed as data, side-effecting calls are gated, and every
decision is attested - with zero changes to the server. This page is copy-paste recipes.

## Install

```bash
# From PyPI
pip install airlock-mcp          # provides the `airlock` command

# Or run without installing (uv)
uvx airlock-mcp scan path/to/server.py
uvx airlock-mcp proxy path/to/server.py --on-action block
```

Requires Python 3.11+. The deterministic core runs at $0 with no network; the optional
local-model judge/inference use a local Ollama if present and fail safe if not.

## Scan a server (the on-ramp)

```bash
airlock scan  path/to/server.py                 # a Python stdio server
airlock scan  --http http://127.0.0.1:3001/mcp  # any server in HTTP mode
airlock scan-source path/to/server/src          # static, without executing it
airlock scan-memory path/to/memory_server.py    # a memory server's stored entries
```

## Put the proxy in front of a server

```bash
# A Python stdio server: Airlock launches it and serves the enforced boundary over stdio.
airlock proxy path/to/server.py --on-action block

# Any server (incl. Node/npx) over HTTP: run the server in HTTP mode, then front it.
#   e.g.  PORT=3001 npx -y @modelcontextprotocol/server-everything streamableHttp
airlock proxy --http http://127.0.0.1:3001/mcp --on-action block --audit-log audit.jsonl
```

> Note: today the stdio launcher runs `python <target>`, so a non-Python (Node/npx) server
> is fronted over **HTTP** as shown. Direct `airlock proxy -- npx …` launching is a planned
> fast-follow (`connect()` already supports arbitrary commands).

## Front Claude Desktop

Edit `claude_desktop_config.json` and route a server through Airlock. For a **Python** stdio
server, replace its entry:

```jsonc
{
  "mcpServers": {
    "notes": {
      "command": "airlock",
      "args": ["proxy", "/abs/path/to/notes_server.py", "--on-action", "block",
               "--audit-log", "/abs/path/to/airlock-audit.jsonl"]
    }
  }
}
```

For a **Node/npx** server, run it in HTTP mode (a small wrapper or a `launchd`/service entry),
then point Airlock at it:

```jsonc
{
  "mcpServers": {
    "files": {
      "command": "airlock",
      "args": ["proxy", "--http", "http://127.0.0.1:3001/mcp", "--on-action", "approve",
               "--approval-webhook", "https://your.endpoint/approve"]
    }
  }
}
```

Restart Claude Desktop. Untrusted tool output now arrives demarcated as data, and a
side-effecting call after untrusted content is in the session is blocked or held for
approval before it reaches the server.

## Front Cursor / any MCP client

Any client that speaks MCP over stdio works the same way: wherever the client config names a
server `command`, substitute `airlock proxy <server> …`. For HTTP-configured clients, point
the client at the Airlock proxy endpoint.

## Docker

```bash
docker run --rm ghcr.io/adi2kool/airlock-mcp --help
docker run --rm ghcr.io/adi2kool/airlock-mcp scan --http http://host.docker.internal:3001/mcp
docker run --rm ghcr.io/adi2kool/airlock-mcp proxy --http http://host.docker.internal:3001/mcp --on-action block
```

The container fronts an **HTTP** upstream (the stdio launcher is Python-only inside the
image); use the host install for stdio Python servers.

## Governance flags worth knowing

- `--on-action annotate|approve|block` - gate side-effecting calls once untrusted content is in the session.
- `--on-sampling|--on-elicitation frame|block` - enforce the server->client channels.
- `--lock airlock.lock` / `--pin-on-start` + `--on-drift block` - catch a mid-session rug pull.
- `--audit-log audit.jsonl --audit-key op.key` then `airlock verify-log audit.jsonl` - a signed, tamper-evident record.

See `README.md` for the full flag reference.
