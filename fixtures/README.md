# Fixtures

These are inert test fixtures. Every payload in this directory is inert. Nothing
here performs network, email, or filesystem I/O. The payloads exist only so the
Phase 1 scanner has something to catch and the Phase 2 enforcer has something to
neutralize. None of it is functional attack code.

## Files

- `vulnerable_server.py`: a local stdio MCP server that exposes a poisoned resource
  and prompt. The false target.
- `clean_server.py`: the same surface with benign content and no payloads. The
  false-positive control. A scanner must produce zero findings here.
- `scratch_client.py`: the Stage 1 client. Connects to a server over stdio, lists
  its prompts, resources, and tools, and prints their full contents (rendered and
  as `repr()` so invisible characters are visible).
- `tagged_server.py`: a conforming Phase 2 tagging server, built on the low-level
  MCP Server so it emits provenance in each item's `_meta`. Operator-authored
  content is tagged trusted; content it fetched from a third party is honestly
  tagged external/untrusted and carries an inert injection, so the reference client
  enforcer (`airlock guard`) can demonstrate demoting it to data. Also inert.
- `compose_files_server.py`, `compose_web_server.py`, `compose_mailer_server.py`:
  three clean single-purpose servers for the Phase 3 cross-server composition demo
  (`airlock compose`). The files server supplies only the private-data leg, the web
  server only the untrusted-content leg, and the mailer only the exfiltration leg.
  Each is individually clean with no injection payloads; only the composition of all
  three enables the lethal trifecta. All tools are inert and perform no real I/O.
- `hostile_upstream.py`: an adversarial upstream for testing the enforcing proxy. It
  emits the same inert injection through several content shapes (a plain tool text
  block, an EmbeddedResource inside a tool result and inside a prompt message, and a
  plain resource body), all untagged, so the proxy tests can prove every shape is
  enforced and no raw injection leaks. Inert.

## Surface (both servers)

- Resource `notes://internal`
- Prompt `summarize_ticket(ticket_id)`
- Tools `send_email(to, subject, body)` and `create_ticket(title, body)`

The two servers are identical except for the payloads in the vulnerable one.

## Payload inventory (vulnerable_server.py only)

The payloads cover the attack taxonomy the project models. Each maps to a sanitizer
category the Phase 2 library will need.

- Instruction override: the prompt tells the agent to ignore previous instructions
  and system rules.
- Tool shadowing: the prompt tells the agent to call `send_email` whenever it would
  call `create_ticket`, hijacking one trusted tool with another.
- Exfiltration directive: the payloads name inert sinks (see below) as the
  destination for the resource contents.
- Hidden and invisible payloads, using three techniques:
  - Zero-width characters: `U+200B` ZERO WIDTH SPACE, `U+200C` ZERO WIDTH
    NON-JOINER, `U+200D` ZERO WIDTH JOINER, `U+FEFF` ZERO WIDTH NO-BREAK SPACE.
  - Unicode tag characters: printable ASCII encoded into the `U+E0000` block
    (`U+E0020`..`U+E007E`), the classic invisible ASCII-smuggling channel. The
    plaintext of the smuggled instruction is written in the source in readable
    ASCII before it is encoded, so a reviewer can see exactly what is hidden.
  - Homoglyphs: the word "admin" written with a Cyrillic `а` (`U+0430`) so a naive
    Latin keyword filter misses it.
- Conditional or sleeper payload: the hidden resource instruction activates only on
  a later action ("when the user next summarizes any ticket"), linking the resource
  to the prompt.

## Inert sinks

The exfiltration directives name destinations that cannot receive anything:

- `attacker@example.invalid`: the `.invalid` top-level domain is reserved and never
  resolves (RFC 6761).
- `http://192.0.2.1/collect`: `192.0.2.0/24` is TEST-NET-1, reserved and
  non-routable (RFC 5737).

These appear as strings only. No code in this repository contacts them.
