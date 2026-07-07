# Data handling and privacy

Airlock is designed to run at $0 with nothing leaving the machine by default.
This document states exactly what the tool does and does not send anywhere.

## The deterministic core sends nothing

The scanner detectors, the provenance/tagging library, the integrity and signing
code, the client enforcer, the enforcing proxy's structural framing, the
composition analysis, and the adaptive-attack harness are all **local and offline**.
They perform no network I/O. Scanning, tagging, enforcing, signing, and the red-team
run never contact any external service.

## No telemetry

The tool collects and transmits no usage data, metrics, or crash reports. There is
no analytics endpoint and no phone-home. Nothing is logged off the machine.

## Optional network features (opt-in, explicit endpoints only)

Three features touch the network, all off by default and all pointed only at an
endpoint the operator configures:

1. **Semantic judge** (`airlock scan --judge on`) and **LLM provenance inference**
   (`airlock proxy --infer`). These call a model server. The default is a **local**
   Ollama instance (`http://localhost:11434`), so nothing leaves the machine. If the
   operator sets `AIRLOCK_JUDGE_URL` / `AIRLOCK_INFER_URL` to a remote endpoint
   (for example a free hosted tier), then the content being classified is sent to
   that endpoint — the operator's explicit choice. Both features fail safe: if no
   model is reachable they fall back to the conservative local behavior and never
   block on the network.

   What is sent when enabled: the text of the item being classified (a resource
   body, prompt, or tool output) plus a fixed instruction. Nothing else.

2. **JWKS `.well-known` key discovery** (`KeyStore.from_wellknown`). Fetches a public
   key set from a URL the operator configures. It is fail-open (an unreachable
   endpoint yields an empty key store), disables redirects, and caps the response
   size. Only public keys are fetched; no secret or content is sent. The default
   key-discovery path is a **local JWKS file** (`--keystore`), which needs no network.

## What is never transmitted

Private keys, shared secrets, and the operator's content are never transmitted by
the deterministic core. Signing uses keys locally; the enforcer verifies locally.
The only content that can leave the machine is the item text sent to an
operator-configured model endpoint when inference/judge is explicitly enabled with a
remote URL.
