# Performance review (Phase B)

Goal of this pass: confirm the enforcement hot path is cheap, that every regex-bearing
path is linear-time (no ReDoS), and that memory stays bounded on large inputs.

Method: local microbenchmarks (Python 3.13, single machine, warm cache, 5–50 reps after
warmup). Numbers are indicative, not a formal benchmark; the shape (linear vs
super-linear) is the point, not the absolute constants. Reproduce with the harness under
`benchmark/` and the perf notes below.

## Enforcement hot path

`enforce()` on an untagged body (the common proxy case: demote to a framed data block)
is dominated by a single sanitizer pass and a hash, and is effectively free:

| body size | latency | throughput |
| --------- | ------- | ---------- |
| 1 KB      | ~1.8 µs | ~0.6 GB/s  |
| 10 KB     | ~4.8 µs | ~2.1 GB/s  |
| 100 KB    | ~40 µs  | ~2.6 GB/s  |

The signed/verify path (trusted content with an HMAC signature, which re-sanitizes and
re-hashes) is heavier but cleanly linear — ~0.37 ms / ~3.5 ms / ~37 ms at 1 / 10 / 100 KB
(a clean 10× per 10× of input). The higher constant is the per-character invisible-unicode
sanitizer, an existing cost, not new. Signing/verification is only engaged when a key is
configured.

## Linear-time guarantees (ReDoS)

Two quadratic ReDoS defects were found and fixed in the scanner in earlier sessions
(sessions 8 and 11). This pass re-checked the scanner and the regexes added since
(`enforce/proxy.py` `_DESTRUCTIVE_ACTION`, and `compose.py` `_normalize`, which now splits
camelCase). All stay linear on adversarial input:

- Scanner exfil detector on a whitespace-free `http://…` run followed by a verb (the shape
  that used to backtrack): ~7.5 / ~30 / ~62 ms at 10 / 40 / 80 KB — linear in input size.
- `_normalize` + `_DESTRUCTIVE_ACTION` on a pathological alternating-case run (maximizes
  camelCase-split work): ~1.6 / ~17 / ~177 ms at 10 / 100 / 1000 KB — a clean 10× per 10×.
- `_is_side_effecting` on a 100 KB adversarial tool name+description: ~140 ms, linear. Real
  tool names are a handful of characters, so this is microseconds in practice.

No pattern exhibited super-linear growth.

## Memory

`enforce()` on a 1 MB untrusted body peaks at ~1.0 MB of Python allocation (≈1× the input).
No quadratic buffering. The proxy holds one upstream item at a time; it does not accumulate
the session's content.

## Proxy added latency

The proxy's added cost per item is the `enforce()` call above (tens of microseconds for the
untagged path). End-to-end proxy latency is dominated by the upstream MCP round-trip, which
the proxy does not change. In the `approve`/`block` action-gating modes a per-session lock
serializes tool calls to make gating race-free; this adds no measurable latency to a normal
sequential agent flow and only reduces concurrency for operators who opted into strict
gating (a deliberate safety-over-throughput trade). `annotate` (the default) takes a no-op
lock and keeps full concurrency.

## LLM inference / judge cost (opt-in)

The deterministic fast path above is the default. When `--infer` or `--judge on` is enabled,
per-item latency is dominated by the model round-trip (local Ollama: typically hundreds of
ms to seconds depending on model and hardware; a remote free tier depends on the network).
Both features are fail-safe: with no model reachable they fall back to the deterministic
behavior and add no blocking latency. Operators who need throughput should leave inference
off and rely on the structural framing, which is the guarantee regardless.
