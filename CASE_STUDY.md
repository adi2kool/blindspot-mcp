# Case study — maintenance

The portfolio case study is a **living document**, updated in place each release. Its
revision label tracks the git tags and `CHANGELOG.md`, so the label always describes the
changes it covers.

| | |
| --- | --- |
| Current revision | **Rev 2 · v0.2.0** (July 2026) — reverse-channel enforcement + security audit |
| Standalone HTML | `~/Desktop/blindspot-case-study.html` (loose file, not tracked; exact Spectral + Hanken Grotesk fonts) |
| Canonical Artifact | <https://claude.ai/code/artifact/31840872-e221-4b45-bdec-2fb57b5b6bc6> — **redeploy in place; do not mint a new URL** |

## Updating for a new release

1. Land the release on `main` and tag it: `git tag vX.Y.Z && git push origin vX.Y.Z`.
2. Add a `CHANGELOG.md` entry describing the change set.
3. Regenerate the measured numbers: `uv run python scripts/case-study-stats.py`
   (the ecosystem-study numbers come from a reference-server run — see
   `docs/prevalence-findings.md`).
4. Edit `~/Desktop/blindspot-case-study.html`:
   - bump the revision label (hero `label`, the `.revline`, the footer version),
   - update the "New this revision" line and add a `New in vX.Y.Z` section if warranted,
   - refresh every stat from step 3 (chips, metrics band, rigor findings).
5. Redeploy the Artifact to the **same URL above** (pass it as the artifact `url` so it
   replaces in place instead of minting a new one). Update this table if the URL changes.

Rule of thumb: the label lives in three places — this file's tag, the case study's revision
header, and the `CHANGELOG.md` heading — and they must agree.
