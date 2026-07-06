"""Remediation: for each scanned item that carries invisible-unicode payloads,
propose a sanitized rewrite (convention Phase 2 item 4).

This does more than flag: it strips the invisible payloads and returns the clean
text, using the SAME shared sanitizer the provenance tagger applies at emit. So the
scanner's proposed fix and the tagger's emit-time cleaning are byte-for-byte the
same operation.
"""

from __future__ import annotations

from collections.abc import Iterable

from blindspot.models import Remediation, ScanTarget
from blindspot.sanitize import strip_invisible


def propose_remediations(targets: Iterable[ScanTarget]) -> list[Remediation]:
    """Return a sanitized rewrite for every item whose text changed under sanitizing."""
    remediations: list[Remediation] = []
    for item in targets:
        result = strip_invisible(item.text)
        if result.changed:
            remediations.append(
                Remediation(
                    target=item.identifier,
                    surface=item.surface,
                    removed_invisible=result.removed_zero_width,
                    decoded_tag_text=list(result.decoded_tag_text),
                    sanitized=result.text,
                )
            )
    return remediations
