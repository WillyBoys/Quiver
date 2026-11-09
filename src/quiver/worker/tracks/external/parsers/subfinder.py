"""subdomain_enum (subfinder -json -cs): one JSON object per name found.

    {"host": "www.example.com", "input": "example.com", "sources": ["crtsh", "anubis"]}

Only names equal to or below the domain that was asked about are kept: a source can return
anything, and the parser trusts none of it. Each name becomes a `domain` entity. Source errors
(`[WRN] Encountered an error with source X: ...`) are collected, because subfinder exits 0 even
when every source failed, and an empty result must not read as "no subdomains".
"""

import re
from collections.abc import Mapping
from typing import Any

from quiver.core.graph.record import Observed
from quiver.worker.tracks.external.parsers.common import (
    MAX_ENTITIES,
    Parsed,
    domain,
    lines,
    strings,
    under,
)

_SOURCE_ERROR = re.compile(r"^\[WRN\] Encountered an error with source ([A-Za-z0-9_.-]{1,50}):")


def parse(output: bytes, params: Mapping[str, Any]) -> Parsed:
    base = domain(params.get("domain"))
    if base is None:
        raise ValueError("subdomain_enum job has no valid domain parameter")

    found: dict[str, set[str]] = {}
    source_errors: set[str] = set()
    skipped = 0
    capped = False
    for line in lines(output):
        if line.data is None:
            m = _SOURCE_ERROR.match(line.text)
            if m:
                source_errors.add(m.group(1))
            elif line.text.startswith("{"):
                skipped += 1  # a JSON line we could not read (e.g. cut off by the output cap)
            continue
        name = domain(line.data.get("host"))
        sources = strings(line.data.get("sources", []), limit=50, max_len=50)
        if name is None or sources is None or not under(name, base):
            skipped += 1
            continue
        if name not in found and len(found) >= MAX_ENTITIES:
            capped = True
            continue
        found.setdefault(name, set()).update(sources)

    entities = tuple(
        Observed("domain", {"name": name, "sources": sorted(sources)})
        for name, sources in sorted(found.items())
    )
    return Parsed(
        entities=entities,
        skipped=skipped,
        capped=capped,
        notes={"names": len(entities), "source_errors": sorted(source_errors)},
    )
