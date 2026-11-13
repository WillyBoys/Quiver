"""cert_transparency (quiver-ct): one JSON object per logged certificate, then a summary.

    {"type": "cert", "id": 123, "names": ["*.example.com", "example.com"],
     "issuer": "C=US, O=..., CN=...", "not_before": "2026-09-26T22:49:11", "not_after": "..."}
    {"type": "summary", "domain": "example.com", "certs": 16, "truncated": false, "errors": []}

crt.sh JSON carries no certificate SHA-256, so certificates are not graph entities here; each
name a certificate covers becomes a `domain` (Blueprint §7.3). A wildcard name `*.x` records
`x` with `ct_wildcard: true` (a certificate covers the names below it). Only names equal to or
below the domain that was asked about are kept; e-mail addresses and other non-domain names
in certificates are skipped. The summary's errors and truncation go to the notes, and a
missing summary (output cut off) is noted too, so an empty result is never read as "no
certificates".
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from quiver.core.graph.record import Observed
from quiver.worker.tracks.external.parsers.common import (
    MAX_ENTITIES,
    NO_RESOLUTIONS,
    Parsed,
    Resolutions,
    domain,
    lines,
    under,
)

MAX_ISSUERS = 5  # per name
MAX_ISSUER_LEN = 200
MAX_NAMES_PER_CERT = 1000
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?$")


@dataclass
class _Seen:
    certs: int = 0
    wildcard: bool = False
    issuers: list[str] = field(default_factory=list)
    first_not_before: str | None = None
    last_not_after: str | None = None

    def add(self, cert: Mapping[str, Any], wildcard: bool) -> None:
        self.certs += 1
        self.wildcard |= wildcard
        issuer = cert.get("issuer")
        if (
            isinstance(issuer, str)
            and 0 < len(issuer) <= MAX_ISSUER_LEN
            and issuer not in self.issuers
            and len(self.issuers) < MAX_ISSUERS
        ):
            self.issuers.append(issuer)
        nb, na = _timestamp(cert.get("not_before")), _timestamp(cert.get("not_after"))
        if nb and (self.first_not_before is None or nb < self.first_not_before):
            self.first_not_before = nb
        if na and (self.last_not_after is None or na > self.last_not_after):
            self.last_not_after = na

    def attributes(self, name: str) -> dict:
        attrs: dict[str, Any] = {
            "name": name,
            "ct_certs": self.certs,
            "ct_wildcard": self.wildcard,
            "ct_issuers": sorted(self.issuers),
        }
        if self.first_not_before:
            attrs["ct_first_not_before"] = self.first_not_before
        if self.last_not_after:
            attrs["ct_last_not_after"] = self.last_not_after
        return attrs


def _timestamp(value: Any) -> str | None:
    return value if isinstance(value, str) and _TIMESTAMP.match(value) else None


def _summary(data: Mapping[str, Any]) -> dict:
    certs = data.get("certs")
    errors = data.get("errors")
    return {
        "certs": certs if isinstance(certs, int) and not isinstance(certs, bool) else None,
        "truncated": data.get("truncated") is True,
        "errors": [e[:200] for e in errors if isinstance(e, str)][:5]
        if isinstance(errors, list)
        else [],
    }


def parse(
    output: bytes, params: Mapping[str, Any], *, resolutions: Resolutions = NO_RESOLUTIONS
) -> Parsed:
    base = domain(params.get("domain"))
    if base is None:
        raise ValueError("cert_transparency job has no valid domain parameter")

    found: dict[str, _Seen] = {}
    summary: dict | None = None
    certs = skipped = 0
    capped = False
    for line in lines(output):
        data = line.data
        if data is None:
            if line.text.startswith("{"):
                skipped += 1  # a JSON line we could not read (e.g. cut off by the output cap)
            continue
        kind = data.get("type")
        if kind == "summary":
            summary = _summary(data)
            continue
        names = data.get("names")
        if kind != "cert" or not isinstance(names, list):
            skipped += 1
            continue
        certs += 1
        in_cert: dict[str, bool] = {}  # name -> covered by a wildcard in this certificate
        for raw in names[:MAX_NAMES_PER_CERT]:
            if not isinstance(raw, str):
                skipped += 1
                continue
            wildcard = raw.startswith("*.")
            name = domain(raw[2:] if wildcard else raw)
            if name is None or not under(name, base):
                skipped += 1  # e-mail addresses, free text, foreign names, nested wildcards
                continue
            in_cert[name] = in_cert.get(name, False) or wildcard
        for name, wildcard in in_cert.items():
            if name not in found:
                if len(found) >= MAX_ENTITIES:
                    capped = True
                    continue
                found[name] = _Seen()
            found[name].add(data, wildcard)

    entities = tuple(
        Observed("domain", seen.attributes(name)) for name, seen in sorted(found.items())
    )
    notes: dict[str, Any] = {"names": len(entities), "certs": certs}
    if summary is None:
        notes["summary_missing"] = True  # the tool did not finish or its output was cut
    else:
        notes.update(truncated=summary["truncated"], errors=summary["errors"])
    return Parsed(entities=entities, skipped=skipped, capped=capped, notes=notes)
