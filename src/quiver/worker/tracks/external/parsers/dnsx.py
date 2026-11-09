"""dns_resolve (dnsx -json -a -aaaa -cname -resp): one JSON object per name that answered.

    {"host": "www.example.com", "a": ["203.0.113.10"], "aaaa": ["2001:db8::10"],
     "cname": ["edge.provider.net"], "status_code": "NOERROR", ...}

Only names the job asked about are kept. Each becomes a `domain` (with its CNAME chain,
response code and addresses as reported data) and each address a `host`, linked by
`resolves_to`. Addresses are recorded whatever they are (private, loopback): the graph keeps
what was seen, and the policy gate alone decides what may be touched. Names that did not
resolve are not reported line by line; dnsx's count of them is kept in the notes.
"""

import re
from collections.abc import Mapping
from typing import Any

from quiver.core.graph.record import Link, Observed
from quiver.worker.tracks.external.parsers.common import (
    MAX_ENTITIES,
    Parsed,
    domain,
    ip,
    lines,
    strings,
)

MAX_ADDRESSES = 50  # per name
MAX_CNAMES = 10
_UNRESOLVED = re.compile(r"^\[WRN\] (\d{1,9}) domains? failed to resolve")
_RCODE = re.compile(r"^[A-Z]{1,20}$")


def parse(output: bytes, params: Mapping[str, Any]) -> Parsed:
    hosts = params.get("hosts")
    asked = {d for d in map(domain, hosts if isinstance(hosts, list) else []) if d}
    if not asked:
        raise ValueError("dns_resolve job has no valid hosts parameter")

    names: dict[str, dict] = {}
    skipped = 0
    capped = False
    unresolved = 0
    for line in lines(output):
        if line.data is None:
            m = _UNRESOLVED.match(line.text)
            if m:
                unresolved += int(m.group(1))
            elif line.text.startswith("{"):
                skipped += 1
            continue
        name = domain(line.data.get("host"))
        if name is None or name not in asked:
            skipped += 1
            continue
        addresses: list[str] = []
        for field in ("a", "aaaa"):
            values = line.data.get(field, [])
            if not isinstance(values, list):
                continue
            addresses.extend(a for a in map(ip, values) if a)
        addresses = list(dict.fromkeys(addresses))[:MAX_ADDRESSES]
        cnames = [c for c in map(domain, strings(line.data.get("cname", []), limit=50) or []) if c][
            :MAX_CNAMES
        ]
        rcode = line.data.get("status_code")
        attrs = {"name": name, "addresses": addresses, "cnames": cnames}
        if isinstance(rcode, str) and _RCODE.match(rcode):
            attrs["rcode"] = rcode
        if name not in names and len(names) >= MAX_ENTITIES:
            capped = True
            continue
        names[name] = attrs

    entities: dict[str, Observed] = {}
    links: list[Link] = []
    for name, attrs in sorted(names.items()):
        dom = Observed("domain", attrs)
        entities[f"domain:{name}"] = dom
        for address in attrs["addresses"]:
            host = entities.setdefault(f"host:{address}", Observed("host", {"ip": address}))
            links.append(Link("resolves_to", dom, host))
    return Parsed(
        entities=tuple(entities.values()),
        links=tuple(links),
        skipped=skipped,
        capped=capped,
        notes={"answered": len(names), "unresolved": unresolved},
    )
