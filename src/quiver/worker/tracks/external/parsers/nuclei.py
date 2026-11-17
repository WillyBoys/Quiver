"""nuclei_scan (quiver-bind → nuclei -jsonl -or -ot): one JSON object per match.

    {"template-id": "git-config", "info": {"name": "...", "severity": "medium",
       "tags": [...], "classification": {"cwe-id": [...], "cve-id": null, ...}},
     "matcher-name": "...", "type": "http", "host": "203.0.113.10", "ip": "203.0.113.10",
     "port": "80", "scheme": "http", "matched-at": "http://203.0.113.10:80/.git/config",
     "extracted-results": [...], "curl-command": "curl ..."}

quiver-bind ran nuclei against the pinned addresses with the job's host as Host header and
SNI, so each match is rebuilt under that host: the `web_endpoint` at the matched path
(`http://www.example.com:80/.git/config`), served by its `service` and `on_domain` the host.
Each match is a **candidate** finding on that endpoint. Its identity is the template id, the
endpoint and the matcher name (`finding_key`), so a later run of the same check updates the
same finding; extracted values (versions, tokens) are details, not identity.

Everything here except the template's own fields is target-controlled. Matches about an
address the job was not given, or of a protocol other than HTTP, are skipped.
"""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from quiver.core.graph import keys
from quiver.core.graph.record import EvidenceIn, FindingIn, Link, Observed
from quiver.core.models import Severity
from quiver.worker.tracks.external.parsers.common import (
    MAX_ENTITIES,
    NO_RESOLUTIONS,
    BoundInput,
    Parsed,
    Resolutions,
    ip,
    lines,
    port,
    text,
)

MAX_FINDINGS = 10_000
MAX_LIST = 10
MAX_EXCERPT = 4000
_SEVERITIES = {s.value for s in Severity}


def _obj(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any, limit: int = MAX_LIST, max_len: int = 200) -> list[str]:
    """Strings from a field that may be one string or a list: truncated, deduplicated,
    capped; anything that is not a string is dropped."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out = dict.fromkeys(v.strip()[:max_len] for v in value if isinstance(v, str) and v.strip())
    return list(out)[:limit]


def _endpoint_url(matched: Any, host: str, default_port: int) -> str | None:
    """The matched URL rebuilt under the job's host (the match itself names the address)."""
    if not isinstance(matched, str):
        return None
    try:
        parts = urlsplit(matched)
        number = parts.port or default_port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    try:
        return keys.canonical_url(f"{parts.scheme}://{host}:{number}{parts.path or '/'}")
    except ValueError:
        return None


def _details(info: Mapping[str, Any], data: Mapping[str, Any]) -> dict[str, Any]:
    classification = _obj(info.get("classification"))
    details: dict[str, Any] = {
        "template": text(data.get("template-id"), 100),
        "tags": _list(info.get("tags"), 20, 50),
        "references": _list(info.get("reference"), MAX_LIST, 500),
        "cve": _list(classification.get("cve-id"), MAX_LIST, 50),
        "cwe": _list(classification.get("cwe-id"), MAX_LIST, 50),
        "extracted": _list(data.get("extracted-results")),
    }
    score = classification.get("cvss-score")
    if isinstance(score, int | float) and not isinstance(score, bool) and 0 <= score <= 10:
        details["cvss_score"] = score
    description = text(info.get("description"), 1000)
    if description:
        details["description"] = description
    return {k: v for k, v in details.items() if v}


def _excerpt(data: Mapping[str, Any]) -> str:
    parts = [f"matched-at: {text(data.get('matched-at'), 1000)}"]
    matcher = text(data.get("matcher-name"), 200)
    if matcher:
        parts.append(f"matcher: {matcher}")
    extracted = _list(data.get("extracted-results"))
    if extracted:
        parts.append("extracted: " + ", ".join(extracted))
    curl = text(data.get("curl-command"), 2000)
    if curl:
        parts.append(f"request: {curl}")
    return "\n".join(parts)[:MAX_EXCERPT]


def parse(
    output: bytes, params: Mapping[str, Any], *, resolutions: Resolutions = NO_RESOLUTIONS
) -> Parsed:
    from quiver.worker.tracks.external.tools import NUCLEI_SCAN, _root_url  # avoid a cycle

    allowed = BoundInput(NUCLEI_SCAN, params, resolutions)
    root, host, is_name = _root_url(params)  # ValueError for bad params: a bug
    default_port = urlsplit(root).port

    entities: dict[str, Observed] = {}
    links: list[Link] = []
    linked: set[str] = set()
    findings: dict[tuple[str, str, str], FindingIn] = {}
    skipped = 0
    capped = False
    by_severity: dict[str, int] = {}
    domain_entity = Observed("domain", {"name": host}) if is_name else None
    for line in lines(output):
        data = line.data
        if data is None:
            if line.text.startswith("{"):
                skipped += 1
            continue
        template = text(data.get("template-id"), 200)
        address = ip(data.get("ip") or data.get("host"))
        if (
            not template
            or "|" in template
            or data.get("type") != "http"
            or address is None
            or address not in allowed
        ):
            skipped += 1
            continue
        url = _endpoint_url(data.get("matched-at"), host, default_port)
        number = port(data.get("port")) or default_port
        if url is None:
            skipped += 1
            continue
        if len(findings) >= MAX_FINDINGS or len(entities) + 3 > MAX_ENTITIES:
            capped = True
            break

        info = _obj(data.get("info"))
        severity = info.get("severity") if info.get("severity") in _SEVERITIES else "info"
        endpoint = entities.setdefault(f"web:{url}", Observed("web_endpoint", {"url": url}))
        service_key = f"svc:{address}:{number}"
        if service_key not in entities:
            service = Observed("service", {"ip": address, "port": number, "protocol": "tcp"})
            entities[service_key] = service
        if url not in linked:  # one serves/on_domain pair per endpoint
            linked.add(url)
            links.append(Link("serves", entities[service_key], endpoint))
            if domain_entity is not None:
                entities.setdefault(f"domain:{host}", domain_entity)
                links.append(Link("on_domain", endpoint, domain_entity))
        location = text(data.get("matcher-name"), 200) or ""
        finding = FindingIn(
            issue_type=template,
            entity=endpoint,
            title=text(info.get("name"), 200) or template,
            severity=severity,
            location=location,
            details=_details(info, data),
            evidence=(EvidenceIn(_excerpt(data)),),
        )
        identity = (template, url, location)
        if identity not in findings:
            by_severity[severity] = by_severity.get(severity, 0) + 1
        findings[identity] = finding  # the last sighting of the same match wins

    return Parsed(
        entities=tuple(entities.values()),
        links=tuple(links),
        findings=tuple(findings.values()),
        skipped=skipped,
        capped=capped,
        notes={"matches": len(findings), "by_severity": by_severity},
    )
