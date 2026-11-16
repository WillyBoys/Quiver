"""tls_scan (tlsx -json -sm ctls -ve -ce): one JSON object per port.

    {"ip": "203.0.113.10", "port": "443", "probe_status": true, "sni": "www.example.com",
     "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256",
     "fingerprint_hash": {"sha256": "..."}, "subject_cn": "...", "subject_an": [...],
     "issuer_dn": "...", "not_before": "...", "not_after": "...", "self_signed": true,
     "version_enum": ["tls13", "tls12"],
     "cipher_enum": [{"version": "tls12", "ciphers": {"weak": [...], "secure": [...]}}]}

Each answer becomes the `certificate` the service presented (identity: SHA-256 of the
certificate) and TLS facts on the `service` (negotiated version and cipher, the versions it
supports and its weak or insecure ciphers), linked by `presents`; the certificate `names` each
domain in its subject and SANs (a wildcard `*.x` names `x`). Names outside the engagement's
scope become scope suggestions through the graph. Failed handshakes (a port that does not
speak TLS) are counted, not recorded. tlsx's own `mismatched` flag compares the certificate
with the IP it connected to, not the SNI, so it is not recorded.
"""

import re
from collections.abc import Mapping
from typing import Any

from quiver.core.graph import keys
from quiver.core.graph.record import Link, Observed
from quiver.worker.tracks.external.parsers.common import (
    MAX_ENTITIES,
    NO_RESOLUTIONS,
    BoundInput,
    Parsed,
    Resolutions,
    domain,
    ip,
    lines,
    port,
    strings,
    text,
)

MAX_NAMES = 100  # SAN entries per certificate
MAX_CIPHERS = 50  # per strength
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
_VERSION = re.compile(r"^(ssl30|tls1[0-3])$")
_STRENGTHS = ("insecure", "weak", "secure")


def _obj(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _certificate(data: Mapping[str, Any]) -> Observed | None:
    try:
        sha256 = keys.canonical_fingerprint(_obj(data.get("fingerprint_hash")).get("sha256"))
    except (ValueError, TypeError, AttributeError):
        return None
    attrs: dict[str, Any] = {"sha256": sha256}
    for field in ("subject_cn", "subject_dn", "issuer_cn", "issuer_dn", "serial"):
        value = text(data.get(field), 500)
        if value:
            attrs[field] = value
    for field in ("not_before", "not_after"):
        value = data.get(field)
        if isinstance(value, str) and _TIMESTAMP.match(value):
            attrs[field] = value
    san = strings(data.get("subject_an", []), limit=MAX_NAMES)
    if san:
        attrs["san"] = san
    for flag in ("self_signed", "expired", "untrusted"):
        if data.get(flag) is True:
            attrs[flag] = True
    return Observed("certificate", attrs)


def _named_domains(cert: Observed) -> list[str]:
    names = [cert.attributes.get("subject_cn", ""), *cert.attributes.get("san", [])]
    out: dict[str, None] = {}
    for raw in names:
        name = domain(raw[2:] if raw.startswith("*.") else raw)
        if name is not None:
            out[name] = None
    return list(out)


def _ciphers(value: Any) -> dict[str, list[str]]:
    """Supported ciphers by strength, across TLS versions (insecure and weak first)."""
    found: dict[str, dict[str, None]] = {s: {} for s in _STRENGTHS}
    for entry in value if isinstance(value, list) else []:
        for strength, names in _obj(_obj(entry).get("ciphers")).items():
            if strength in found:
                for name in strings(names, limit=MAX_CIPHERS, max_len=100) or []:
                    found[strength][name] = None
    return {s: list(names)[:MAX_CIPHERS] for s, names in found.items() if names}


def parse(
    output: bytes, params: Mapping[str, Any], *, resolutions: Resolutions = NO_RESOLUTIONS
) -> Parsed:
    from quiver.worker.tracks.external.tools import TLS_SCAN  # tools imports parsers

    allowed = BoundInput(TLS_SCAN, params, resolutions)

    entities: dict[str, Observed] = {}
    links: list[Link] = []
    skipped = 0
    capped = False
    no_tls: list[int] = []
    for line in lines(output):
        data = line.data
        if data is None:
            if line.text.startswith("{"):
                skipped += 1
            continue
        address = ip(data.get("ip") or data.get("host"))
        number = port(data.get("port"))
        if address is None or address not in allowed or number is None:
            skipped += 1
            continue
        if data.get("probe_status") is not True:
            no_tls.append(number)
            continue
        cert = _certificate(data)
        if cert is None:
            skipped += 1
            continue
        named = _named_domains(cert)
        if len(entities) + 2 + len(named) > MAX_ENTITIES:
            capped = True
            break

        svc: dict[str, Any] = {"ip": address, "port": number, "protocol": "tcp"}
        version = data.get("tls_version")
        if isinstance(version, str) and _VERSION.match(version):
            svc["tls_version"] = version
        cipher = text(data.get("cipher"), 100)
        if cipher:
            svc["tls_cipher"] = cipher
        versions = [
            v for v in strings(data.get("version_enum", []), limit=6) or [] if _VERSION.match(v)
        ]
        if versions:
            svc["tls_versions"] = sorted(versions)
        ciphers = _ciphers(data.get("cipher_enum"))
        if ciphers:
            svc["tls_ciphers"] = ciphers
        service = Observed("service", svc)

        entities[f"svc:{address}:{number}"] = service
        entities.setdefault(f"cert:{cert.attributes['sha256']}", cert)
        links.append(Link("presents", service, cert))
        for name in named:
            dom = entities.setdefault(f"domain:{name}", Observed("domain", {"name": name}))
            links.append(Link("names", cert, dom))

    return Parsed(
        entities=tuple(entities.values()),
        links=tuple(links),
        skipped=skipped,
        capped=capped,
        notes={
            "certificates": sum(1 for e in entities.values() if e.type == "certificate"),
            "no_tls_ports": sorted(set(no_tls)),
        },
    )
