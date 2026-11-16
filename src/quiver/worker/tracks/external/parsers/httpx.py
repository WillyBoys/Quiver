"""http_probe (httpx -json -td -tls-grab): one JSON object per port that answered HTTP(S).

    {"url": "https://203.0.113.10:443", "host": "203.0.113.10", "port": "443",
     "scheme": "https", "status_code": 200, "title": "...", "webserver": "nginx/1.27.5",
     "tech": ["Nginx:1.27.5", "WordPress:6.4.2"], "location": "...", "sni": "www.example.com",
     "tls": {"fingerprint_hash": {"sha256": "..."}, "tls_version": "tls13", ...}}

The job probes one host: httpx connected to the pinned addresses on its input and sent the
job's hostname as Host header and SNI. So each answer becomes a `web_endpoint` under that
hostname (`https://www.example.com/`, or the IP when the job's host is an address), served by
the `service` it was reached on and linked to the `domain` by `on_domain`. Title, server,
technologies and the redirect location are target-controlled data. Redirects are never
followed: the host of an absolute `Location` that differs from the probed host is recorded as
a `domain` (or `host`) entity, so the graph's scope check suggests it when it is out of scope.
"""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

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

MAX_TECH = 50
MAX_LOCATION = 1000


def _fingerprint(value: Any) -> str | None:
    try:
        return keys.canonical_fingerprint(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _redirect_target(location: str | None, probed: str) -> Observed | None:
    """The other host an absolute redirect points to, as an entity, or None."""
    if not location:
        return None
    try:
        parts = urlsplit(location)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    name = domain(parts.hostname)
    if name is not None:
        return None if name == probed else Observed("domain", {"name": name})
    address = ip(parts.hostname)
    if address is not None and address != probed:
        return Observed("host", {"ip": address})
    return None


def parse(
    output: bytes, params: Mapping[str, Any], *, resolutions: Resolutions = NO_RESOLUTIONS
) -> Parsed:
    from quiver.worker.tracks.external.tools import HTTP_PROBE, _probe_host  # avoid a cycle

    allowed = BoundInput(HTTP_PROBE, params, resolutions)
    probed, is_name = _probe_host(params)  # ValueError for bad params: a bug

    entities: dict[str, Observed] = {}
    links: list[Link] = []
    skipped = failed = 0
    capped = False
    redirects: set[str] = set()
    probed_domain = Observed("domain", {"name": probed}) if is_name else None

    for line in lines(output):
        data = line.data
        if data is None:
            if line.text.startswith("{"):
                skipped += 1  # cut off by the output cap
            continue
        if data.get("failed") is True:
            failed += 1
            continue
        address = ip(data.get("host_ip") or data.get("host"))
        number = port(data.get("port"))
        scheme = data.get("scheme")
        if address is None or address not in allowed or number is None:
            skipped += 1
            continue
        if scheme not in ("http", "https"):
            skipped += 1
            continue
        try:
            url = keys.canonical_url(f"{scheme}://{_url_host(probed)}:{number}/")
        except ValueError:
            skipped += 1
            continue
        if len(entities) + 4 > MAX_ENTITIES:
            capped = True
            break

        attrs: dict[str, Any] = {"url": url, "ip": address}
        status = data.get("status_code")
        if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 999:
            attrs["status_code"] = status
        for src, dst in (
            ("title", "title"),
            ("webserver", "webserver"),
            ("content_type", "content_type"),
        ):
            value = text(data.get(src))
            if value:
                attrs[dst] = value
        tech = strings(data.get("tech", []), limit=MAX_TECH, max_len=100)
        if tech:
            attrs["tech"] = sorted(tech)
        location = text(data.get("location"), MAX_LOCATION)
        if location:
            attrs["location"] = location
        tls = data.get("tls") if isinstance(data.get("tls"), dict) else {}
        hashes = (
            tls.get("fingerprint_hash") if isinstance(tls.get("fingerprint_hash"), dict) else {}
        )
        sha256 = _fingerprint(hashes.get("sha256"))
        if sha256:
            attrs["tls_sha256"] = sha256
        tls_version = text(tls.get("tls_version"), 20)
        if tls_version:
            attrs["tls_version"] = tls_version

        endpoint = Observed("web_endpoint", attrs)
        service = Observed("service", {"ip": address, "port": number, "protocol": "tcp"})
        entities[f"web:{url}"] = endpoint
        entities.setdefault(f"svc:{address}:{number}", service)
        links.append(Link("serves", service, endpoint))
        if probed_domain is not None:
            entities.setdefault(f"domain:{probed}", probed_domain)
            links.append(Link("on_domain", endpoint, probed_domain))
        target = _redirect_target(location, probed)
        if target is not None:
            key = f"{target.type}:{target.attributes.get('name') or target.attributes['ip']}"
            entities.setdefault(key, target)
            redirects.add(key.split(":", 1)[1])

    return Parsed(
        entities=tuple(entities.values()),
        links=tuple(links),
        skipped=skipped,
        capped=capped,
        notes={
            "endpoints": sum(1 for e in entities.values() if e.type == "web_endpoint"),
            "failed": failed,
            "redirects_to": sorted(redirects),
        },
    )


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host
