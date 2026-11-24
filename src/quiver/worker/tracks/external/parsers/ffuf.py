"""content_discovery (quiver-bind → ffuf -json): one JSON object per hit.

    {"input": {"FUZZ": "<base64>"}, "status": 301, "length": 169, "words": 5, "lines": 8,
     "content-type": "text/html", "redirectlocation": "http://www.example.com:8080/app/admin/",
     "url": "http://203.0.113.10:8080/app/admin", "host": "www.example.com", ...}

quiver-bind ran ffuf against the pinned addresses with the job's host as Host header and SNI,
so `url` names the address; each hit is rebuilt under the job's host as a `web_endpoint`,
served by its `service` and `on_domain` the host. Hits outside the job's base URL, about an
address the job was not given, or not plain HTTP results, are skipped. An absolute redirect to
another host records that host (the graph turns it into a scope suggestion when it is out of
scope). No findings: nuclei reports issues; this maps what exists.

Recursion: a hit that is a directory (a redirect to the same path + "/" on the same host, or
a path ending in "/") becomes a follow-up `content_discovery` job one level deeper when the
job asked for recursion and is above `max_depth`. ffuf's own recursion cannot see that a
redirect to the name is the address it requested.

Everything here is target-controlled.
"""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit

from quiver.core.graph import keys
from quiver.core.graph.record import Link, Observed
from quiver.worker.tracks.external.parsers.common import (
    MAX_ENTITIES,
    NO_RESOLUTIONS,
    BoundInput,
    FollowUp,
    Parsed,
    Resolutions,
    ip,
    lines,
    redirect_target,
    text,
)

MAX_FOLLOW_UPS = 20  # directories queued per job; the rest are listed in the notes only
MAX_LOCATION = 1000
_REDIRECTS = {301, 302, 303, 307, 308}
_DEFAULT_PORTS = {"http": 80, "https": 443}
# Parameters a follow-up job inherits from its parent.
_INHERITED = ("recursion", "max_depth", "rate", "max_minutes")


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**53:
        return None
    return value


def _same_place(a: str, b: str) -> bool:
    """Whether two absolute URLs name the same scheme, host, port and path."""
    try:
        x, y = urlsplit(a), urlsplit(b)
        px = x.port or _DEFAULT_PORTS.get(x.scheme)
        py = y.port or _DEFAULT_PORTS.get(y.scheme)
    except ValueError:
        return False
    return (x.scheme, (x.hostname or "").lower(), px, x.path) == (
        y.scheme,
        (y.hostname or "").lower(),
        py,
        y.path,
    )


def parse(
    output: bytes, params: Mapping[str, Any], *, resolutions: Resolutions = NO_RESOLUTIONS
) -> Parsed:
    # Imported here to avoid a cycle (tools imports the parsers' registry).
    from quiver.worker.tracks.external.tools import (
        CONTENT_DISCOVERY,
        _base_url,
        _recursion,
    )

    allowed = BoundInput(CONTENT_DISCOVERY, params, resolutions)
    base, host, is_name = _base_url(params)  # ValueError for bad params: a bug
    recursion, max_depth, depth = _recursion(params)
    base_parts = urlsplit(base)
    base_path = keys.canonical_path(base_parts.path)

    entities: dict[str, Observed] = {}
    links: list[Link] = []
    directories: dict[str, None] = {}
    redirects: set[str] = set()
    by_status: dict[str, int] = {}
    skipped = 0
    capped = False
    domain_entity = Observed("domain", {"name": host}) if is_name else None
    for line in lines(output):
        data = line.data
        if data is None:
            if line.text.startswith("{"):
                skipped += 1
            continue
        status = _count(data.get("status"))
        raw_url = data.get("url")
        if status is None or not 100 <= status <= 599 or not isinstance(raw_url, str):
            skipped += 1
            continue
        try:
            parts = urlsplit(raw_url)
            number = parts.port or _DEFAULT_PORTS.get(parts.scheme)
        except ValueError:
            skipped += 1
            continue
        address = ip(parts.hostname)
        if (
            address is None
            or address not in allowed
            or parts.scheme != base_parts.scheme
            or number != base_parts.port
            or parts.query
            or parts.fragment
        ):
            skipped += 1
            continue
        try:
            url = keys.canonical_url(f"{parts.scheme}://{_netloc(host)}:{number}{parts.path}")
        except ValueError:
            skipped += 1
            continue
        path = urlsplit(url).path
        if not path.startswith(base_path) or path == base_path:
            skipped += 1  # outside the base URL (or the base itself)
            continue
        if len(entities) + 3 > MAX_ENTITIES:
            capped = True
            break

        location = text(data.get("redirectlocation"), MAX_LOCATION)
        attributes: dict[str, Any] = {"url": url, "ip": address, "status_code": status}
        for field, name in (("length", "content_length"), ("words", "words"), ("lines", "lines")):
            value = _count(data.get(field))
            if value is not None:
                attributes[name] = value
        content_type = text(data.get("content-type"), 200)
        if content_type:
            attributes["content_type"] = content_type
        if location:
            attributes["location"] = location
        attributes["found_by"] = "content_discovery"
        endpoint = Observed("web_endpoint", attributes)
        if f"web:{url}" not in entities:
            by_status[str(status)] = by_status.get(str(status), 0) + 1
        entities[f"web:{url}"] = endpoint
        service_key = f"svc:{address}:{number}"
        service = entities.setdefault(
            service_key, Observed("service", {"ip": address, "port": number, "protocol": "tcp"})
        )
        links.append(Link("serves", service, endpoint))
        if domain_entity is not None:
            entities.setdefault(f"domain:{host}", domain_entity)
            links.append(Link("on_domain", endpoint, domain_entity))

        target = redirect_target(location, host)
        if target is not None and not (
            target.type == "host" and target.attributes["ip"] in allowed
        ):
            key = f"{target.type}:{target.attributes.get('name') or target.attributes['ip']}"
            entities.setdefault(key, target)
            redirects.add(key.split(":", 1)[1])

        directory = None
        if path.endswith("/") and status not in _REDIRECTS:
            directory = url
        elif status in _REDIRECTS and location:
            # Relative or absolute; on the job's host by name or by the bound address.
            target_url = urljoin(url, location)
            by_address = urljoin(raw_url, location)
            if _same_place(target_url, url + "/") or _same_place(by_address, raw_url + "/"):
                directory = url + "/"
        if directory is not None:
            directories[directory] = None

    follow_ups: list[FollowUp] = []
    if recursion and depth < max_depth:
        inherited = {k: params[k] for k in _INHERITED if k in params}
        for directory in sorted(directories)[:MAX_FOLLOW_UPS]:
            child = {**inherited, "url": directory, "depth": depth + 1}
            try:
                _base_url(child)  # a path the tool would refuse is not followed
            except ValueError:
                continue
            follow_ups.append(FollowUp("content_discovery", child))

    return Parsed(
        entities=tuple(entities.values()),
        links=tuple(links),
        skipped=skipped,
        capped=capped,
        notes={
            "hits": sum(by_status.values()),
            "by_status": by_status,
            "directories": len(directories),
            "follow_ups": len(follow_ups),
            "redirects_to": sorted(redirects),
        },
        follow_ups=tuple(follow_ups),
    )


def _netloc(host: str) -> str:
    return f"[{host}]" if ":" in host else host
