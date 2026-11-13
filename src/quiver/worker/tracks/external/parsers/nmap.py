"""port_scan (nmap -sT -oX -): an XML report on standard output.

    <host><status state="up"/><address addr="203.0.113.10" addrtype="ipv4"/>
      <ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.27.5"><cpe>cpe:/a:...</cpe></service>
      </port></ports></host>
    <runstats><finished exit="success"/><hosts up="2" down="0" total="2"/></runstats>

The executor merges stderr into the same file, and the output cap or a timeout can cut the
report anywhere, so the document is not parsed as a whole: each complete `<host>` element is
cut out and parsed on its own (nmap escapes `<` in banners, so `</host>` cannot appear inside
one). A partial last host is dropped; a document with an entity declaration is refused
outright (nmap never writes one), and without a DTD no entity can be expanded.

Only addresses the job was given (the bound input: pinned addresses and the job's IP and
network targets) are kept. Each becomes a `host`, each **open** TCP port a `service` linked by
`exposes`, and each hostname whose pinned addresses include it a `domain` linked by
`resolves_to`. Banner fields (product, version, extra info) are target-controlled data.
"""

import ipaddress
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Mapping
from typing import Any

from quiver.core.graph.record import Link, Observed
from quiver.core.policy.tools import BindError, bind_targets
from quiver.worker.tracks.external.parsers.common import (
    MAX_ENTITIES,
    NO_RESOLUTIONS,
    Parsed,
    Resolutions,
    ip,
)

MAX_HOST_BLOCK = 1024 * 1024  # one host's XML; larger is not nmap's
MAX_FIELD = 200  # banner strings
MAX_CPES = 10
_HOST = re.compile(rb"<host\b[^>]*>.*?</host>", re.DOTALL)
_FINISHED = re.compile(rb'<finished\b[^>]*\bexit="([a-z]{1,20})"')
_SERVICE_FIELDS = ("name", "product", "version", "extrainfo", "tunnel", "ostype")


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:MAX_FIELD] if value else None


def _host_elements(output: bytes) -> Iterator[ET.Element | None]:
    """Each complete <host> element, or None for one that does not parse."""
    for match in _HOST.finditer(output):
        block = match.group(0)
        if len(block) > MAX_HOST_BLOCK:
            yield None
            continue
        try:
            # A fragment without a DTD: undefined entities are errors, nothing is expanded or
            # fetched, and the size is capped above.
            yield ET.fromstring(block)  # noqa: S314
        except ET.ParseError:
            yield None


class _Allowed:
    """The addresses the job was given: what a result may be about."""

    def __init__(self, params: Mapping[str, Any], resolutions: Resolutions):
        from quiver.worker.tracks.external.tools import PORT_SCAN  # tools imports parsers

        self.names: dict[str, set[str]] = {}  # address -> hostnames pinned to it
        lines = PORT_SCAN.stdin_for(params)
        version = PORT_SCAN.bind_stdin(params)
        hostnames = [line for line in lines if not _is_network(line)]
        try:
            bound = bind_targets(lines, resolutions, version=version).lines
        except BindError:  # unknown pins: keep only the job's own IP and network targets
            bound = tuple(line for line in lines if _is_network(line))
        self.networks = [ipaddress.ip_network(line) for line in bound]
        for name in hostnames:
            for address in resolutions.get(name, ()):
                canonical = ip(address)
                if canonical:
                    self.names.setdefault(canonical, set()).add(name)

    def __contains__(self, address: str) -> bool:
        addr = ipaddress.ip_address(address)
        return any(addr in net for net in self.networks)


def _is_network(line: str) -> bool:
    try:
        ipaddress.ip_network(line)
    except ValueError:
        return False
    return True


def parse(
    output: bytes, params: Mapping[str, Any], *, resolutions: Resolutions = NO_RESOLUTIONS
) -> Parsed:
    allowed = _Allowed(params, resolutions)  # a ValueError here is a bug (bad job params)
    if b"<!ENTITY" in output:
        return Parsed(skipped=1, notes={"refused": "entity declaration in the report"})

    entities: dict[str, Observed] = {}
    links: list[Link] = []
    skipped = 0
    capped = False
    counts = {"hosts_up": 0, "hosts_down": 0, "open": 0, "closed": 0, "filtered": 0}
    for host in _host_elements(output):
        if host is None:
            skipped += 1
            continue
        address = next(
            (
                ip(a.get("addr"))
                for a in host.findall("address")
                if a.get("addrtype") in ("ipv4", "ipv6")
            ),
            None,
        )
        if address is None or address not in allowed:
            skipped += 1
            continue
        status = host.find("status")
        state = _text(status.get("state")) if status is not None else None
        counts["hosts_up" if state == "up" else "hosts_down"] += 1

        services = []
        for port in host.iter("port"):
            port_state = port.find("state")
            pstate = _text(port_state.get("state")) if port_state is not None else None
            if pstate in ("closed",):
                counts["closed"] += 1
            elif pstate is not None and "filtered" in pstate:
                counts["filtered"] += 1
            if pstate != "open":
                continue
            try:
                number = int(port.get("portid", ""))
            except ValueError:
                skipped += 1
                continue
            if port.get("protocol") != "tcp" or not 1 <= number <= 65535:
                skipped += 1
                continue
            counts["open"] += 1
            attrs: dict[str, Any] = {"ip": address, "port": number, "protocol": "tcp"}
            attrs["state"] = "open"
            reason = _text(port_state.get("reason")) if port_state is not None else None
            if reason:
                attrs["reason"] = reason
            service = port.find("service")
            if service is not None:
                for field in _SERVICE_FIELDS:
                    value = _text(service.get(field))
                    if value:
                        attrs[field] = value
                cpes = [c for c in (_text(e.text) for e in service.findall("cpe")) if c]
                if cpes:
                    attrs["cpe"] = list(dict.fromkeys(cpes))[:MAX_CPES]
            services.append(Observed("service", attrs))

        names = sorted(allowed.names.get(address, ()))
        if len(entities) + 1 + len(services) + len(names) > MAX_ENTITIES:
            capped = True
            break
        host_entity = Observed("host", {"ip": address, "nmap_state": state or "unknown"})
        entities[f"host:{address}"] = host_entity
        for svc in services:
            entities[f"svc:{address}:{svc.attributes['port']}"] = svc
            links.append(Link("exposes", host_entity, svc))
        for name in names:
            dom = entities.setdefault(f"domain:{name}", Observed("domain", {"name": name}))
            links.append(Link("resolves_to", dom, host_entity))

    finished = _FINISHED.search(output)
    notes: dict[str, Any] = {
        **counts,
        "finished": finished.group(1).decode() if finished else None,
    }
    return Parsed(
        entities=tuple(entities.values()),
        links=tuple(links),
        skipped=skipped,
        capped=capped,
        notes=notes,
    )
