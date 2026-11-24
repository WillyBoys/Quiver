"""Shared helpers for parsers. Parsers are pure functions from a job's raw output (and the
parameters the worker built it from) to graph records (Blueprint §6).

Tool output is target-controlled and untrusted. A parser never raises because of what is in
the output: lines it cannot use are counted as skipped. Every item it returns is already
validated against the graph types, so one bad line can never make `record()` (which is
all-or-nothing) reject the whole job. Only a bug in the parser itself raises.
"""

import ipaddress
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from quiver.core.graph import keys
from quiver.core.graph.record import FindingIn, Link, Observed
from quiver.core.policy.tools import BindError, ToolSpec, bind_targets

# The addresses the gate pinned for each hostname in the job's last decision (Job.resolutions):
# what a tool with bound targets was actually given. Passive tools ignore them.
Resolutions = Mapping[str, Sequence[str]]
NO_RESOLUTIONS: Resolutions = MappingProxyType({})

# Lines longer than this are not tool results we can use.
MAX_LINE = 64 * 1024
# Most entities one job may record. More is either a runaway tool or a hostile target.
MAX_ENTITIES = 50_000


@dataclass(frozen=True)
class FollowUp:
    """A job a parser asks for next (content discovery recursion). The worker enqueues it like
    any other job, so the gate judges it on its own."""

    tool: str
    params: Mapping[str, Any]


@dataclass(frozen=True)
class Parsed:
    entities: tuple[Observed, ...] = ()
    links: tuple[Link, ...] = ()
    findings: tuple[FindingIn, ...] = ()
    skipped: int = 0  # output lines or items that could not be used
    capped: bool = False  # more results than MAX_ENTITIES; the rest were dropped
    # What the tool reported about itself (source errors, unresolved names), for the event.
    notes: Mapping[str, Any] = field(default_factory=dict)
    follow_ups: tuple[FollowUp, ...] = ()


@dataclass(frozen=True)
class Line:
    text: str
    data: dict | None  # the JSON object on this line, if it is one


def lines(output: bytes) -> Iterator[Line]:
    """Every non-empty line of output. JSON objects are decoded; other lines (banners, log
    messages, a line cut off by the output cap) come back as text with data None."""
    for raw in output.decode("utf-8", errors="replace").splitlines():
        text = raw.strip()
        if not text or len(text) > MAX_LINE:
            continue
        data = None
        if text.startswith("{"):
            try:
                value = json.loads(text)
            except ValueError:
                value = None
            data = value if isinstance(value, dict) else None
        yield Line(text, data)


def domain(value: Any) -> str | None:
    """The canonical form of a domain name, or None if it is not one."""
    if not isinstance(value, str):
        return None
    try:
        return keys.canonical_domain(value)
    except ValueError:
        return None


def ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return keys.canonical_ip(value)
    except ValueError:
        return None


def under(name: str, base: str) -> bool:
    """`name` is `base` or a name below it (label boundary, so badexample.com is not)."""
    return name == base or name.endswith("." + base)


def strings(value: Any, *, limit: int, max_len: int = 255) -> list[str] | None:
    """A list of short strings, deduplicated in order and capped, or None if `value` is not
    a list of strings."""
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        return None
    return list(dict.fromkeys(v for v in value if 0 < len(v) <= max_len))[:limit]


class BoundInput:
    """What a tool with bound targets was given (Blueprint §4.1): the pinned addresses of its
    hostnames plus its own IP and network targets. A result about any other address is not
    about this job and is skipped. `names` maps each pinned address to its hostnames.

    Recomputed from the job's parameters and the decision's resolutions, exactly as the
    worker bound them at dispatch. If a name's pins are unknown, only the job's own IP and
    network targets count."""

    def __init__(self, spec: ToolSpec, params: Mapping[str, Any], resolutions: Resolutions):
        lines = spec.stdin_for(params)  # ValueError for bad params: a bug, not bad output
        version = spec.bind_stdin(params) if spec.bind_stdin else None
        hostnames = [line for line in lines if not _is_network(line)]
        try:
            bound = bind_targets(lines, resolutions, version=version).lines
        except BindError:
            bound = tuple(line for line in lines if _is_network(line))
        self.networks = [ipaddress.ip_network(line) for line in bound]
        self.names: dict[str, set[str]] = {}
        for name in hostnames:
            for address in resolutions.get(name, ()):
                canonical = ip(address)
                if canonical and canonical in self:
                    self.names.setdefault(canonical, set()).add(name)

    def __contains__(self, address: str) -> bool:
        try:
            addr = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)


def _is_network(line: str) -> bool:
    try:
        ipaddress.ip_network(line)
    except ValueError:
        return False
    return True


def port(value: Any) -> int | None:
    """A TCP port from tool output (a number or a numeric string), or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isdigit() and len(value) <= 5:
        value = int(value)
    return value if isinstance(value, int) and 1 <= value <= 65535 else None


def text(value: Any, limit: int = 200) -> str | None:
    """A short, stripped string from tool output, or None."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] if value else None


def redirect_target(location: str | None, probed: str) -> Observed | None:
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
