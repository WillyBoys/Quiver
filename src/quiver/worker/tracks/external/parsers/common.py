"""Shared helpers for parsers. Parsers are pure functions from a job's raw output (and the
parameters the worker built it from) to graph records (Blueprint §6).

Tool output is target-controlled and untrusted. A parser never raises because of what is in
the output: lines it cannot use are counted as skipped. Every item it returns is already
validated against the graph types, so one bad line can never make `record()` (which is
all-or-nothing) reject the whole job. Only a bug in the parser itself raises.
"""

import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from quiver.core.graph import keys
from quiver.core.graph.record import FindingIn, Link, Observed

# The addresses the gate pinned for each hostname in the job's last decision (Job.resolutions):
# what a tool with bound targets was actually given. Passive tools ignore them.
Resolutions = Mapping[str, Sequence[str]]
NO_RESOLUTIONS: Resolutions = MappingProxyType({})

# Lines longer than this are not tool results we can use.
MAX_LINE = 64 * 1024
# Most entities one job may record. More is either a runaway tool or a hostile target.
MAX_ENTITIES = 50_000


@dataclass(frozen=True)
class Parsed:
    entities: tuple[Observed, ...] = ()
    links: tuple[Link, ...] = ()
    findings: tuple[FindingIn, ...] = ()
    skipped: int = 0  # output lines or items that could not be used
    capped: bool = False  # more results than MAX_ENTITIES; the rest were dropped
    # What the tool reported about itself (source errors, unresolved names), for the event.
    notes: Mapping[str, Any] = field(default_factory=dict)


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
