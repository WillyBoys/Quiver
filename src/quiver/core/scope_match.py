"""Scope matching: is a target inside an engagement's scope? (Blueprint §4.1)

`Scope` is built once from an engagement's active scope entries; `Scope.check(target)` returns
a `ScopeDecision`. This module is pure: no DNS, no I/O. Whether a hostname's *addresses* are
acceptable (third-party hosting, pinning) is decided by the policy gate on top of this.

Every ambiguity resolves toward less testing:
- Exclusions always win, and any overlap with an exclusion counts (a CIDR sweep or crawl that
  would touch an excluded address or path is excluded as a whole).
- Includes are matched strictly; exclusions are matched loosely (an excluded hostname also
  covers its subdomains; excluded URL paths match case-insensitively, ignore ;params and
  repeated slashes, and apply to every scheme and port on that host).
- A target that cannot be read with confidence is UNCERTAIN, and the gate asks the operator.

Decisions made by the operator (2026-10-29): wildcards cover any depth below the base domain
(never the base itself); URL entries cover only web requests under that URL, not host-level
actions such as port scans.
"""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

import idna

from quiver.core.scope import ScopeKind, ScopeMode

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeResult(StrEnum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"  # no include entry covers it
    EXCLUDED = "excluded"  # an exclude entry covers or overlaps it
    UNCERTAIN = "uncertain"  # the target cannot be interpreted with confidence


@dataclass(frozen=True)
class ScopeRule:
    """One active scope entry, already normalized by quiver.core.scope."""

    kind: ScopeKind
    value: str
    mode: ScopeMode
    id: Any = None

    @classmethod
    def from_entry(cls, entry) -> "ScopeRule":
        return cls(ScopeKind(entry.kind), entry.value, ScopeMode(entry.mode), entry.id)


@dataclass(frozen=True)
class ScopeDecision:
    result: ScopeResult
    reason: str
    rule: ScopeRule | None = None  # the entry that decided it, when there is a single one

    @property
    def in_scope(self) -> bool:
        return self.result is ScopeResult.IN_SCOPE


class _Uncertain(Exception):
    pass


# --- parsed forms -----------------------------------------------------------------------------


@dataclass(frozen=True)
class _Url:
    scheme: str
    host: str | IPAddress
    port: int
    path: str  # canonical: dot segments resolved, unreserved escapes decoded


_DEFAULT_PORTS = {"http": 80, "https": 443}
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
# Labels that some resolvers and HTTP clients interpret as (parts of) an IP address,
# e.g. 2130706433, 0x7f.1, 017700000001.
_NUMERIC_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")
_PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
# Still-encoded characters that servers may decode into separators or traversal.
_RISKY_ESCAPES = ("%2F", "%5C", "%25")


def _ip(value: str) -> IPAddress | None:
    if "%" in value:
        raise _Uncertain("IPv6 zone identifiers are not supported in targets")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped  # ::ffff:203.0.113.5 is 203.0.113.5
    return ip


def _hostname(value: str) -> str:
    """Normalize a target hostname. Unlike scope entries, single-label names are accepted
    (they simply never match anything); anything ambiguous is UNCERTAIN."""
    host = value.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise _Uncertain("empty hostname")
    labels = host.split(".")
    if all(_NUMERIC_LABEL_RE.match(label) for label in labels) or labels[-1].isdigit():
        raise _Uncertain(f"{value} may be interpreted as an IP address in a non-standard form")
    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise _Uncertain(f"{value} is not a valid hostname: {exc}") from exc
    labels = ascii_host.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise _Uncertain(f"{value} is not a valid hostname")
    if all(_NUMERIC_LABEL_RE.match(label) for label in labels):
        raise _Uncertain(f"{value} may be interpreted as an IP address in a non-standard form")
    return ascii_host


def _canonical_path(path: str) -> str:
    if "\\" in path:
        raise _Uncertain("backslashes in URL paths are interpreted differently by servers")
    if not path.startswith("/"):
        path = "/" + path

    def decode(m: re.Match) -> str:
        char = chr(int(m.group(1), 16))
        return char if char in _UNRESERVED else f"%{m.group(1).upper()}"

    path = _PCT_RE.sub(decode, path)
    if any(esc in path for esc in _RISKY_ESCAPES):
        raise _Uncertain("encoded '/', '\\' or '%' in the URL path may be decoded by the server")

    out: list[str] = []
    segments = path.split("/")[1:]
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        if seg == "..":
            if out:
                out.pop()
            if last:
                out.append("")
        elif seg == ".":
            if last:
                out.append("")
        else:
            out.append(seg)
    return "/" + "/".join(out)


def _parse_url(value: str) -> _Url:
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise _Uncertain(f"{value} is not a valid URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise _Uncertain(f"unsupported URL scheme {scheme!r}")
    if parts.username is not None or parts.password is not None:
        raise _Uncertain("URL contains credentials (user@host), which can disguise the real host")
    if not parts.hostname:
        raise _Uncertain(f"{value} has no host")
    if port == 0:
        raise _Uncertain("port 0 is not a valid target port")
    raw_host = parts.hostname
    host: str | IPAddress
    ip = _ip(raw_host)
    host = ip if ip is not None else _hostname(raw_host)
    return _Url(scheme, host, port or _DEFAULT_PORTS[scheme], _canonical_path(parts.path))


def _path_within(path: str, prefix: str) -> bool:
    """Is `path` equal to or below `prefix`, at a segment boundary?"""
    prefix = prefix.rstrip("/")
    if not prefix:  # root covers everything
        return True
    return path == prefix or path.startswith(prefix + "/")


def _loose_path(path: str) -> str:
    """Lenient form for exclusion matching: case-insensitive, no ;params, no empty segments."""
    segments = [seg.split(";", 1)[0] for seg in path.lower().split("/")]
    return "/" + "/".join(s for s in segments if s)


def _host_text(host: str | IPAddress) -> str:
    return host if isinstance(host, str) else str(host)


# --- scope --------------------------------------------------------------------------------------


class Scope:
    def __init__(self, rules: Iterable[ScopeRule]):
        self._nets: dict[ScopeMode, list[tuple[IPNetwork, ScopeRule]]] = {m: [] for m in ScopeMode}
        self._hosts: dict[ScopeMode, dict[str, ScopeRule]] = {m: {} for m in ScopeMode}
        self._wildcards: dict[ScopeMode, dict[str, ScopeRule]] = {m: {} for m in ScopeMode}
        self._urls: dict[ScopeMode, list[tuple[_Url, ScopeRule]]] = {m: [] for m in ScopeMode}

        for rule in rules:
            # Stored entries are already normalized; a value that does not parse here means
            # corrupted scope, and failing loudly (the gate then denies) is the safe outcome.
            try:
                self._add(rule)
            except (_Uncertain, ValueError) as exc:
                raise ValueError(f"invalid scope entry {rule.value!r}: {exc}") from exc

        self._include_collapsed = {
            version: list(
                ipaddress.collapse_addresses(
                    net for net, _ in self._nets[ScopeMode.INCLUDE] if net.version == version
                )
            )
            for version in (4, 6)
        }

    @classmethod
    def from_entries(cls, entries: Iterable[Any]) -> "Scope":
        return cls(ScopeRule.from_entry(e) for e in entries)

    def _add(self, rule: ScopeRule) -> None:
        if rule.kind in (ScopeKind.IP, ScopeKind.CIDR):
            self._nets[rule.mode].append((ipaddress.ip_network(rule.value), rule))
        elif rule.kind is ScopeKind.HOSTNAME:
            self._hosts[rule.mode][rule.value] = rule
        elif rule.kind is ScopeKind.WILDCARD:
            self._wildcards[rule.mode][rule.value.removeprefix("*.")] = rule
        elif rule.kind is ScopeKind.URL:
            self._urls[rule.mode].append((_parse_url(rule.value), rule))

    # --- public API ---------------------------------------------------------------------

    def check(self, target: str, *, url_subtree: bool = False) -> ScopeDecision:
        """Decide whether `target` is in scope.

        target: an IP, a CIDR (every address in it), a hostname, or an http(s) URL.
        url_subtree: for URL targets, whether the action reaches everything below the URL
            (crawlers, content discovery) rather than that single request.
        """
        try:
            return self._check(target, url_subtree)
        except _Uncertain as exc:
            return ScopeDecision(ScopeResult.UNCERTAIN, str(exc))

    def _check(self, target: str, url_subtree: bool) -> ScopeDecision:
        value = target.strip()
        if not value:
            raise _Uncertain("empty target")
        if any(c.isspace() or not c.isprintable() for c in value):
            raise _Uncertain("target contains spaces or control characters")

        if value.lower().startswith(("http://", "https://")):
            return self._check_url(_parse_url(value), url_subtree)
        if "://" in value:
            raise _Uncertain(f"unsupported target scheme in {value!r}")
        if "*" in value:
            raise _Uncertain("targets must be concrete; wildcards are only valid in scope entries")
        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise _Uncertain(f"{value} is neither an IP network nor a URL") from exc
            if net.num_addresses == 1:
                return self._check_ip(net.network_address)
            return self._check_network(net)

        ip = _ip(value)
        if ip is not None:
            return self._check_ip(ip)
        return self._check_host(_hostname(value))

    # --- IPs and networks -------------------------------------------------------------------

    def _check_ip(self, ip: IPAddress) -> ScopeDecision:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        excluded = self._host_level_url_exclusion(ip)
        if excluded:
            return excluded
        for net, rule in self._nets[ScopeMode.EXCLUDE]:
            if ip.version == net.version and ip in net:
                return ScopeDecision(
                    ScopeResult.EXCLUDED, f"{ip} is excluded by {rule.value}", rule
                )
        for net, rule in self._nets[ScopeMode.INCLUDE]:
            if ip.version == net.version and ip in net:
                return ScopeDecision(ScopeResult.IN_SCOPE, f"{ip} is covered by {rule.value}", rule)
        return ScopeDecision(ScopeResult.OUT_OF_SCOPE, f"{ip} is not covered by any include entry")

    def _check_network(self, net: IPNetwork) -> ScopeDecision:
        for excl, rule in self._nets[ScopeMode.EXCLUDE]:
            if net.version == excl.version and net.overlaps(excl):
                return ScopeDecision(
                    ScopeResult.EXCLUDED, f"{net} overlaps excluded range {rule.value}", rule
                )
        for url, rule in self._urls[ScopeMode.EXCLUDE]:
            if (
                not isinstance(url.host, str)
                and url.host.version == net.version
                and url.host in net
                and _loose_path(url.path) == "/"
            ):
                return ScopeDecision(
                    ScopeResult.UNCERTAIN,
                    f"{net} contains {url.host}, whose web root is excluded ({rule.value})",
                    rule,
                )
        for incl, rule in self._nets[ScopeMode.INCLUDE]:
            if net.version == incl.version and net.subnet_of(incl):
                return ScopeDecision(
                    ScopeResult.IN_SCOPE, f"{net} is covered by {rule.value}", rule
                )
        if any(net.subnet_of(c) for c in self._include_collapsed[net.version]):
            return ScopeDecision(
                ScopeResult.IN_SCOPE, f"{net} is covered by several adjacent include entries"
            )
        return ScopeDecision(
            ScopeResult.OUT_OF_SCOPE, f"{net} is not entirely covered by include entries"
        )

    # --- hostnames --------------------------------------------------------------------------

    def _host_exclusion(self, host: str) -> ScopeDecision | None:
        for excluded, rule in self._hosts[ScopeMode.EXCLUDE].items():
            if host == excluded or host.endswith("." + excluded):
                return ScopeDecision(
                    ScopeResult.EXCLUDED, f"{host} is excluded by {excluded}", rule
                )
        for base, rule in self._wildcards[ScopeMode.EXCLUDE].items():
            if host.endswith("." + base):
                return ScopeDecision(ScopeResult.EXCLUDED, f"{host} is excluded by *.{base}", rule)
        return None

    def _host_inclusion(self, host: str) -> ScopeDecision | None:
        rule = self._hosts[ScopeMode.INCLUDE].get(host)
        if rule is not None:
            return ScopeDecision(ScopeResult.IN_SCOPE, f"{host} is in scope", rule)
        # Longest matching base first, so the reported rule is the most specific one.
        for base, rule in sorted(
            self._wildcards[ScopeMode.INCLUDE].items(), key=lambda kv: -len(kv[0])
        ):
            if host.endswith("." + base):
                return ScopeDecision(ScopeResult.IN_SCOPE, f"{host} is covered by *.{base}", rule)
        return None

    def _host_level_url_exclusion(self, host: str | IPAddress) -> ScopeDecision | None:
        """Host-level actions on a host whose entire web root is excluded are uncertain:
        they may well touch the excluded web application."""
        for url, rule in self._urls[ScopeMode.EXCLUDE]:
            if _host_text(url.host) == _host_text(host) and _loose_path(url.path) == "/":
                return ScopeDecision(
                    ScopeResult.UNCERTAIN,
                    f"the web root of {_host_text(host)} is excluded ({rule.value}); "
                    "host-level testing may touch it",
                    rule,
                )
        return None

    def _check_host(self, host: str) -> ScopeDecision:
        excluded = self._host_exclusion(host)
        if excluded:
            return excluded
        uncertain = self._host_level_url_exclusion(host)
        if uncertain:
            return uncertain
        included = self._host_inclusion(host)
        if included:
            return included
        if any(_host_text(u.host) == host for u, _ in self._urls[ScopeMode.INCLUDE]):
            return ScopeDecision(
                ScopeResult.OUT_OF_SCOPE,
                f"only specific URLs on {host} are in scope, not host-level actions",
            )
        return ScopeDecision(
            ScopeResult.OUT_OF_SCOPE, f"{host} is not covered by any include entry"
        )

    # --- URLs -------------------------------------------------------------------------------

    def _check_url(self, url: _Url, subtree: bool) -> ScopeDecision:
        host_text = _host_text(url.host)

        # Host-level exclusions apply to every URL on the host.
        if isinstance(url.host, str):
            excluded = self._host_exclusion(url.host)
        else:
            excluded = next(
                (
                    ScopeDecision(ScopeResult.EXCLUDED, f"{url.host} is excluded by {r.value}", r)
                    for net, r in self._nets[ScopeMode.EXCLUDE]
                    if url.host.version == net.version and url.host in net
                ),
                None,
            )
        if excluded:
            return excluded

        # URL exclusions: any scheme or port on the same host; loose path comparison; for a
        # subtree target, an excluded path anywhere below it also counts.
        target_loose = _loose_path(url.path)
        for excl, rule in self._urls[ScopeMode.EXCLUDE]:
            if _host_text(excl.host) != host_text:
                continue
            excl_loose = _loose_path(excl.path)
            if _path_within(target_loose, excl_loose) or (
                subtree and _path_within(excl_loose, target_loose)
            ):
                return ScopeDecision(
                    ScopeResult.EXCLUDED,
                    f"{url.path} on {host_text} is excluded by {rule.value}",
                    rule,
                )

        # Host-level inclusion covers every URL on the host, on any port.
        if isinstance(url.host, str):
            included = self._host_inclusion(url.host)
            if included:
                return included
        else:
            decision = self._check_ip(url.host)
            if decision.in_scope:
                return decision

        # URL inclusion: same scheme, host and port; path within the entry's prefix (strict).
        for incl, rule in self._urls[ScopeMode.INCLUDE]:
            if (incl.scheme, _host_text(incl.host), incl.port) != (url.scheme, host_text, url.port):
                continue
            if _path_within(url.path, incl.path):
                return ScopeDecision(
                    ScopeResult.IN_SCOPE, f"{url.path} is within {rule.value}", rule
                )
        if subtree and any(
            (i.scheme, _host_text(i.host), i.port) == (url.scheme, host_text, url.port)
            and _path_within(i.path, url.path)
            for i, _ in self._urls[ScopeMode.INCLUDE]
        ):
            return ScopeDecision(
                ScopeResult.OUT_OF_SCOPE,
                f"only part of {url.path} on {host_text} is in scope; narrow the target",
            )
        return ScopeDecision(
            ScopeResult.OUT_OF_SCOPE,
            f"{url.scheme}://{host_text}:{url.port}{url.path} is not in scope",
        )
