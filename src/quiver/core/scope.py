"""Scope entries: classification and normalization (Blueprint §4.1).

Every scope value the operator enters is classified (IP, CIDR, hostname, wildcard, URL) and
normalized to one canonical string, or rejected with a reason. Nothing is silently "fixed":
an ambiguous or dangerous entry is an error the operator must resolve.

Include entries are held to stricter rules than exclude entries, because an overly broad
exclude can only shrink scope, while an overly broad include widens it.

Matching targets against scope builds on these functions (build step 6).
"""

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

import idna
from publicsuffixlist import PublicSuffixList


class ScopeKind(StrEnum):
    IP = "ip"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    WILDCARD = "wildcard"
    URL = "url"


class ScopeMode(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class ScopeValueError(ValueError):
    """The value cannot be used as a scope entry. The message is shown to the operator."""


@dataclass(frozen=True)
class NormalizedScope:
    kind: ScopeKind
    value: str


# Widest networks an include entry may cover.
MIN_INCLUDE_PREFIX = {4: 8, 6: 32}

# Never testable from an external vantage point, and dangerous to aim tools at from inside the
# worker (its own loopback, the cloud metadata service at 169.254.169.254, broadcast, etc.).
FORBIDDEN_INCLUDE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "this network" / unspecified
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, incl. cloud metadata
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, incl. broadcast
        "::/128",  # unspecified
        "::1/128",  # loopback
        "::ffff:0:0/96",  # IPv4-mapped (use the IPv4 form instead)
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
)

MAX_HOSTNAME_LENGTH = 253
MAX_URL_LENGTH = 2048
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_psl = PublicSuffixList()


def normalize_scope_value(raw: str, mode: ScopeMode) -> NormalizedScope:
    """Classify and normalize an operator-entered scope value, or raise ScopeValueError."""
    value = raw.strip()
    if not value:
        raise ScopeValueError("Scope value is empty.")
    if any(c.isspace() or not c.isprintable() for c in value):
        raise ScopeValueError("Scope value must not contain spaces or control characters.")

    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return NormalizedScope(ScopeKind.URL, _normalize_url(value, mode))
    if "://" in value:
        raise ScopeValueError("Only http:// and https:// URLs can be scope entries.")
    if value.startswith("*."):
        return NormalizedScope(ScopeKind.WILDCARD, _normalize_wildcard(value, mode))
    if "*" in value:
        raise ScopeValueError("Wildcards are only allowed as a leading '*.' (e.g. *.example.com).")
    if "/" in value:
        return _normalize_network(value, mode)

    ip = _parse_ip(value)
    if ip is not None:
        _check_include_address(ip, mode)
        return NormalizedScope(ScopeKind.IP, str(ip))
    return NormalizedScope(ScopeKind.HOSTNAME, normalize_hostname(value, mode))


# --- IP addresses and networks --------------------------------------------------------------


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if "%" in value:
        raise ScopeValueError("IPv6 zone identifiers (e.g. %eth0) are not allowed in scope.")
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _check_include_address(ip, mode: ScopeMode) -> None:
    if mode is ScopeMode.INCLUDE and any(ip in net for net in FORBIDDEN_INCLUDE_NETWORKS):
        raise ScopeValueError(
            f"{ip} is a loopback, link-local, multicast, or otherwise reserved address and "
            "cannot be in scope."
        )


def _normalize_network(value: str, mode: ScopeMode) -> NormalizedScope:
    if "%" in value:
        raise ScopeValueError("IPv6 zone identifiers (e.g. %eth0) are not allowed in scope.")
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        loose = _try_loose_network(value)
        if loose is not None:
            raise ScopeValueError(
                f"{value} has host bits set. Did you mean {loose}? Enter the network address "
                "exactly so the range is unambiguous."
            ) from exc
        raise ScopeValueError(f"{value} is not a valid IP network (CIDR).") from exc

    if net.num_addresses == 1:  # /32 or /128: a single address
        ip = net.network_address
        _check_include_address(ip, mode)
        return NormalizedScope(ScopeKind.IP, str(ip))

    if mode is ScopeMode.INCLUDE:
        min_prefix = MIN_INCLUDE_PREFIX[net.version]
        if net.prefixlen < min_prefix:
            raise ScopeValueError(
                f"{net} is too broad for an include entry "
                f"(IPv{net.version} ranges must be /{min_prefix} or narrower)."
            )
        for forbidden in FORBIDDEN_INCLUDE_NETWORKS:
            if net.version == forbidden.version and net.overlaps(forbidden):
                raise ScopeValueError(
                    f"{net} overlaps reserved range {forbidden} (loopback, link-local, "
                    "multicast, or similar) and cannot be in scope."
                )
    return NormalizedScope(ScopeKind.CIDR, str(net))


def _try_loose_network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


# --- hostnames and wildcards ----------------------------------------------------------------


def normalize_hostname(value: str, mode: ScopeMode = ScopeMode.INCLUDE) -> str:
    """Lowercase, strip one trailing dot, convert Unicode labels to punycode, and validate."""
    host = value.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise ScopeValueError("Hostname is empty.")

    try:
        # UTS #46 mapping then IDNA 2008, so lookalike Unicode forms normalize consistently
        # and invalid internationalized names are rejected rather than passed through.
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise ScopeValueError(f"{value} is not a valid hostname: {exc}") from exc

    if len(ascii_host) > MAX_HOSTNAME_LENGTH:
        raise ScopeValueError(f"Hostname is longer than {MAX_HOSTNAME_LENGTH} characters.")
    labels = ascii_host.split(".")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ScopeValueError(
                f"{value} is not a valid hostname (each label must be 1-63 letters, digits, "
                "or hyphens, not starting or ending with a hyphen)."
            )
    if labels[-1].isdigit():
        raise ScopeValueError(f"{value} looks like a malformed IP address, not a hostname.")
    if len(labels) < 2:
        raise ScopeValueError(
            f"{value} is a single-label name. Use a fully qualified domain name or an IP address."
        )
    if mode is ScopeMode.INCLUDE and _psl.is_public(ascii_host):
        raise ScopeValueError(
            f"{ascii_host} is a public suffix (like .com or .co.uk) shared by many unrelated "
            "owners and cannot be in scope."
        )
    return ascii_host


def _normalize_wildcard(value: str, mode: ScopeMode) -> str:
    base = value[2:]
    if not base or "*" in base:
        raise ScopeValueError("A wildcard must be exactly '*.' followed by a domain.")
    if mode is ScopeMode.INCLUDE and _psl.is_public(base.lower().rstrip(".")):
        raise ScopeValueError(
            f"{value} would cover a public suffix shared by many unrelated owners. "
            "Use the organization's own domain (e.g. *.example.com)."
        )
    base_host = normalize_hostname(base, ScopeMode.EXCLUDE)  # syntax only; PSL check below
    if mode is ScopeMode.INCLUDE and _psl.is_public(base_host):
        raise ScopeValueError(
            f"*.{base_host} would cover a public suffix shared by many unrelated owners. "
            "Use the organization's own domain (e.g. *.example.com)."
        )
    return f"*.{base_host}"


# --- URLs -----------------------------------------------------------------------------------


def _normalize_url(value: str, mode: ScopeMode) -> str:
    if len(value) > MAX_URL_LENGTH:
        raise ScopeValueError(f"URL is longer than {MAX_URL_LENGTH} characters.")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ScopeValueError(f"{value} is not a valid URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if parts.username is not None or parts.password is not None:
        raise ScopeValueError("Scope URLs must not contain credentials.")
    if parts.query or parts.fragment:
        raise ScopeValueError("Scope URLs must not contain a query string or fragment.")
    if not parts.hostname:
        raise ScopeValueError(f"{value} has no host.")

    ip = _parse_ip(parts.hostname)
    if ip is not None:
        _check_include_address(ip, mode)
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    else:
        host = normalize_hostname(parts.hostname, mode)

    if port is not None and not (1 <= port <= 65535):
        raise ScopeValueError("URL port must be between 1 and 65535.")
    default_port = {"http": 80, "https": 443}[scheme]
    netloc = host if port in (None, default_port) else f"{host}:{port}"

    path = parts.path or "/"
    segments = path.split("/")
    if any(seg in (".", "..") or seg.lower() in ("%2e", "%2e%2e") for seg in segments):
        raise ScopeValueError("Scope URL paths must not contain '.' or '..' segments.")
    return f"{scheme}://{netloc}{path}"
