"""Deterministic identity keys for graph entities and findings (Blueprint §5.3).

The LLM never decides identity: two sightings are the same entity exactly when these
functions give the same key. Keys are `type:canonical-form`. Every function is pure and total
over valid input; invalid input raises ValueError (never a guess).

Canonical forms:
- host          the IP address; IPv4-mapped IPv6 becomes IPv4, IPv6 is compressed lowercase
- domain        lowercase, trailing dot removed, Unicode → punycode (UTS 46 + IDNA 2008), so
                lookalike names stay distinct
- service       address:port/protocol (tcp or udp)
- certificate   SHA-256 fingerprint, 64 lowercase hex digits
- web_endpoint  scheme://host:port/path with the default port explicit, credentials, query and
                fragment dropped, unreserved escapes decoded, other escapes uppercased, and dot
                segments removed. Unlike scope matching, nothing here is "uncertain": the gate
                decides whether such a URL may be touched; identity only has to be stable.
- finding       issue type | affected entity key | location
"""

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

from quiver.core.scope import ScopeMode, normalize_hostname

_DEFAULT_PORTS = {"http": 80, "https": 443}
_PROTOCOLS = ("tcp", "udp")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
MAX_ISSUE = 200
MAX_LOCATION = 2048
MAX_URL = 2048


def key_hash(key: str) -> str:
    """Fixed-size form of a key for indexing (keys of long URLs can be large)."""
    return hashlib.sha256(key.encode()).hexdigest()


# --- addresses and names --------------------------------------------------------------------


def canonical_ip(value: str) -> str:
    text = str(value).strip()
    if "%" in text:
        raise ValueError(f"IPv6 zone identifiers are not part of an address identity: {text!r}")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"{text!r} is not an IP address") from exc
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def canonical_domain(value: str) -> str:
    # Syntax only (exclude mode): public suffixes are valid names to record, just not scope.
    return normalize_hostname(str(value).strip(), ScopeMode.EXCLUDE)


def _host(value: str) -> str:
    """An address or a name, canonical either way."""
    try:
        return canonical_ip(value)
    except ValueError:
        return canonical_domain(value)


# --- keys -----------------------------------------------------------------------------------


def host_key(ip: str) -> str:
    return f"host:{canonical_ip(ip)}"


def domain_key(name: str) -> str:
    return f"domain:{canonical_domain(name)}"


def canonical_port(port) -> int:
    if isinstance(port, bool) or not isinstance(port, int | str):
        raise ValueError(f"port {port!r} is not a number")
    try:
        number = int(port)
    except ValueError as exc:
        raise ValueError(f"port {port!r} is not a number") from exc
    if not 1 <= number <= 65535:
        raise ValueError(f"port {number} is out of range")
    return number


def canonical_protocol(protocol: str) -> str:
    proto = str(protocol).strip().lower()
    if proto not in _PROTOCOLS:
        raise ValueError(f"protocol must be one of {_PROTOCOLS}, not {protocol!r}")
    return proto


def service_key(ip: str, port, protocol: str = "tcp") -> str:
    return f"service:{canonical_ip(ip)}:{canonical_port(port)}/{canonical_protocol(protocol)}"


def canonical_fingerprint(value: str) -> str:
    fp = re.sub(r"[\s:]", "", str(value)).lower().removeprefix("sha256")
    fp = fp.lstrip("=:/")
    if not _HEX64.match(fp):
        raise ValueError("a certificate fingerprint must be a SHA-256 digest (64 hex digits)")
    return fp


def certificate_key(sha256: str) -> str:
    return f"certificate:{canonical_fingerprint(sha256)}"


def canonical_url(url: str) -> str:
    text = str(url).strip()
    if len(text) > MAX_URL:
        raise ValueError(f"URL is longer than {MAX_URL} characters")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"{text!r} is not a valid URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"web endpoints are http or https, not {scheme or 'no scheme'!r}")
    if not parts.hostname:
        raise ValueError(f"{text!r} has no host")
    host = _host(parts.hostname)
    if ":" in host:
        host = f"[{host}]"
    port = canonical_port(port) if port is not None else _DEFAULT_PORTS[scheme]
    return f"{scheme}://{host}:{port}{canonical_path(parts.path)}"


def web_endpoint_key(url: str) -> str:
    return f"web_endpoint:{canonical_url(url)}"


def finding_key(issue_type: str, entity_key: str, location: str = "") -> str:
    issue = canonical_issue(issue_type)
    loc = canonical_location(location)
    if not entity_key or "|" in entity_key:
        raise ValueError("a finding needs the key of the entity it affects")
    return f"finding:{issue}|{entity_key}|{loc}"


def canonical_issue(issue_type: str) -> str:
    issue = " ".join(str(issue_type).split()).lower()
    if not issue or len(issue) > MAX_ISSUE or "|" in issue:
        raise ValueError(f"issue type must be 1-{MAX_ISSUE} characters without '|'")
    return issue


def canonical_location(location: str) -> str:
    loc = str(location or "").strip()
    if len(loc) > MAX_LOCATION:
        raise ValueError(f"location is longer than {MAX_LOCATION} characters")
    return loc


# --- URL paths ------------------------------------------------------------------------------


def canonical_path(path: str) -> str:
    """Normalize a URL path for identity: decode escapes of unreserved characters, uppercase
    the rest, encode a stray '%', and remove dot segments (RFC 3986 §5.2.4)."""

    def escape(m: re.Match) -> str:
        char = chr(int(m.group(1), 16))
        return char if char in _UNRESERVED else f"%{m.group(1).upper()}"

    out, i = [], 0
    while i < len(path):  # a '%' not followed by two hex digits is a literal percent sign
        m = _ESCAPE.match(path, i)
        if m:
            out.append(escape(m))
            i = m.end()
        elif path[i] == "%":
            out.append("%25")
            i += 1
        else:
            out.append(path[i])
            i += 1
    return _remove_dot_segments("".join(out) or "/")


def _remove_dot_segments(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    output: list[str] = []
    segments = path.split("/")[1:]
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        if seg == "..":
            if output:
                output.pop()
            if last:
                output.append("")
        elif seg == ".":
            if last:
                output.append("")
        else:
            output.append(seg)
    return "/" + "/".join(output)
