"""Property-based checks: the matcher must agree with a brute-force reference."""

import ipaddress

from hypothesis import given, settings
from hypothesis import strategies as st

from quiver.core.scope import ScopeKind, ScopeMode
from quiver.core.scope_match import Scope, ScopeResult, ScopeRule

# A small universe (10.9.0.0/22, 1024 addresses) so brute force is cheap and collisions common.
BASE = int(ipaddress.ip_address("10.9.0.0"))


@st.composite
def networks(draw, min_prefix=22, max_prefix=32):
    prefix = draw(st.integers(min_prefix, max_prefix))
    size = 2 ** (32 - prefix)
    offset = draw(st.integers(0, 1024 // size - 1)) * size
    return ipaddress.ip_network((BASE + offset, prefix))


def rule(net, mode):
    kind = ScopeKind.IP if net.num_addresses == 1 else ScopeKind.CIDR
    value = str(net.network_address) if kind is ScopeKind.IP else str(net)
    return ScopeRule(kind, value, mode)


def brute(target_net, includes, excludes):
    addrs = set(target_net)
    if any(a in e for a in addrs for e in excludes):
        return ScopeResult.EXCLUDED
    if all(any(a in i for i in includes) for a in addrs):
        return ScopeResult.IN_SCOPE
    return ScopeResult.OUT_OF_SCOPE


@settings(max_examples=400, deadline=None)
@given(
    includes=st.lists(networks(), max_size=5),
    excludes=st.lists(networks(), max_size=3),
    target=networks(min_prefix=24),
)
def test_ip_and_cidr_targets_match_brute_force(includes, excludes, target):
    s = Scope(
        [rule(n, ScopeMode.INCLUDE) for n in includes]
        + [rule(n, ScopeMode.EXCLUDE) for n in excludes]
    )
    text = str(target.network_address) if target.num_addresses == 1 else str(target)
    assert s.check(text).result is brute(target, includes, excludes)


LABELS = st.sampled_from(["a", "b", "ab", "example", "corp", "x-y"])
TLDS = st.sampled_from(["com", "net"])


@st.composite
def hostnames(draw, min_labels=0, max_labels=3):
    labels = draw(st.lists(LABELS, min_size=min_labels, max_size=max_labels))
    return ".".join([*labels, draw(LABELS), draw(TLDS)])


def host_brute(host, inc_hosts, inc_wild, exc_hosts, exc_wild):
    if any(host == h or host.endswith("." + h) for h in exc_hosts):
        return ScopeResult.EXCLUDED
    if any(host.endswith("." + b) for b in exc_wild):
        return ScopeResult.EXCLUDED
    if host in inc_hosts or any(host.endswith("." + b) for b in inc_wild):
        return ScopeResult.IN_SCOPE
    return ScopeResult.OUT_OF_SCOPE


@settings(max_examples=400, deadline=None)
@given(
    inc_hosts=st.lists(hostnames(), max_size=3),
    inc_wild=st.lists(hostnames(), max_size=3),
    exc_hosts=st.lists(hostnames(), max_size=2),
    exc_wild=st.lists(hostnames(), max_size=2),
    target=hostnames(max_labels=4),
)
def test_hostname_targets_match_brute_force(inc_hosts, inc_wild, exc_hosts, exc_wild, target):
    rules = (
        [ScopeRule(ScopeKind.HOSTNAME, h, ScopeMode.INCLUDE) for h in inc_hosts]
        + [ScopeRule(ScopeKind.WILDCARD, f"*.{b}", ScopeMode.INCLUDE) for b in inc_wild]
        + [ScopeRule(ScopeKind.HOSTNAME, h, ScopeMode.EXCLUDE) for h in exc_hosts]
        + [ScopeRule(ScopeKind.WILDCARD, f"*.{b}", ScopeMode.EXCLUDE) for b in exc_wild]
    )
    expected = host_brute(target, set(inc_hosts), inc_wild, exc_hosts, exc_wild)
    assert Scope(rules).check(target).result is expected


SEGMENTS = st.sampled_from(["portal", "admin", "x", "..", ".", "%2e%2e", "%2E", "Admin", ""])


@settings(max_examples=400, deadline=None)
@given(st.lists(SEGMENTS, max_size=6))
def test_traversal_never_escapes_into_admin_via_portal(segments):
    """Whatever the path does, a target that resolves outside /portal is never in scope, and
    a target that resolves into /admin is always excluded."""
    s = Scope(
        [
            ScopeRule(ScopeKind.URL, "https://app.example.com/portal", ScopeMode.INCLUDE),
            ScopeRule(ScopeKind.URL, "https://app.example.com/admin", ScopeMode.EXCLUDE),
        ]
    )
    path = "/" + "/".join(segments)
    decision = s.check(f"https://app.example.com{path}")

    # Reference resolution (RFC 3986 dot-segment removal after decoding %2e).
    out = []
    raw = [seg.replace("%2e", ".").replace("%2E", ".") for seg in segments]
    for i, seg in enumerate(raw):
        last = i == len(raw) - 1
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
    resolved = "/" + "/".join(out)
    loose = "/" + "/".join(s.lower() for s in resolved.split("/") if s)

    if loose == "/admin" or loose.startswith("/admin/"):
        assert decision.result is ScopeResult.EXCLUDED
    elif decision.result is ScopeResult.IN_SCOPE:
        assert resolved == "/portal" or resolved.startswith("/portal/")
