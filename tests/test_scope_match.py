"""Scope matching (core/scope_match.py). Every ambiguity must resolve toward less testing."""

import pytest

from quiver.core.scope import ScopeKind, ScopeMode, normalize_scope_value
from quiver.core.scope_match import Scope, ScopeResult, ScopeRule

IN, OUT, EXCL, UNC = (
    ScopeResult.IN_SCOPE,
    ScopeResult.OUT_OF_SCOPE,
    ScopeResult.EXCLUDED,
    ScopeResult.UNCERTAIN,
)


def scope(*includes, excludes=()):
    rules = []
    for mode, values in ((ScopeMode.INCLUDE, includes), (ScopeMode.EXCLUDE, excludes)):
        for v in values:
            n = normalize_scope_value(v, mode)
            rules.append(ScopeRule(n.kind, n.value, mode, id=v))
    return Scope(rules)


def result(s, target, **kw):
    return s.check(target, **kw).result


# --- IP and CIDR ------------------------------------------------------------------------------


def test_ip_targets():
    s = scope("203.0.113.0/24", "2001:db8::/48", excludes=["203.0.113.66"])
    assert result(s, "203.0.113.10") is IN
    assert result(s, "203.0.114.10") is OUT
    assert result(s, "203.0.113.66") is EXCL
    assert result(s, "2001:db8::abcd") is IN
    assert result(s, "2001:DB8:0:0::1") is IN
    assert result(s, "2001:db9::1") is OUT
    assert result(s, "::ffff:203.0.113.10") is IN  # IPv4-mapped form of an in-scope IPv4
    assert result(s, "::ffff:203.0.113.66") is EXCL  # ...and of an excluded one
    assert result(s, "fe80::1%eth0") is UNC


def test_decision_names_the_rule():
    s = scope("203.0.113.0/24", excludes=["203.0.113.66"])
    assert s.check("203.0.113.10").rule.value == "203.0.113.0/24"
    assert s.check("203.0.113.66").rule.value == "203.0.113.66"
    assert s.check("198.51.100.1").rule is None


def test_cidr_targets_must_be_fully_covered_and_never_touch_exclusions():
    s = scope("10.1.0.0/24", "10.1.1.0/24", excludes=["10.1.0.128/25"])
    assert result(s, "10.1.1.0/25") is IN
    assert result(s, "10.1.0.0/26") is IN
    assert result(s, "10.1.0.0/24") is EXCL  # overlaps the excluded half
    assert result(s, "10.1.0.0/16") is EXCL
    assert result(s, "10.1.2.0/24") is OUT
    assert result(s, "10.1.1.0/23") is EXCL  # 10.1.0.0/23 overlaps the exclusion


def test_cidr_covered_by_adjacent_entries():
    s = scope("10.2.0.0/25", "10.2.0.128/25")
    assert result(s, "10.2.0.0/24") is IN
    assert result(s, "10.2.0.0/23") is OUT


def test_cidr_target_with_host_bits_means_the_whole_network():
    s = scope("10.3.0.0/24")
    assert result(s, "10.3.0.5/24") is IN
    assert result(s, "10.3.0.5/23") is OUT
    assert result(s, "10.3.0.5/32") is IN


def test_ip_entries_never_cover_hostnames():
    # Resolution is the gate's job (step 7); an IP entry alone does not put names in scope.
    assert result(scope("203.0.113.0/24"), "www.example.com") is OUT


# --- hostnames and wildcards ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("example.com", IN),
        ("EXAMPLE.com.", IN),
        ("www.example.com", OUT),  # an apex entry covers only the apex
        ("api.corp.com", IN),  # *.corp.com, one level
        ("a.b.c.corp.com", IN),  # any depth
        ("corp.com", OUT),  # a wildcard never covers its base
        ("notcorp.com", OUT),
        ("corp.com.evil.net", OUT),
        ("api.corp.com.evil.net", OUT),
        ("example.com.evil.net", OUT),
        ("xexample.com", OUT),
        ("localhost", OUT),
        ("intranet", OUT),
    ],
)
def test_hostname_targets(target, expected):
    s = scope("example.com", "*.corp.com")
    assert result(s, target) is expected


def test_unicode_lookalikes_do_not_match():
    s = scope("example.com", "*.corp.com")
    assert result(s, "ex\u0430mple.com") is OUT  # Cyrillic a (U+0430)
    assert result(s, "api.c\u043erp.com") is OUT  # Cyrillic o (U+043E)
    fullwidth = "".join(chr(0xFF41 + ord(c) - ord("a")) for c in "example")
    assert result(s, f"{fullwidth}.com") is IN  # fullwidth maps to the same ASCII name
    assert result(s, "example\u3002com") is IN  # ideographic full stop maps to "."


def test_punycode_and_unicode_forms_are_the_same_host():
    s = scope("bücher.example")
    assert result(s, "xn--bcher-kva.example") is IN
    assert result(s, "BÜCHER.example") is IN


@pytest.mark.parametrize(
    "target",
    ["2130706433", "0x7f000001", "0x7f.1", "017700000001", "127.1", "10.0.1", "1.2.3.4.5"],
)
def test_ip_lookalike_hostnames_are_uncertain(target):
    # Resolvers and HTTP clients may read these as IP addresses.
    assert result(scope("example.com"), target) is UNC


def test_hostname_exclusions_cover_subdomains_and_beat_wildcards():
    s = scope("*.example.com", excludes=["legacy.example.com", "*.lab.example.com"])
    assert result(s, "app.example.com") is IN
    assert result(s, "legacy.example.com") is EXCL
    assert result(s, "db.legacy.example.com") is EXCL  # excluded names cover subdomains
    assert result(s, "x.lab.example.com") is EXCL
    assert result(s, "lab.example.com") is IN  # *.lab excludes below lab, not lab itself
    assert s.check("x.lab.example.com").rule.value == "*.lab.example.com"


def test_most_specific_wildcard_is_reported():
    s = scope("*.example.com", "*.api.example.com")
    assert s.check("v1.api.example.com").rule.value == "*.api.example.com"


@pytest.mark.parametrize("target", ["*.example.com", "", "  ", "exa mple.com", "a\x00.example.com"])
def test_malformed_targets_are_uncertain(target):
    assert result(scope("*.example.com"), target) is UNC


def test_invalid_hostname_is_uncertain():
    assert result(scope("example.com"), "bad_host.example.com") is UNC
    assert result(scope("example.com"), "-bad.example.com") is UNC


# --- URLs ------------------------------------------------------------------------------------


def test_host_level_inclusion_covers_all_urls():
    s = scope("app.example.com", "203.0.113.5")
    assert result(s, "https://app.example.com/anything?x=1") is IN
    assert result(s, "http://app.example.com:8080/") is IN
    assert result(s, "https://203.0.113.5:8443/x") is IN
    assert result(s, "https://other.example.com/") is OUT


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://app.example.com/portal", IN),
        ("https://app.example.com/portal/", IN),
        ("https://app.example.com/portal/login?next=/admin", IN),
        ("https://app.example.com:443/portal/x", IN),  # default port
        ("HTTPS://APP.example.com/portal/x", IN),
        ("https://app.example.com/portalx", OUT),  # segment boundary
        ("https://app.example.com/Portal/x", OUT),  # include paths are case-sensitive
        ("https://app.example.com/admin", OUT),
        ("https://app.example.com/", OUT),
        ("http://app.example.com/portal", OUT),  # scheme
        ("https://app.example.com:8443/portal", OUT),  # port
        ("https://app.example.com/portal/../admin", OUT),  # traversal resolved first
        ("https://app.example.com/portal/%2e%2e/admin", OUT),
        ("https://app.example.com/portal/%2E%2E/admin", OUT),
        ("https://app.example.com/portal/./x", IN),
        ("https://app.example.com/%70ortal/x", IN),  # %70 = "p" (unreserved, decoded)
    ],
)
def test_url_entries_cover_web_requests_under_the_path(target, expected):
    assert result(scope("https://app.example.com/portal"), target) is expected


def test_url_entries_do_not_cover_host_level_actions():
    s = scope("https://app.example.com/portal")
    decision = s.check("app.example.com")
    assert decision.result is OUT
    assert "host-level" in decision.reason


def test_url_subtree_targets():
    s = scope("https://app.example.com/portal")
    assert result(s, "https://app.example.com/portal/", url_subtree=True) is IN
    decision = s.check("https://app.example.com/", url_subtree=True)
    assert decision.result is OUT
    assert "narrow" in decision.reason


@pytest.mark.parametrize(
    "target",
    [
        "https://app.example.com/admin",
        "https://app.example.com/admin/users",
        "https://app.example.com/ADMIN",  # case-insensitive for exclusions
        "https://app.example.com/Admin/x",
        "https://app.example.com/admin;jsessionid=1",  # ;params ignored
        "https://app.example.com//admin",  # repeated slashes
        "http://app.example.com/admin",  # any scheme
        "https://app.example.com:8443/admin",  # any port
        "https://app.example.com/x/../admin",
        "https://app.example.com/%61dmin",  # %61 = "a"
    ],
)
def test_url_exclusions_are_matched_loosely(target):
    s = scope("app.example.com", excludes=["https://app.example.com/admin"])
    assert result(s, target) is EXCL


def test_url_exclusion_inside_a_subtree_target():
    s = scope("app.example.com", excludes=["https://app.example.com/admin"])
    assert result(s, "https://app.example.com/", url_subtree=False) is IN  # one request to /
    assert result(s, "https://app.example.com/", url_subtree=True) is EXCL  # a crawl from /
    assert result(s, "https://app.example.com/docs", url_subtree=True) is IN


def test_excluded_web_root_makes_host_level_actions_uncertain():
    s = scope(
        "*.example.com",
        "203.0.113.0/24",
        excludes=["https://app.example.com/", "https://203.0.113.9/"],
    )
    assert result(s, "app.example.com") is UNC
    assert result(s, "https://app.example.com/x") is EXCL
    assert result(s, "203.0.113.9") is UNC
    assert result(s, "203.0.113.0/24") is UNC
    assert result(s, "www.example.com") is IN


def test_host_exclusions_apply_to_urls():
    s = scope("*.example.com", "203.0.113.0/24", excludes=["legacy.example.com", "203.0.113.66"])
    assert result(s, "https://legacy.example.com/") is EXCL
    assert result(s, "https://api.legacy.example.com/") is EXCL
    assert result(s, "https://203.0.113.66/") is EXCL
    assert result(s, "https://[::ffff:203.0.113.66]/") is EXCL


@pytest.mark.parametrize(
    "target",
    [
        "https://app.example.com@evil.example.net/",  # credentials disguise the real host
        "https://user:pw@app.example.com/",
        "https://app.example.com\\@evil.example.net/",
        "ftp://app.example.com/",
        "gopher://app.example.com/",
        "https://app.example.com/a%2Fb",  # encoded slash
        "https://app.example.com/a%5Cb",  # encoded backslash
        "https://app.example.com/%252e%252e/admin",  # double encoding
        "https://app.example.com/a\\b",
        "https://app.example.com:0/",
        "https://app.example.com:99999/",
        "https:///nohost",
        "http://2130706433/",
        "http://0x7f.1/",
        "http://[fe80::1%25eth0]/",
    ],
)
def test_suspicious_urls_are_uncertain(target):
    assert result(scope("app.example.com", "*.example.com"), target) is UNC


# --- no scope, and corrupted scope ------------------------------------------------------------


def test_empty_scope_covers_nothing():
    s = Scope([])
    assert result(s, "203.0.113.1") is OUT
    assert result(s, "example.com") is OUT
    assert result(s, "https://example.com/") is OUT


def test_excludes_alone_cover_nothing():
    s = scope(excludes=["0.0.0.0/0", "*.co.uk"])
    assert result(s, "203.0.113.1") is EXCL
    assert result(s, "example.com") is OUT


def test_corrupted_stored_entry_fails_loudly():
    with pytest.raises(ValueError, match="invalid scope entry"):
        Scope([ScopeRule(ScopeKind.CIDR, "not-a-network", ScopeMode.INCLUDE)])


def test_from_entries_accepts_orm_like_objects():
    class Row:
        def __init__(self, kind, value, mode):
            self.kind, self.value, self.mode, self.id = kind, value, mode, f"row-{value}"

    s = Scope.from_entries([Row("cidr", "203.0.113.0/24", "include")])
    decision = s.check("203.0.113.7")
    assert decision.in_scope
    assert decision.rule.id == "row-203.0.113.0/24"
