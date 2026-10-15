import pytest

from quiver.core.scope import ScopeKind, ScopeMode, ScopeValueError, normalize_scope_value

INC, EXC = ScopeMode.INCLUDE, ScopeMode.EXCLUDE


def norm(raw, mode=INC):
    n = normalize_scope_value(raw, mode)
    return n.kind, n.value


# --- accepted, with canonical form -------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "kind", "value"),
    [
        ("203.0.113.10", ScopeKind.IP, "203.0.113.10"),
        ("  203.0.113.10  ", ScopeKind.IP, "203.0.113.10"),
        ("2001:DB8::1", ScopeKind.IP, "2001:db8::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", ScopeKind.IP, "2001:db8::1"),
        ("203.0.113.0/24", ScopeKind.CIDR, "203.0.113.0/24"),
        ("203.0.113.7/32", ScopeKind.IP, "203.0.113.7"),  # single address
        ("2001:db8::/48", ScopeKind.CIDR, "2001:db8::/48"),
        ("10.0.0.0/8", ScopeKind.CIDR, "10.0.0.0/8"),  # private ranges allowed (lab use)
        ("Example.COM", ScopeKind.HOSTNAME, "example.com"),
        ("api.example.com.", ScopeKind.HOSTNAME, "api.example.com"),  # trailing dot
        ("bücher.example", ScopeKind.HOSTNAME, "xn--bcher-kva.example"),  # punycode
        ("xn--bcher-kva.example", ScopeKind.HOSTNAME, "xn--bcher-kva.example"),
        ("*.Example.com", ScopeKind.WILDCARD, "*.example.com"),
        ("*.example.co.uk", ScopeKind.WILDCARD, "*.example.co.uk"),
        ("HTTPS://App.Example.com", ScopeKind.URL, "https://app.example.com/"),
        ("https://app.example.com:443/admin", ScopeKind.URL, "https://app.example.com/admin"),
        ("http://app.example.com:8080/x/", ScopeKind.URL, "http://app.example.com:8080/x/"),
        ("http://[2001:db8::1]/", ScopeKind.URL, "http://[2001:db8::1]/"),
        ("https://203.0.113.5:8443/", ScopeKind.URL, "https://203.0.113.5:8443/"),
    ],
)
def test_accepted(raw, kind, value):
    assert norm(raw) == (kind, value)


def test_unicode_lookalike_normalizes_differently_from_ascii():
    # Cyrillic small a (U+0430) instead of Latin "a": must not collapse to the real domain.
    _, value = norm("ex\u0430mple.com")
    assert value != "example.com"
    assert value.startswith("xn--")


def test_fullwidth_characters_map_to_ascii():
    # UTS #46 maps fullwidth forms (U+FF41..) to their ASCII equivalents.
    fullwidth = "".join(chr(0xFF41 + ord(c) - ord("a")) for c in "example")
    assert norm(f"{fullwidth}.com") == (ScopeKind.HOSTNAME, "example.com")


# --- rejected for includes -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("", "empty"),
        ("exa mple.com", "spaces"),
        ("example.com\x00", "control"),
        ("127.0.0.1", "reserved"),
        ("::1", "reserved"),
        ("169.254.169.254", "reserved"),  # cloud metadata
        ("0.0.0.0", "reserved"),
        ("224.0.0.1", "reserved"),
        ("255.255.255.255", "reserved"),
        ("fe80::1", "reserved"),
        ("::ffff:203.0.113.1", "reserved"),  # IPv4-mapped: use the IPv4 form
        ("fe80::1%eth0", "zone"),
        ("0.0.0.0/0", "too broad"),
        ("::/0", "too broad"),
        ("10.0.0.0/7", "too broad"),
        ("2001:db8::/31", "too broad"),
        ("169.0.0.0/8", "overlaps"),  # contains 169.254.0.0/16
        ("10.0.0.5/24", "host bits"),
        ("10.0.0.0/33", "not a valid"),
        ("com", "single-label"),
        ("co.uk", "public suffix"),
        ("github.io", "public suffix"),
        ("intranet", "single-label"),
        ("-bad.example.com", "not a valid hostname"),
        ("bad-.example.com", "not a valid hostname"),
        ("under_score.example.com", "not a valid"),
        ("a" * 64 + ".example.com", "not a valid hostname"),
        (("a" * 60 + ".") * 5 + "com", "too long|longer than"),
        ("1.2.3", "malformed IP"),
        ("*.com", "public suffix"),
        ("*.co.uk", "public suffix"),
        ("*.github.io", "public suffix"),
        ("*", "Wildcards"),
        ("*.", "exactly"),
        ("foo.*.example.com", "Wildcards"),
        ("*.*.example.com", "exactly"),
        ("*example.com", "Wildcards"),
        ("ftp://example.com/", "Only http"),
        ("https://user:pw@example.com/", "credentials"),
        ("https://example.com/?q=1", "query"),
        ("https://example.com/#frag", "query"),
        ("https://example.com/a/../admin", "segments"),
        ("https://example.com/%2e%2e/admin", "segments"),
        ("https://127.0.0.1/", "reserved"),
        ("https://example.com:99999/", "not a valid URL"),
        ("https:///path", "no host"),
    ],
)
def test_rejected_include(raw, reason):
    with pytest.raises(ScopeValueError, match=f"(?i){reason}"):
        normalize_scope_value(raw, INC)


# --- excludes may be broad, but must still be well-formed -----------------------------------


@pytest.mark.parametrize(
    ("raw", "kind", "value"),
    [
        ("127.0.0.1", ScopeKind.IP, "127.0.0.1"),
        ("0.0.0.0/0", ScopeKind.CIDR, "0.0.0.0/0"),
        ("*.co.uk", ScopeKind.WILDCARD, "*.co.uk"),
        ("github.io", ScopeKind.HOSTNAME, "github.io"),
    ],
)
def test_broad_excludes_allowed(raw, kind, value):
    assert norm(raw, EXC) == (kind, value)


@pytest.mark.parametrize("raw", ["10.0.0.5/24", "intranet", "*", "ftp://x.example/"])
def test_malformed_excludes_rejected(raw):
    with pytest.raises(ScopeValueError):
        normalize_scope_value(raw, EXC)


def test_normalization_is_idempotent():
    for raw in ["Example.COM.", "*.Example.com", "HTTPS://App.Example.com:443", "2001:DB8::/48"]:
        _, once = norm(raw)
        _, twice = norm(once)
        assert once == twice
