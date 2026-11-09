"""Identity keys: equivalent spellings collapse to one key, different things never do."""

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from quiver.core.graph import keys

# --- same thing, same key -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spellings", "key"),
    [
        (
            ["203.0.113.5", " 203.0.113.5 ", "::ffff:203.0.113.5", "::FFFF:cb00:7105"],
            "host:203.0.113.5",
        ),
        (["2001:db8::1", "2001:0DB8:0000::0001", "2001:db8:0:0:0:0:0:1"], "host:2001:db8::1"),
    ],
)
def test_host_spellings(spellings, key):
    assert {keys.host_key(s) for s in spellings} == {key}


@pytest.mark.parametrize(
    "spelling", ["www.example.com", "WWW.Example.COM", "www.example.com.", " www.example.com "]
)
def test_domain_spellings(spelling):
    assert keys.domain_key(spelling) == "domain:www.example.com"


def test_unicode_domains_become_punycode():
    assert keys.domain_key("bücher.example") == "domain:xn--bcher-kva.example"
    assert keys.domain_key("BÜCHER.example") == keys.domain_key("bücher.example")


def test_service_spellings():
    same = {
        keys.service_key("203.0.113.5", 443),
        keys.service_key("::ffff:203.0.113.5", "443", "TCP"),
        keys.service_key(" 203.0.113.5", 443, " tcp "),
    }
    assert same == {"service:203.0.113.5:443/tcp"}


def test_certificate_spellings():
    hex64 = "ab" * 32
    spellings = [hex64, hex64.upper(), ":".join(["AB"] * 32), f"SHA256:{hex64}", f"sha256={hex64}"]
    assert {keys.certificate_key(s) for s in spellings} == {f"certificate:{hex64}"}


@pytest.mark.parametrize(
    "url",
    [
        "https://www.example.com/a/b",
        "HTTPS://WWW.EXAMPLE.COM/a/b",
        "https://www.example.com:443/a/b",
        "https://www.example.com/a/./b",
        "https://www.example.com/a/x/../b",
        "https://www.example.com/a/b?query=1#frag",
        "https://user:pass@www.example.com/a/b",
        "https://www.example.com/%61/b",  # %61 is 'a', an unreserved character
    ],
)
def test_web_endpoint_spellings(url):
    assert keys.web_endpoint_key(url) == "web_endpoint:https://www.example.com:443/a/b"


def test_web_endpoint_root_and_escapes():
    assert keys.canonical_url("http://example.com") == "http://example.com:80/"
    assert keys.canonical_url("http://example.com/a%2fb") == "http://example.com:80/a%2Fb"
    assert keys.canonical_url("http://example.com/%7Euser") == "http://example.com:80/~user"
    assert keys.canonical_url("http://example.com/100%") == "http://example.com:80/100%25"
    assert keys.canonical_url("http://[2001:DB8::1]:8080/x") == "http://[2001:db8::1]:8080/x"
    assert keys.canonical_url("http://[::ffff:203.0.113.5]/") == "http://203.0.113.5:80/"


def test_finding_key():
    entity = keys.web_endpoint_key("https://www.example.com/login")
    k = keys.finding_key("  Nuclei:CVE-2021-44228 ", entity, " param:user ")
    assert k == f"finding:nuclei:cve-2021-44228|{entity}|param:user"
    assert keys.finding_key("nuclei:cve-2021-44228", entity, "param:user") == k


# --- different things, different keys -------------------------------------------------------


def test_lookalike_domains_stay_distinct():
    real = keys.domain_key("paypal.com")
    assert keys.domain_key("p\u0430ypal.com") != real  # Cyrillic "a" (U+0430)
    assert keys.domain_key("paypa1.com") != real


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("https://example.com/", "http://example.com/"),
        ("https://example.com/", "https://example.com:8443/"),
        ("https://example.com/Admin", "https://example.com/admin"),  # paths are case-sensitive
        ("https://example.com/a/", "https://example.com/a"),
        ("https://a.example.com/", "https://b.example.com/"),
        ("https://203.0.113.5/", "https://www.example.com/"),  # virtual hosts differ
    ],
)
def test_distinct_endpoints(a, b):
    assert keys.web_endpoint_key(a) != keys.web_endpoint_key(b)


def test_distinct_services():
    base = keys.service_key("203.0.113.5", 53, "tcp")
    assert keys.service_key("203.0.113.5", 53, "udp") != base
    assert keys.service_key("203.0.113.5", 54, "tcp") != base
    assert keys.service_key("203.0.113.6", 53, "tcp") != base


def test_findings_differ_by_issue_entity_and_location():
    e1, e2 = keys.host_key("203.0.113.5"), keys.host_key("203.0.113.6")
    base = keys.finding_key("weak-tls", e1, "")
    assert keys.finding_key("weak-tls", e2, "") != base
    assert keys.finding_key("weak-tls", e1, "port 443") != base
    assert keys.finding_key("expired-cert", e1, "") != base


# --- invalid input is rejected, never guessed -----------------------------------------------


@pytest.mark.parametrize(
    ("fn", "args"),
    [
        (keys.host_key, ("not-an-ip",)),
        (keys.host_key, ("fe80::1%eth0",)),
        (keys.domain_key, ("localhost",)),  # single label
        (keys.domain_key, ("a..b.com",)),
        (keys.service_key, ("203.0.113.5", 0)),
        (keys.service_key, ("203.0.113.5", 70000)),
        (keys.service_key, ("203.0.113.5", True)),
        (keys.service_key, ("203.0.113.5", 80, "sctp")),
        (keys.service_key, ("www.example.com", 80)),  # services are keyed by address
        (keys.certificate_key, ("ab" * 20,)),  # SHA-1 length
        (keys.certificate_key, ("zz" * 32,)),
        (keys.web_endpoint_key, ("ftp://example.com/",)),
        (keys.web_endpoint_key, ("https:///nohost",)),
        (keys.web_endpoint_key, ("https://example.com:99999/",)),
        (keys.web_endpoint_key, ("https://example.com/" + "a" * 3000,)),
        (keys.finding_key, ("", "host:203.0.113.5")),
        (keys.finding_key, ("a|b", "host:203.0.113.5")),
        (keys.finding_key, ("issue", "")),
    ],
)
def test_invalid_input_raises(fn, args):
    with pytest.raises(ValueError):
        fn(*args)


def test_key_hash_is_stable_and_fixed_size():
    k = keys.web_endpoint_key("https://example.com/" + "a" * 1000)
    assert keys.key_hash(k) == keys.key_hash(k) and len(keys.key_hash(k)) == 64


# --- properties -----------------------------------------------------------------------------


@given(st.ip_addresses())
def test_host_key_is_canonical(ip):
    k = keys.host_key(str(ip))
    assert keys.host_key(k.removeprefix("host:")) == k  # idempotent
    expected = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
    assert ipaddress.ip_address(k.removeprefix("host:")) == expected


_segment = st.text(alphabet="abcXYZ09-._~%2F", min_size=0, max_size=6)


@given(st.lists(_segment, max_size=6), st.sampled_from(["http", "https"]))
def test_url_canonicalization_is_idempotent(segments, scheme):
    url = f"{scheme}://example.com/" + "/".join(segments)
    once = keys.canonical_url(url)
    assert keys.canonical_url(once) == once
    path = once.split(":", 2)[2].split("/", 1)[1]
    assert "/./" not in f"/{path}/" and "/../" not in f"/{path}/"
