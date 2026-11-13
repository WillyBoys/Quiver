"""External track parsers against recorded tool output (tests/fixtures/tools/).

example_com.log files are recorded from the pinned tool versions (and quiver-ct against crt.sh)
for example.com (a documentation domain; dnsx addresses replaced with documentation ranges).
edge_cases.log and all_sources_failed.log are hand-made in the same format: what hostile or
broken output can look like.
"""

from pathlib import Path

import pytest

from quiver.core.graph.types import default_graph
from quiver.worker.tracks.external.parsers import common, ct, dnsx, nmap, subfinder

FIXTURES = Path(__file__).parent / "fixtures" / "tools"
GRAPH = default_graph()


def fixture(tool: str, name: str) -> bytes:
    return (FIXTURES / tool / f"{name}.log").read_bytes()


def names(parsed, entity_type="domain"):
    return [e.attributes["name"] for e in parsed.entities if e.type == entity_type]


def assert_all_valid(parsed):
    """Everything a parser returns must pass the graph types, so record() never rejects it."""
    for e in parsed.entities:
        GRAPH.entity(e.type).key(e.attributes)
    for link in parsed.links:
        GRAPH.relation(link.type)


# --- subfinder -------------------------------------------------------------------------------


def test_subfinder_recorded_output():
    parsed = subfinder.parse(fixture("subfinder", "example_com"), {"domain": "example.com"})
    assert_all_valid(parsed)
    assert len(parsed.entities) == 21 and parsed.skipped == 0 and not parsed.capped
    assert "www.example.com" in names(parsed)
    assert "xn--90arkcabltj6b.example.com" in names(parsed)  # IDN kept in punycode
    www = next(e for e in parsed.entities if e.attributes["name"] == "www.example.com")
    assert www.attributes["sources"] == sorted(
        ["scanmalware", "shodanct", "anubis", "hackertarget", "crtname", "crtsh"]
    )
    assert parsed.notes == {"names": 21, "source_errors": []}


def test_subfinder_edge_cases():
    parsed = subfinder.parse(fixture("subfinder", "edge_cases"), {"domain": "example.com"})
    assert_all_valid(parsed)
    assert names(parsed) == [
        "a.b.c.example.com",
        "api.example.com",  # trailing dot dropped
        "dup.example.com",
        "example.com",  # the base itself
        "www.example.com",  # case folded
        "xn--bcher-kva.example.com",  # Unicode -> punycode
    ]
    dup = next(e for e in parsed.entities if e.attributes["name"] == "dup.example.com")
    assert dup.attributes["sources"] == ["anubis", "crtsh"]
    # Wildcard, lookalikes, foreign names, IP, invalid labels, empty, wrong types, an
    # over-long name and the truncated last line are skipped. Plain junk lines are ignored.
    assert parsed.skipped == 11
    assert parsed.notes["source_errors"] == ["crtname"]


def test_subfinder_all_sources_failed_is_visible():
    parsed = subfinder.parse(fixture("subfinder", "all_sources_failed"), {"domain": "example.com"})
    assert parsed.entities == ()
    assert parsed.notes["source_errors"] == ["anubis", "crtsh", "hackertarget", "shodanct"]


def test_subfinder_keeps_only_names_under_the_asked_domain():
    out = b'{"host":"a.example.com"}\n{"host":"a.example.org"}\n{"host":"xexample.com"}\n'
    parsed = subfinder.parse(out, {"domain": "example.com"})
    assert names(parsed) == ["a.example.com"] and parsed.skipped == 2


def test_subfinder_caps_results(monkeypatch):
    monkeypatch.setattr(subfinder, "MAX_ENTITIES", 3)
    out = b"".join(b'{"host":"h%d.example.com"}\n' % i for i in range(10))
    parsed = subfinder.parse(out, {"domain": "example.com"})
    assert len(parsed.entities) == 3 and parsed.capped


def test_subfinder_without_valid_params_is_a_bug():
    with pytest.raises(ValueError):
        subfinder.parse(b"", {})


@pytest.mark.parametrize(
    "output",
    [
        b"",
        b"\xff\xfe\x00garbage",
        b"{" * 100_000,
        b'{"host": "' + b"a" * 70_000 + b'.example.com"}',
        b"\n".join([b"[]", b"null", b"1", b'"x"', b"{}"]),
    ],
)
def test_parsers_never_raise_on_junk(output):
    subfinder.parse(output, {"domain": "example.com"})
    dnsx.parse(output, {"hosts": ["www.example.com"]})
    ct.parse(output, {"domain": "example.com"})
    nmap.parse(output, {"targets": ["203.0.113.0/24"]})


# --- dnsx ----------------------------------------------------------------------------------


ASKED = [
    "www.example.com",
    "example.com",
    "cdn.example.com",
    "mail.example.com",
    "v6.example.com",
    "bad.example.com",
    "loop.example.com",
    "cname-only.example.com",
    "nx.example.com",
    "huge.example.com",
    "cut.example.com",
]


def test_dnsx_recorded_output():
    parsed = dnsx.parse(fixture("dnsx", "example_com"), {"hosts": ASKED})
    assert_all_valid(parsed)
    assert names(parsed) == ["cdn.example.com", "example.com", "www.example.com"]
    ips = sorted(e.attributes["ip"] for e in parsed.entities if e.type == "host")
    assert ips == ["198.51.100.7", "2001:db8::10", "2001:db8::11", "203.0.113.10", "203.0.113.11"]
    cdn = next(e for e in parsed.entities if e.attributes.get("name") == "cdn.example.com")
    assert cdn.attributes == {
        "name": "cdn.example.com",
        "addresses": ["198.51.100.7"],
        "cnames": ["example.cdn.provider.net", "edge.provider.net"],
        "rcode": "NOERROR",
    }
    # Two names share addresses: one host entity each, one link per (name, address).
    assert len(parsed.links) == 9
    assert all(link.type == "resolves_to" for link in parsed.links)
    assert parsed.notes == {"answered": 3, "unresolved": 3}


def test_dnsx_edge_cases():
    parsed = dnsx.parse(fixture("dnsx", "edge_cases"), {"hosts": ASKED})
    assert_all_valid(parsed)
    by_name = {e.attributes["name"]: e.attributes for e in parsed.entities if e.type == "domain"}
    assert "other.example.net" not in by_name  # not asked for
    assert by_name["mail.example.com"]["addresses"] == ["203.0.113.20"]
    assert by_name["v6.example.com"]["addresses"] == ["2001:db8::1", "203.0.113.22"]
    assert by_name["bad.example.com"]["addresses"] == ["203.0.113.23"]
    assert by_name["loop.example.com"]["addresses"] == ["127.0.0.1"]  # data; the gate decides
    assert by_name["nx.example.com"] == {
        "name": "nx.example.com",
        "addresses": [],
        "cnames": [],
        "rcode": "NXDOMAIN",
    }
    assert len(by_name["huge.example.com"]["cnames"]) == dnsx.MAX_CNAMES
    assert "cut.example.com" not in by_name
    assert parsed.skipped == 3  # foreign name, null host, truncated line


def test_dnsx_without_hosts_is_a_bug():
    with pytest.raises(ValueError):
        dnsx.parse(b"", {"hosts": []})


def test_lines_helper_skips_overlong_lines():
    assert [line.text for line in common.lines(b"a\n" + b"x" * (common.MAX_LINE + 1))] == ["a"]


# --- cert_transparency (quiver-ct) ---------------------------------------------------------


def test_ct_recorded_output():
    parsed = ct.parse(fixture("quiver-ct", "example_com"), {"domain": "example.com"})
    assert_all_valid(parsed)
    assert names(parsed) == ["emudhra-lab.example.com", "example.com", "www.example.com"]
    apex = next(e.attributes for e in parsed.entities if e.attributes["name"] == "example.com")
    assert apex["ct_wildcard"] is True  # *.example.com certificates
    assert apex["ct_certs"] == 12 and len(apex["ct_issuers"]) == ct.MAX_ISSUERS
    assert apex["ct_first_not_before"] < apex["ct_last_not_after"]
    # user@example.com and "AS207960 Test Intermediate - example.com" are not domains.
    assert parsed.skipped == 2
    assert parsed.notes == {"names": 3, "certs": 16, "truncated": False, "errors": []}


def test_ct_edge_cases():
    parsed = ct.parse(fixture("quiver-ct", "edge_cases"), {"domain": "example.com"})
    assert_all_valid(parsed)
    by_name = {e.attributes["name"]: e.attributes for e in parsed.entities}
    assert sorted(by_name) == [
        "a.b.c.example.com",
        "dup.example.com",
        "example.com",  # from *.example.com and example.com in one certificate: counted once
        "www.example.com",  # case and trailing dot folded, counted once per certificate
        "xn--bcher-kva.example.com",
    ]
    assert by_name["example.com"]["ct_wildcard"] is True and by_name["example.com"]["ct_certs"] == 1
    assert by_name["www.example.com"]["ct_certs"] == 1
    assert by_name["dup.example.com"]["ct_issuers"] == ["CN=One", "CN=Two"]
    bucher = by_name["xn--bcher-kva.example.com"]
    assert bucher["ct_issuers"] == []  # over-long issuer dropped
    assert "ct_first_not_before" not in bucher and "ct_last_not_after" not in bucher
    # 11 unusable names (nested/bare wildcards, e-mail, free text, empty, foreign, lookalike,
    # non-strings), 2 unusable lines and the truncated last line.
    assert parsed.skipped == 14
    assert parsed.notes == {"names": 5, "certs": 9, "truncated": True, "errors": ["HTTP 503"]}


def test_ct_missing_summary_is_noted():
    parsed = ct.parse(b'{"type":"cert","names":["a.example.com"]}\n', {"domain": "example.com"})
    assert names(parsed) == ["a.example.com"] and parsed.notes["summary_missing"] is True


def test_ct_keeps_only_names_under_the_asked_domain():
    out = b'{"type":"cert","names":["a.example.com","a.example.org","*.xexample.com"]}\n'
    parsed = ct.parse(out, {"domain": "a.example.com"})
    assert names(parsed) == ["a.example.com"] and parsed.skipped == 2


def test_ct_caps_results(monkeypatch):
    monkeypatch.setattr(ct, "MAX_ENTITIES", 3)
    out = b'{"type":"cert","names":[%s]}' % b",".join(b'"h%d.example.com"' % i for i in range(10))
    parsed = ct.parse(out, {"domain": "example.com"})
    assert len(parsed.entities) == 3 and parsed.capped


def test_ct_without_valid_params_is_a_bug():
    with pytest.raises(ValueError):
        ct.parse(b"", {"domain": "*.example.com"})


# --- port_scan (nmap XML) --------------------------------------------------------------------

LAB = {"targets": ["www.example.com", "203.0.113.11"], "ports": [22, 80, 443, 6379, 8080]}
LAB_PINS = {"www.example.com": ["203.0.113.10", "2001:db8::10"]}


def by_type(parsed, entity_type):
    return [e.attributes for e in parsed.entities if e.type == entity_type]


def test_nmap_recorded_output():
    parsed = nmap.parse(fixture("nmap", "lab"), LAB, resolutions=LAB_PINS)
    assert_all_valid(parsed)
    assert by_type(parsed, "host") == [
        {"ip": "203.0.113.10", "nmap_state": "up"},
        {"ip": "203.0.113.11", "nmap_state": "up"},
    ]
    services = {s["port"]: s for s in by_type(parsed, "service")}
    assert set(services) == {80, 6379}  # open ports only
    assert services[80] == {
        "ip": "203.0.113.10",
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "reason": "syn-ack",
        "name": "http",
        "product": "nginx",
        "version": "1.27.5",
        "cpe": ["cpe:/a:igor_sysoev:nginx:1.27.5"],
    }
    assert services[6379]["product"] == "Redis key-value store"
    assert by_type(parsed, "domain") == [{"name": "www.example.com"}]
    links = sorted(
        (link.type, link.source.attributes.get("name") or link.source.attributes["ip"])
        for link in parsed.links
    )
    assert links == [
        ("exposes", "203.0.113.10"),
        ("exposes", "203.0.113.11"),
        ("resolves_to", "www.example.com"),
    ]
    assert parsed.skipped == 0
    assert parsed.notes == {
        "hosts_up": 2,
        "hosts_down": 0,
        "open": 2,
        "closed": 8,
        "filtered": 0,
        "finished": "success",
    }


def test_nmap_keeps_only_addresses_it_was_given():
    # Without the pin for www.example.com, 203.0.113.10 is not something the job was given.
    parsed = nmap.parse(fixture("nmap", "lab"), LAB)
    assert [h["ip"] for h in by_type(parsed, "host")] == ["203.0.113.11"]
    assert parsed.skipped == 1 and by_type(parsed, "domain") == []


def test_nmap_truncated_report_keeps_complete_hosts():
    parsed = nmap.parse(fixture("nmap", "truncated"), {"targets": ["203.0.113.10", "203.0.113.11"]})
    assert_all_valid(parsed)
    assert [h["ip"] for h in by_type(parsed, "host")] == ["203.0.113.10"]
    assert parsed.notes["finished"] is None  # nmap did not finish writing


def test_nmap_edge_cases():
    params = {
        "targets": [
            "203.0.113.20",
            "203.0.113.21",
            "203.0.113.22",
            "203.0.113.23",
            "203.0.113.32/28",
        ]
    }
    parsed = nmap.parse(fixture("nmap", "edge_cases"), params)
    assert_all_valid(parsed)
    hosts = {h["ip"]: h["nmap_state"] for h in by_type(parsed, "host")}
    assert hosts == {
        "203.0.113.20": "up",  # filtered and closed ports only
        "203.0.113.21": "up",
        "203.0.113.23": "up",  # a stray stderr line inside the host is just text
        "203.0.113.40": "up",  # inside the 203.0.113.32/28 target
        "203.0.113.41": "down",
    }
    services = {(s["ip"], s["port"]): s for s in by_type(parsed, "service")}
    assert set(services) == {("203.0.113.21", 8443), ("203.0.113.23", 80), ("203.0.113.40", 3306)}
    odd = services[("203.0.113.21", 8443)]
    assert len(odd["product"]) == nmap.MAX_FIELD and odd["version"] == "1.0 <script>"
    assert odd["tunnel"] == "ssl" and len(odd["cpe"]) == nmap.MAX_CPES
    # Skipped: a host not in the input, UDP, port 0, a non-numeric port, an undefined entity,
    # a MAC-only address, IPv6 in an IPv4 scan. The cut-off last host is not a complete element.
    assert parsed.skipped == 7
    assert parsed.notes["filtered"] == 2 and parsed.notes["closed"] == 1
    assert parsed.notes["finished"] is None


def test_nmap_refuses_entity_declarations():
    doc = (
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]>'
        b'<host><status state="up"/><address addr="203.0.113.10" addrtype="ipv4"/></host>'
    )
    parsed = nmap.parse(doc, {"targets": ["203.0.113.10"]})
    assert parsed.entities == () and parsed.notes == {"refused": "entity declaration in the report"}


def test_nmap_ipv6_scan():
    doc = (
        b'<host><status state="up"/><address addr="2001:DB8::10" addrtype="ipv6"/><ports>'
        b'<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port>'
        b"</ports></host>"
    )
    parsed = nmap.parse(doc, {"targets": ["www.example.com"], "ipv6": True}, resolutions=LAB_PINS)
    assert_all_valid(parsed)
    assert [h["ip"] for h in by_type(parsed, "host")] == ["2001:db8::10"]
    assert [s["port"] for s in by_type(parsed, "service")] == [443]


def test_nmap_caps_results(monkeypatch):
    monkeypatch.setattr(nmap, "MAX_ENTITIES", 3)
    parsed = nmap.parse(fixture("nmap", "lab"), LAB, resolutions=LAB_PINS)
    assert parsed.capped and len(parsed.entities) <= 3


def test_nmap_without_valid_params_is_a_bug():
    with pytest.raises(ValueError):
        nmap.parse(b"", {"targets": []})
