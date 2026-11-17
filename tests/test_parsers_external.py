"""External track parsers against recorded tool output (tests/fixtures/tools/).

example_com.log files are recorded from the pinned tool versions (and quiver-ct against crt.sh)
for example.com (a documentation domain; dnsx addresses replaced with documentation ranges).
edge_cases.log and all_sources_failed.log are hand-made in the same format: what hostile or
broken output can look like.
"""

from pathlib import Path

import pytest

from quiver.core.graph.types import default_graph
from quiver.worker.tracks.external.parsers import (
    common,
    ct,
    dnsx,
    httpx,
    nmap,
    nuclei,
    subfinder,
    tlsx,
)

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
    httpx.parse(output, {"host": "203.0.113.10"})
    tlsx.parse(output, {"host": "203.0.113.10"})
    nuclei.parse(output, {"url": "http://203.0.113.10/"})


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


# --- http_probe (httpx) ------------------------------------------------------------------------

WWW = {"www.example.com": ["203.0.113.10"]}


def test_httpx_recorded_output():
    params = {"host": "www.example.com", "ports": [80, 443, 8080]}
    parsed = httpx.parse(fixture("httpx", "lab"), params, resolutions=WWW)
    assert_all_valid(parsed)
    endpoints = {e["url"]: e for e in by_type(parsed, "web_endpoint")}
    assert set(endpoints) == {"http://www.example.com:80/", "https://www.example.com:443/"}
    https = endpoints["https://www.example.com:443/"]
    assert https["title"] == "WWW Example" and https["webserver"] == "nginx/1.27.5"
    assert https["tech"] == ["MySQL", "Nginx:1.27.5", "PHP:8.2.1", "WordPress:6.4.2"]
    assert https["tls_sha256"] == "d3e14c563664d59b7e649bc8e25a7a81d3f2d79423ade5911843d068d7423aed"
    assert https["ip"] == "203.0.113.10" and https["status_code"] == 200
    assert sorted((s["port"]) for s in by_type(parsed, "service")) == [80, 443]
    assert by_type(parsed, "domain") == [{"name": "www.example.com"}]
    assert sorted(link.type for link in parsed.links) == ["on_domain"] * 2 + ["serves"] * 2
    assert parsed.notes == {"endpoints": 2, "failed": 0, "redirects_to": []}


def test_httpx_off_site_redirect_becomes_an_entity_to_scope_check():
    parsed = httpx.parse(
        fixture("httpx", "redirect"),
        {"host": "go.example.com", "ports": [80]},
        resolutions={"go.example.com": ["203.0.113.10"]},
    )
    assert_all_valid(parsed)
    [endpoint] = by_type(parsed, "web_endpoint")
    assert endpoint["status_code"] == 301
    assert endpoint["location"] == "https://evil.example.org/landing?from=go"
    assert {d["name"] for d in by_type(parsed, "domain")} == {"go.example.com", "evil.example.org"}
    assert parsed.notes["redirects_to"] == ["evil.example.org"]


def test_httpx_edge_cases():
    parsed = httpx.parse(
        fixture("httpx", "edge_cases"), {"host": "www.example.com"}, resolutions=WWW
    )
    assert_all_valid(parsed)
    endpoints = {e["url"]: e for e in by_type(parsed, "web_endpoint")}
    odd = endpoints["https://www.example.com:8443/"]
    assert len(odd["title"]) == 200 and "tech" not in odd and "status_code" not in odd
    assert "tls_sha256" not in odd and odd["location"] == "/login"
    # Redirects: same host and javascript: make nothing; another host or an IP does.
    assert {d["name"] for d in by_type(parsed, "domain")} == {"www.example.com", "evil.example.org"}
    assert by_type(parsed, "host") == [{"ip": "198.51.100.20"}]
    assert parsed.notes["redirects_to"] == ["198.51.100.20", "evil.example.org"]  # not ftp://
    # Skipped: an address not given to the job, ftp, two bad ports, the cut-off last line.
    assert parsed.skipped == 5 and parsed.notes["failed"] == 1


def test_httpx_on_an_address_has_no_domain():
    parsed = httpx.parse(fixture("httpx", "lab"), {"host": "203.0.113.10"})
    assert {e["url"] for e in by_type(parsed, "web_endpoint")} == {
        "http://203.0.113.10:80/",
        "https://203.0.113.10:443/",
    }
    assert by_type(parsed, "domain") == [] and {link.type for link in parsed.links} == {"serves"}


def test_httpx_ignores_answers_from_addresses_it_was_not_given():
    parsed = httpx.parse(fixture("httpx", "lab"), {"host": "www.example.com"})  # no pins
    assert parsed.entities == () and parsed.skipped == 2


# --- tls_scan (tlsx) ---------------------------------------------------------------------------


def test_tlsx_recorded_output():
    params = {"host": "www.example.com", "ports": [443, 80]}
    parsed = tlsx.parse(fixture("tlsx", "lab"), params, resolutions=WWW)
    assert_all_valid(parsed)
    [cert] = by_type(parsed, "certificate")
    assert cert["sha256"] == "d3e14c563664d59b7e649bc8e25a7a81d3f2d79423ade5911843d068d7423aed"
    assert cert["subject_cn"] == "www.example.com" and cert["self_signed"] is True
    assert cert["san"] == ["www.example.com", "api.example.com"]
    [svc] = by_type(parsed, "service")
    assert svc["port"] == 443 and svc["tls_version"] == "tls13"
    assert svc["tls_versions"] == ["tls12", "tls13"]
    assert len(svc["tls_ciphers"]["weak"]) == 8 and len(svc["tls_ciphers"]["secure"]) == 3
    assert {d["name"] for d in by_type(parsed, "domain")} == {"www.example.com", "api.example.com"}
    assert sorted(link.type for link in parsed.links) == ["names", "names", "presents"]
    assert parsed.notes == {"certificates": 1, "no_tls_ports": [80]}


def test_tlsx_edge_cases():
    parsed = tlsx.parse(fixture("tlsx", "edge_cases"), {"host": "www.example.com"}, resolutions=WWW)
    assert_all_valid(parsed)
    [cert] = by_type(parsed, "certificate")
    assert cert["expired"] is True and "self_signed" not in cert
    services = {s["port"]: s for s in by_type(parsed, "service")}
    assert set(services) == {443, 9443}
    assert services[443]["tls_versions"] == ["tls10", "tls12"]  # tls99 dropped
    assert services[443]["tls_ciphers"] == {
        "insecure": ["TLS_RSA_WITH_RC4_128_SHA"],
        "weak": ["AES128-SHA", "AES256-SHA"],
        "secure": ["ECDHE-RSA-AES128-GCM-SHA256"],
    }
    # *.example.com names example.com; free text and e-mail addresses name nothing.
    assert {d["name"] for d in by_type(parsed, "domain")} == {
        "www.example.com",
        "example.com",
        "other.example.net",
    }
    # Skipped: an address not given, no fingerprint, the cut-off last line.
    assert parsed.skipped == 3 and parsed.notes["no_tls_ports"] == [8443]


def test_tlsx_bad_timestamp_is_dropped():
    line = (
        b'{"ip":"203.0.113.10","port":"443","probe_status":true,"not_after":"soon",'
        b'"fingerprint_hash":{"sha256":"' + b"b" * 64 + b'"}}'
    )
    [cert] = by_type(tlsx.parse(line, {"host": "203.0.113.10"}), "certificate")
    assert cert == {"sha256": "b" * 64}


# --- nuclei_scan (nuclei through quiver-bind) ---------------------------------------------------

NUCLEI = {"url": "http://www.example.com/"}


def assert_findings_valid(parsed):
    from quiver.core.graph import keys

    for f in parsed.findings:
        entity_key = GRAPH.entity(f.entity.type).key(f.entity.attributes)
        keys.finding_key(f.issue_type, entity_key, f.location)


def test_nuclei_recorded_output():
    parsed = nuclei.parse(fixture("nuclei", "lab"), NUCLEI, resolutions=WWW)
    assert_all_valid(parsed)
    assert_findings_valid(parsed)
    assert {e["url"] for e in by_type(parsed, "web_endpoint")} == {
        "http://www.example.com:80/",
        "http://www.example.com:80/.git/config",
    }
    assert parsed.notes == {"matches": 16, "by_severity": {"info": 15, "medium": 1}}
    git = next(f for f in parsed.findings if f.issue_type == "git-config")
    assert git.severity == "medium" and git.title == "Git Configuration - Detect"
    assert git.entity.attributes["url"] == "http://www.example.com:80/.git/config"
    assert git.details["cwe"] == ["cwe-200"] and git.details["cvss_score"] == 5.3
    assert "matched-at: http://203.0.113.10:80/.git/config" in git.evidence[0].excerpt
    headers = [f for f in parsed.findings if f.issue_type == "http-missing-security-headers"]
    assert len(headers) == 10 and len({f.location for f in headers}) == 10  # one per header
    version = next(f for f in parsed.findings if f.issue_type == "nginx-version")
    assert version.location == "" and version.details["extracted"] == ["nginx/1.27.5"]
    assert sorted(link.type for link in parsed.links) == ["on_domain"] * 2 + ["serves"] * 2


def test_nuclei_finding_identity_is_stable_across_runs():
    from quiver.core.graph import keys

    def ids(parsed):
        return sorted(
            keys.finding_key(
                f.issue_type, GRAPH.entity(f.entity.type).key(f.entity.attributes), f.location
            )
            for f in parsed.findings
        )

    first = nuclei.parse(fixture("nuclei", "lab"), NUCLEI, resolutions=WWW)
    again = nuclei.parse(fixture("nuclei", "lab"), NUCLEI, resolutions=WWW)
    assert ids(first) == ids(again) and len(set(ids(first))) == 16
    assert "finding:git-config|web_endpoint:http://www.example.com:80/.git/config|" in ids(first)


def test_nuclei_edge_cases():
    parsed = nuclei.parse(fixture("nuclei", "edge_cases"), NUCLEI, resolutions=WWW)
    assert_all_valid(parsed)
    assert_findings_valid(parsed)
    by_id = {f.issue_type: f for f in parsed.findings}
    assert set(by_id) == {"odd-sev", "big-extract", "no-info", "other-port", "dup"}
    assert by_id["odd-sev"].severity == "info"  # unknown severity
    assert by_id["no-info"].title == "no-info" and by_id["no-info"].severity == "info"
    extracted = by_id["big-extract"].details["extracted"]
    assert extracted == ["v" * 200]  # truncated, deduplicated
    # A template may probe another port on the pinned address: recorded under that port.
    assert by_id["other-port"].entity.attributes["url"] == "http://www.example.com:5814/autopass"
    assert {s["port"] for s in by_type(parsed, "service")} == {80, 5814}
    # Skipped: an address not given, a DNS match, a | in the id, a non-URL, the cut-off line.
    assert parsed.skipped == 5 and parsed.notes["matches"] == 5


def test_nuclei_ignores_matches_from_addresses_it_was_not_given():
    parsed = nuclei.parse(fixture("nuclei", "lab"), NUCLEI)  # no pins known
    assert parsed.findings == () and parsed.skipped == 16
