"""External track parsers against recorded tool output (tests/fixtures/tools/).

example_com.log files are recorded from the pinned tool versions against example.com (a
documentation domain; dnsx addresses replaced with documentation ranges). edge_cases.log and
all_sources_failed.log are hand-made in the same format: what hostile or broken output can
look like.
"""

from pathlib import Path

import pytest

from quiver.core.graph.types import default_graph
from quiver.worker.tracks.external.parsers import common, dnsx, subfinder

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
