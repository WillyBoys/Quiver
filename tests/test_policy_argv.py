"""Target extraction from argv: what the gate scope-checks beyond declared parameters."""

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from quiver.core.policy.argv import extract_targets


def ex(*args):
    return extract_targets(["tool", *args])


def test_program_name_and_flags_are_skipped():
    e = extract_targets(["evil.example.com", "-sV", "--open", "-T4", "80", "1000"])
    assert e == ex()  # nothing extracted
    assert e.definite == () and e.possible_hosts == () and e.uncertain == ()


@pytest.mark.parametrize(
    ("args", "definite"),
    [
        (["203.0.113.5"], ("203.0.113.5",)),
        (["203.0.113.0/24"], ("203.0.113.0/24",)),
        (["203.0.113.5/32"], ("203.0.113.5",)),
        (["2001:db8::1"], ("2001:db8::1",)),
        (["[2001:db8::1]:8443"], ("2001:db8::1",)),
        (["203.0.113.5:8080"], ("203.0.113.5",)),
        (["--target=203.0.113.5"], ("203.0.113.5",)),
        (["203.0.113.5,203.0.113.6"], ("203.0.113.5", "203.0.113.6")),
        (["root@203.0.113.5"], ("203.0.113.5",)),
        (["https://a.example.com/x?y=1"], ("https://a.example.com/x?y=1",)),
        (["-uhttps://a.example.com/"], ("https://a.example.com/",)),
        (["--url=http://a.example.com/"], ("http://a.example.com/",)),
        (["ftp://files.example.com/"], ("ftp://files.example.com/",)),
    ],
)
def test_definite_targets(args, definite):
    assert ex(*args).definite == definite


@pytest.mark.parametrize(
    ("args", "possible"),
    [
        (["www.example.com"], ("www.example.com",)),
        (["WWW.Example.COM."], ("www.example.com",)),
        (["www.example.com:443"], ("www.example.com",)),
        (["admin@mail.example.com"], ("mail.example.com",)),
        (["Host: evil.example.net"], ("evil.example.net",)),
        (["-H", "Host:evil.example.net"], ("evil.example.net",)),
        (["example.com/admin"], ("example.com",)),
        (["out.sh"], ("out.sh",)),  # .sh is a real TLD: could be a host
        (["bücher.example"], ()),  # .example is not a delegated TLD
        (["bücher.de"], ("xn--bcher-kva.de",)),
    ],
)
def test_possible_hosts(args, possible):
    assert ex(*args).possible_hosts == possible


@pytest.mark.parametrize(
    "arg",
    ["report.xml", "results.json", "/data/jobs/1/nmap.xml", "./out.sh", "../x.sh", "~/a.com"],
)
def test_file_names_and_paths_are_not_targets(arg):
    e = ex(arg)
    assert e.definite == () and e.possible_hosts == () and e.uncertain == ()


@pytest.mark.parametrize("arg", ["1.5", "0x7f.1", "10.1", "127.1", "0x7f000001", "fe80::1%eth0"])
def test_ambiguous_address_forms_are_uncertain(arg):
    e = ex(arg)
    assert e.uncertain, arg
    assert e.definite == ()


def test_unicode_garbage_is_uncertain():
    assert ex("x.‮.com").uncertain


def test_duplicates_are_reported_once():
    assert ex("203.0.113.5", "203.0.113.5:80").definite == ("203.0.113.5",)


@given(st.ip_addresses(), st.sampled_from(["{}", "--t={}", "{}:80", "a,{},b", "user@{}"]))
def test_any_embedded_ip_is_extracted(ip, template):
    text = f"[{ip}]" if ip.version == 6 and template in ("{}:80",) else str(ip)
    e = ex(template.format(text))
    found = {ipaddress.ip_address(t) for t in e.definite if "/" not in t and "://" not in t}
    assert ip in found or e.uncertain
