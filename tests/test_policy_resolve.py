"""DnsResolver: answers, CNAME chains, and error mapping, with dnspython stubbed (no network)."""

import ipaddress
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from quiver.core.policy.resolve import DnsResolver, Resolution, StaticResolver, resolve_all


class FakeAnswer(list):
    def __init__(self, addresses, cnames=()):
        super().__init__(SimpleNamespace(address=a) for a in addresses)
        rrsets = [[SimpleNamespace(target=f"{c}.")] for c in cnames]
        self.chaining_result = SimpleNamespace(cnames=rrsets)


def resolver_with(table):
    """table: {rdtype: FakeAnswer | exception instance}"""
    r = DnsResolver()

    async def resolve(name, rdtype, search=False):
        outcome = table[rdtype]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    r._resolver = SimpleNamespace(resolve=resolve)
    return r


async def test_a_and_aaaa_with_cname_chain():
    r = resolver_with(
        {
            "A": FakeAnswer(["203.0.113.5"], cnames=["edge.Example.NET", "d1.cloudfront.net"]),
            "AAAA": FakeAnswer(["2001:db8::5"], cnames=["edge.example.net"]),
        }
    )
    res = await r.resolve("www.example.com")
    assert res.address_strings == ("203.0.113.5", "2001:db8::5")
    assert res.cnames == ("edge.example.net", "d1.cloudfront.net")
    assert res.error is None


async def test_no_aaaa_is_not_an_error():
    r = resolver_with({"A": FakeAnswer(["203.0.113.5"]), "AAAA": dns.resolver.NoAnswer()})
    res = await r.resolve("www.example.com")
    assert res.address_strings == ("203.0.113.5",) and res.error is None


async def test_nxdomain():
    r = resolver_with({"A": dns.resolver.NXDOMAIN(), "AAAA": dns.resolver.NXDOMAIN()})
    assert await r.resolve("gone.example.com") == Resolution("gone.example.com", error="NXDOMAIN")


async def test_timeout_everywhere_is_an_error_without_addresses():
    r = resolver_with({"A": dns.exception.Timeout(), "AAAA": dns.exception.Timeout()})
    res = await r.resolve("slow.example.com")
    assert res.addresses == () and "Timeout" in res.error


async def test_partial_failure_keeps_addresses_and_the_error():
    r = resolver_with({"A": FakeAnswer(["203.0.113.5"]), "AAAA": dns.resolver.NoNameservers()})
    res = await r.resolve("www.example.com")
    assert res.address_strings == ("203.0.113.5",)
    assert "NoNameservers" in res.error  # the gate treats this as uncertain


@pytest.mark.parametrize("exc", [dns.resolver.NoAnswer(), dns.exception.DNSException()])
async def test_never_raises(exc):
    r = resolver_with({"A": exc, "AAAA": exc})
    res = await r.resolve("x.example.com")
    assert res.addresses == ()


async def test_static_resolver_and_resolve_all():
    static = StaticResolver({"a.example.com": ["203.0.113.1"]})
    out = await resolve_all(static, ["a.example.com", "b.example.com", "a.example.com"])
    assert out["a.example.com"].addresses == (ipaddress.ip_address("203.0.113.1"),)
    assert out["b.example.com"].error == "NXDOMAIN"
