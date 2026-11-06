"""DNS resolution for the policy gate (Blueprint §4.1: wildcards cover names, not
infrastructure; resolution pinning).

The gate itself stays pure: the store resolves the names a request touches through a
`Resolver` and passes the `Resolution`s in. Tests use `StaticResolver`; nothing in the test
suite touches the network.
"""

import asyncio
import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class Resolution:
    name: str
    addresses: tuple[IPAddress, ...] = ()
    cnames: tuple[str, ...] = ()  # the CNAME chain, in order, without trailing dots
    error: str | None = None  # NXDOMAIN, timeout, ...; addresses are then empty

    @property
    def address_strings(self) -> tuple[str, ...]:
        return tuple(str(a) for a in self.addresses)


class Resolver(Protocol):
    async def resolve(self, name: str) -> Resolution: ...


async def resolve_all(resolver: Resolver, names: Iterable[str]) -> dict[str, Resolution]:
    names = sorted(set(names))
    results = await asyncio.gather(*(resolver.resolve(n) for n in names))
    return dict(zip(names, results, strict=True))


class StaticResolver:
    """Answers from a fixed table. Unknown names resolve as NXDOMAIN."""

    def __init__(self, table: Mapping[str, Resolution | Iterable[str]]):
        self._table = {
            name: v
            if isinstance(v, Resolution)
            else Resolution(name, tuple(ipaddress.ip_address(a) for a in v))
            for name, v in table.items()
        }

    async def resolve(self, name: str) -> Resolution:
        return self._table.get(name, Resolution(name, error="NXDOMAIN"))


class DnsResolver:
    """A and AAAA lookups through the system's configured name servers. Never raises."""

    def __init__(self, timeout: float = 3.0):
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout

    async def resolve(self, name: str) -> Resolution:
        addresses: list[IPAddress] = []
        cnames: list[str] = []
        errors: list[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                answer = await self._resolver.resolve(name, rdtype, search=False)
            except dns.resolver.NXDOMAIN:
                return Resolution(name, error="NXDOMAIN")
            except dns.resolver.NoAnswer:
                continue
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                errors.append(f"{rdtype}: {type(exc).__name__}")
                continue
            except dns.exception.DNSException as exc:
                errors.append(f"{rdtype}: {type(exc).__name__}")
                continue
            for rrset in answer.chaining_result.cnames:
                for rr in rrset:
                    target = str(rr.target).rstrip(".").lower()
                    if target not in cnames:
                        cnames.append(target)
            addresses.extend(ipaddress.ip_address(rr.address) for rr in answer)
        if errors and not addresses:
            return Resolution(name, cnames=tuple(cnames), error="; ".join(errors))
        # A partial failure (e.g. AAAA timed out) still leaves the answer incomplete, so the
        # error is kept and the gate treats the resolution as uncertain.
        return Resolution(
            name,
            tuple(dict.fromkeys(addresses)),
            tuple(cnames),
            "; ".join(errors) or None,
        )
