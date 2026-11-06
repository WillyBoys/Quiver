"""Gate DNS rules (Blueprint §4.1): where in-scope hostnames lead. Pure: answers are given."""

import ipaddress
import uuid
from dataclasses import replace
from datetime import UTC, date, datetime, time

import pytest

from quiver.core.models import EngagementStatus
from quiver.core.policy import (
    RUN_COMMAND,
    ActionRequest,
    AuthorizationPeriod,
    GateContext,
    RiskTier,
    TargetParam,
    ToolRegistry,
    ToolSpec,
    Verdict,
    WindowSpec,
    effective_autonomy,
    evaluate,
)
from quiver.core.policy.gate import MAX_RESOLVE, hostnames_to_resolve
from quiver.core.policy.providers import ProviderIndex
from quiver.core.policy.resolve import Resolution
from quiver.core.scope import ScopeKind, ScopeMode
from quiver.core.scope_match import Scope, ScopeRule

CDN_IP = "13.32.1.1"
PUBLIC_IP = "93.184.215.14"  # public, not a known provider in the test index
PROVIDERS = ProviderIndex({"aws": ["13.32.0.0/15"]}, {"aws": ["cloudfront.net"]})

SCOPE = Scope(
    [
        ScopeRule(ScopeKind.WILDCARD, "*.example.com", ScopeMode.INCLUDE),
        ScopeRule(ScopeKind.HOSTNAME, "shop.example.com", ScopeMode.INCLUDE),
        ScopeRule(ScopeKind.CIDR, "203.0.113.0/24", ScopeMode.INCLUDE),
        ScopeRule(ScopeKind.CIDR, "10.20.0.0/16", ScopeMode.INCLUDE),
        ScopeRule(ScopeKind.IP, "203.0.113.99", ScopeMode.EXCLUDE),
    ]
)
REGISTRY = ToolRegistry(
    [
        RUN_COMMAND,
        ToolSpec("port_scan", RiskTier.DISCOVERY, {"targets": TargetParam()}),
        ToolSpec("nuclei_scan", RiskTier.DISCOVERY, {"url": TargetParam()}),
        ToolSpec("dns_resolve", RiskTier.PASSIVE, {"name": TargetParam()}),
    ]
)
BASE = GateContext(
    now=datetime(2026, 11, 4, 15, 0, tzinfo=UTC),
    engagement_status=EngagementStatus.ACTIVE,
    registry=REGISTRY,
    authorization=AuthorizationPeriod(date(2026, 10, 1), None),
    scope=SCOPE,
    autonomy=effective_autonomy({}),
    windows=(WindowSpec("UTC", frozenset(range(1, 8)), time(0), time(0)),),
    providers=PROVIDERS,
)


def answer(host, *ips, cnames=(), error=None):
    return Resolution(host, tuple(ipaddress.ip_address(i) for i in ips), tuple(cnames), error)


def ctx(*answers, **changes):
    return replace(BASE, resolutions={a.name: a for a in answers}, **changes)


def scan(host):
    return ActionRequest(uuid.uuid4(), "port_scan", {"targets": host}, ("nmap", host), "t")


def resolution_reasons(d):
    return [c.reason for c in d.checks if c.name == "resolution"]


# --- wildcards cover names, not infrastructure ----------------------------------------------


def test_wildcard_name_on_public_non_provider_address_is_allowed_and_pinned():
    d = evaluate(scan("www.example.com"), ctx(answer("www.example.com", PUBLIC_IP)))
    assert d.verdict is Verdict.ALLOW
    assert d.new_pins == (("www.example.com", (PUBLIC_IP,)),)
    assert d.resolutions == d.new_pins


def test_wildcard_name_on_provider_address_is_denied_and_suggested():
    d = evaluate(scan("cdn.example.com"), ctx(answer("cdn.example.com", CDN_IP)))
    assert d.verdict is Verdict.DENY
    assert "hosted by aws" in d.reason
    assert [(s.kind, s.value) for s in d.suggest] == [(ScopeKind.HOSTNAME, "cdn.example.com")]
    assert d.new_pins == ()


def test_wildcard_name_with_provider_cname_is_denied():
    d = evaluate(
        scan("img.example.com"),
        ctx(answer("img.example.com", PUBLIC_IP, cnames=["d111.cloudfront.net"])),
    )
    assert d.verdict is Verdict.DENY


def test_in_scope_address_wins_over_provider_evidence():
    d = evaluate(
        scan("img.example.com"),
        ctx(answer("img.example.com", "203.0.113.10", cnames=["d111.cloudfront.net"])),
    )
    assert d.verdict is Verdict.ALLOW


def test_exact_hostname_entry_skips_the_third_party_rule():
    d = evaluate(scan("shop.example.com"), ctx(answer("shop.example.com", CDN_IP)))
    assert d.verdict is Verdict.ALLOW


def test_missing_provider_data_asks_for_wildcard_names_only():
    no_data = {"providers": None}
    d = evaluate(scan("www.example.com"), ctx(answer("www.example.com", PUBLIC_IP), **no_data))
    assert d.verdict is Verdict.NEEDS_APPROVAL
    d = evaluate(scan("shop.example.com"), ctx(answer("shop.example.com", PUBLIC_IP), **no_data))
    assert d.verdict is Verdict.ALLOW


def test_url_targets_resolve_their_host():
    request = ActionRequest(
        uuid.uuid4(), "nuclei_scan", {"url": "https://cdn.example.com/x"}, (), "t"
    )
    assert hostnames_to_resolve(request, BASE) == {"cdn.example.com"}
    assert evaluate(request, ctx(answer("cdn.example.com", CDN_IP))).verdict is Verdict.DENY


# --- addresses that are never acceptable ----------------------------------------------------


@pytest.mark.parametrize(
    "ip", ["169.254.169.254", "127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1"]
)
def test_forbidden_addresses_are_denied_even_for_exact_names(ip):
    d = evaluate(scan("shop.example.com"), ctx(answer("shop.example.com", ip)))
    assert d.verdict is Verdict.DENY
    assert "never testable" in d.reason


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.1.1", "172.16.0.5", "100.64.1.1", "fd00::1"])
def test_uncovered_private_addresses_are_denied(ip):
    d = evaluate(scan("shop.example.com"), ctx(answer("shop.example.com", ip)))
    assert d.verdict is Verdict.DENY
    assert "private or non-public" in d.reason


def test_private_address_covered_by_an_include_is_allowed():
    d = evaluate(scan("intranet.example.com"), ctx(answer("intranet.example.com", "10.20.1.1")))
    assert d.verdict is Verdict.ALLOW


def test_excluded_address_is_denied():
    d = evaluate(scan("www.example.com"), ctx(answer("www.example.com", "203.0.113.99")))
    assert d.verdict is Verdict.DENY
    assert "excluded" in d.reason


def test_one_bad_address_among_good_ones_denies():
    d = evaluate(
        scan("www.example.com"),
        ctx(answer("www.example.com", "203.0.113.10", "169.254.169.254")),
    )
    assert d.verdict is Verdict.DENY


def test_deny_cannot_be_approved():
    d = evaluate(scan("www.example.com"), ctx(answer("www.example.com", "10.1.1.1")), approved=True)
    assert d.verdict is Verdict.DENY


# --- resolution failures --------------------------------------------------------------------


@pytest.mark.parametrize(
    "res",
    [
        answer("www.example.com", error="NXDOMAIN"),
        answer("www.example.com", PUBLIC_IP, error="AAAA: Timeout"),  # partial answer
        answer("www.example.com"),  # no addresses
    ],
)
def test_unresolvable_names_need_approval(res):
    d = evaluate(scan("www.example.com"), ctx(res))
    assert d.verdict is Verdict.NEEDS_APPROVAL
    assert d.new_pins == ()


def test_name_missing_from_resolutions_needs_approval():
    assert evaluate(scan("www.example.com"), ctx()).verdict is Verdict.NEEDS_APPROVAL


# --- pinning --------------------------------------------------------------------------------


def pins(host, *ips):
    return {"pins": {host: frozenset(ips)}}


def test_same_answer_as_pin_is_allowed_without_repinning():
    d = evaluate(
        scan("www.example.com"),
        ctx(answer("www.example.com", PUBLIC_IP), **pins("www.example.com", PUBLIC_IP)),
    )
    assert d.verdict is Verdict.ALLOW
    assert d.new_pins == ()
    assert d.resolutions == (("www.example.com", (PUBLIC_IP,)),)


def test_subset_of_pin_is_allowed():
    d = evaluate(
        scan("www.example.com"),
        ctx(answer("www.example.com", PUBLIC_IP), **pins("www.example.com", PUBLIC_IP, "1.1.1.1")),
    )
    assert d.verdict is Verdict.ALLOW


def test_new_address_needs_approval_and_approval_allows_it():
    context = ctx(
        answer("www.example.com", PUBLIC_IP, "93.184.215.15"),
        **pins("www.example.com", PUBLIC_IP),
    )
    d = evaluate(scan("www.example.com"), context)
    assert d.verdict is Verdict.NEEDS_APPROVAL
    assert "93.184.215.15" in d.reason
    assert evaluate(scan("www.example.com"), context, approved=True).verdict is Verdict.ALLOW


def test_new_private_address_is_denied_not_asked():
    context = ctx(answer("www.example.com", "10.9.9.9"), **pins("www.example.com", PUBLIC_IP))
    assert evaluate(scan("www.example.com"), context).verdict is Verdict.DENY


# --- what is resolved -----------------------------------------------------------------------


def test_passive_tools_resolve_nothing():
    request = ActionRequest(uuid.uuid4(), "dns_resolve", {"name": "www.example.com"}, (), "t")
    assert hostnames_to_resolve(request, BASE) == set()
    d = evaluate(request, ctx())
    assert d.verdict is Verdict.ALLOW
    assert resolution_reasons(d) == []


def test_ips_and_out_of_scope_names_are_not_resolved():
    request = ActionRequest(
        uuid.uuid4(), "run_command", {}, ("curl", "203.0.113.5", "evil.other.net"), "t"
    )
    assert hostnames_to_resolve(request, BASE) == set()


def test_too_many_names_are_not_resolved():
    hosts = [f"h{i}.example.com" for i in range(MAX_RESOLVE + 1)]
    request = ActionRequest(uuid.uuid4(), "run_command", {}, ("dig", *hosts), "t")
    assert hostnames_to_resolve(request, BASE) == set()
    d = evaluate(request, ctx())
    assert d.verdict is Verdict.NEEDS_APPROVAL
    assert any("more than the gate resolves" in r for r in resolution_reasons(d))
