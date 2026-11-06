"""Policy gate: evaluate() is pure, so every rule is tested against a hand-built context."""

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
    Autonomy,
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
from quiver.core.policy.providers import ProviderIndex
from quiver.core.policy.resolve import Resolution
from quiver.core.scope import ScopeKind, ScopeMode
from quiver.core.scope_match import Scope, ScopeRule

# Wednesday 2026-11-04 15:00 UTC = 09:00 in Chicago (CST).
NOW = datetime(2026, 11, 4, 15, 0, tzinfo=UTC)
WEEKDAYS = WindowSpec("America/Chicago", frozenset({1, 2, 3, 4, 5}), time(8), time(17))
NIGHTS = WindowSpec("America/Chicago", frozenset({1, 2, 3, 4, 5}), time(22), time(6))


def _exploit(params):
    return RiskTier.INTRUSIVE if params.get("templates") == "exploit" else RiskTier.DISCOVERY


REGISTRY = ToolRegistry(
    [
        RUN_COMMAND,
        ToolSpec("port_scan", RiskTier.DISCOVERY, {"targets": TargetParam()}),
        ToolSpec("dns_resolve", RiskTier.PASSIVE, {"name": TargetParam()}),
        ToolSpec("nuclei_scan", RiskTier.DISCOVERY, {"url": TargetParam()}, tier_for=_exploit),
        ToolSpec("content_discovery", RiskTier.DISCOVERY, {"url": TargetParam(url_subtree=True)}),
        ToolSpec("validate_finding", RiskTier.INTRUSIVE, {"url": TargetParam()}),
        ToolSpec("old_tool", RiskTier.DISCOVERY, {"host": TargetParam()}, enabled=False),
    ]
)


def _scope(*rules):
    return Scope(ScopeRule(*_parse(r)) for r in rules)


def _parse(rule):
    mode, kind, value = rule.split(" ", 2)
    return ScopeKind(kind), value, ScopeMode(mode)


SCOPE = _scope(
    "include hostname example.com",
    "include wildcard *.example.com",
    "include cidr 203.0.113.0/24",
    "include url https://app.partner.com/portal",
    "exclude hostname admin.example.com",
    "exclude ip 203.0.113.99",
    "exclude url https://shop.example.com/checkout",
)

BASE = GateContext(
    now=NOW,
    engagement_status=EngagementStatus.ACTIVE,
    registry=REGISTRY,
    authorization=AuthorizationPeriod(date(2026, 10, 1), date(2026, 12, 31)),
    scope=SCOPE,
    autonomy=effective_autonomy({}),
    windows=(WEEKDAYS,),
    # Every in-scope name these tests use resolves into the in-scope /24. DNS rules are
    # tested in test_policy_resolution.py.
    resolutions={
        h: Resolution(h, (ipaddress.ip_address("203.0.113.10"),))
        for h in ("example.com", "www.example.com", "shop.example.com", "app.partner.com")
    },
    providers=ProviderIndex({}, {}),
)


def ctx(**changes) -> GateContext:
    return replace(BASE, **changes)


def req(tool, argv=(), **params) -> ActionRequest:
    return ActionRequest(uuid.uuid4(), tool, params, tuple(argv), "agent-run-1")


def scan(target, *extra):
    return req("port_scan", ["nmap", "-sV", *extra, target], targets=target)


def reasons(decision, name=None):
    return [c.reason for c in decision.checks if name is None or c.name == name]


# --- the happy path -------------------------------------------------------------------------


def test_in_scope_discovery_inside_window_is_allowed():
    d = evaluate(scan("www.example.com"), BASE)
    assert d.verdict is Verdict.ALLOW
    assert d.tier is RiskTier.DISCOVERY
    assert d.suggest == ()
    assert {c.name for c in d.checks} == {
        "kill_switch",
        "engagement",
        "authorization",
        "tool",
        "scope",
        "resolution",
        "window",
        "autonomy",
    }
    assert d.resolutions == (("www.example.com", ("203.0.113.10",)),)
    assert d.new_pins == d.resolutions  # first sighting: pin it


# --- kill switch ----------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["global_kill", "engagement_kill"])
def test_kill_switch_denies(field):
    d = evaluate(scan("www.example.com"), ctx(**{field: "client called"}))
    assert d.verdict is Verdict.DENY
    assert "client called" in d.reason


def test_kill_switch_with_empty_reason_still_denies():
    assert evaluate(scan("www.example.com"), ctx(global_kill="")).verdict is Verdict.DENY


def test_kill_switch_cannot_be_approved():
    d = evaluate(scan("www.example.com"), ctx(engagement_kill="stop"), approved=True)
    assert d.verdict is Verdict.DENY


# --- engagement and authorization -----------------------------------------------------------


@pytest.mark.parametrize("status", [EngagementStatus.DRAFT, EngagementStatus.ARCHIVED])
def test_inactive_engagement_denies(status):
    assert evaluate(scan("www.example.com"), ctx(engagement_status=status)).verdict is Verdict.DENY


def test_paused_engagement_defers_indefinitely_even_for_passive():
    paused = ctx(engagement_status=EngagementStatus.PAUSED)
    for request in (scan("www.example.com"), req("dns_resolve", name="www.example.com")):
        d = evaluate(request, paused)
        assert d.verdict is Verdict.DEFER
        assert d.defer_until is None


@pytest.mark.parametrize(
    "auth",
    [
        None,
        AuthorizationPeriod(None, date(2026, 11, 3)),  # expired yesterday
        AuthorizationPeriod(date(2026, 11, 5), None),  # starts tomorrow
    ],
)
def test_missing_or_out_of_period_authorization_denies(auth):
    assert evaluate(scan("www.example.com"), ctx(authorization=auth)).verdict is Verdict.DENY


def test_authorization_period_is_inclusive():
    auth = AuthorizationPeriod(date(2026, 11, 4), date(2026, 11, 4))
    assert evaluate(scan("www.example.com"), ctx(authorization=auth)).verdict is Verdict.ALLOW


# --- tools ----------------------------------------------------------------------------------


def test_unknown_tool_denies():
    d = evaluate(req("sqlmap", ["sqlmap", "-u", "https://www.example.com/"]), BASE)
    assert d.verdict is Verdict.DENY
    assert "unknown tool" in d.reason


def test_disabled_tool_denies():
    d = evaluate(req("old_tool", ["x", "www.example.com"], host="www.example.com"), BASE)
    assert d.verdict is Verdict.DENY


def test_tier_classifier_raises_the_tier():
    d = evaluate(req("nuclei_scan", url="https://www.example.com/", templates="exploit"), BASE)
    assert d.tier is RiskTier.INTRUSIVE
    assert d.verdict is Verdict.NEEDS_APPROVAL


def test_tier_classifier_cannot_lower_the_tier():
    registry = ToolRegistry(
        [ToolSpec("t", RiskTier.INTRUSIVE, {"h": TargetParam()}, tier_for=lambda p: "passive")]
    )
    d = evaluate(req("t", h="www.example.com"), ctx(registry=registry))
    assert d.tier is RiskTier.INTRUSIVE


def test_failing_tier_classifier_needs_approval():
    def broken(params):
        raise KeyError("templates")

    registry = ToolRegistry(
        [ToolSpec("t", RiskTier.PASSIVE, {"h": TargetParam()}, tier_for=broken)]
    )
    d = evaluate(req("t", h="www.example.com"), ctx(registry=registry))
    assert d.verdict is Verdict.NEEDS_APPROVAL
    assert d.tier is RiskTier.ARBITRARY


def test_duplicate_tool_registration_fails():
    with pytest.raises(ValueError, match="twice"):
        ToolRegistry([RUN_COMMAND, RUN_COMMAND])


# --- scope ----------------------------------------------------------------------------------


def test_out_of_scope_target_denies_and_suggests():
    d = evaluate(scan("Other.Example.NET"), BASE)
    assert d.verdict is Verdict.DENY
    assert [(s.kind, s.value) for s in d.suggest] == [(ScopeKind.HOSTNAME, "other.example.net")]


def test_out_of_scope_url_suggests_its_host():
    d = evaluate(req("nuclei_scan", url="https://beta.other.org/login"), BASE)
    assert d.verdict is Verdict.DENY
    assert [s.value for s in d.suggest] == ["beta.other.org"]


def test_apex_not_covered_by_wildcard_only_scope():
    scope = _scope("include wildcard *.corp.com")
    d = evaluate(scan("corp.com"), ctx(scope=scope))
    assert d.verdict is Verdict.DENY
    assert [s.value for s in d.suggest] == ["corp.com"]


@pytest.mark.parametrize("target", ["127.0.0.1", "169.254.169.254", "co.uk"])
def test_unsuggestable_targets_deny_without_suggestion(target):
    d = evaluate(scan(target), BASE)
    assert d.verdict is Verdict.DENY
    assert d.suggest == ()


@pytest.mark.parametrize(
    "target", ["admin.example.com", "deep.admin.example.com", "203.0.113.99", "203.0.113.96/30"]
)
def test_excluded_target_denies_without_suggestion(target):
    d = evaluate(scan(target), BASE)
    assert d.verdict is Verdict.DENY
    assert d.suggest == ()


def test_excluded_cannot_be_approved():
    assert evaluate(scan("admin.example.com"), BASE, approved=True).verdict is Verdict.DENY


def test_lookalike_domain_is_out_of_scope():
    d = evaluate(scan("examp1e.com"), BASE)
    assert d.verdict is Verdict.DENY
    assert evaluate(scan("example.com.evil.net"), BASE).verdict is Verdict.DENY


@pytest.mark.parametrize("target", ["0x7f.1", "https://user@www.example.com/"])
def test_uncertain_target_needs_approval(target):
    d = evaluate(req("nuclei_scan", url=target), BASE)
    assert d.verdict is Verdict.NEEDS_APPROVAL


def test_list_target_param_checks_every_value():
    d = evaluate(req("port_scan", targets=["www.example.com", "198.51.100.7"]), BASE)
    assert d.verdict is Verdict.DENY
    assert [s.value for s in d.suggest] == ["198.51.100.7"]


def test_non_string_target_param_needs_approval():
    d = evaluate(req("port_scan", ["nmap", "www.example.com"], targets={"h": 1}), BASE)
    assert d.verdict is Verdict.NEEDS_APPROVAL


def test_argv_is_checked_as_well_as_declared_params():
    """Defense in depth: an extra target smuggled into the argv is caught."""
    d = evaluate(scan("www.example.com", "198.51.100.7"), BASE)
    assert d.verdict is Verdict.DENY
    assert any(t.source == "argv" and t.target == "198.51.100.7" for t in d.targets)


def test_ipv6_in_argv_is_checked():
    d = evaluate(req("run_command", ["curl", "http://[2001:db8::1]:8080/"]), BASE)
    assert d.verdict is Verdict.DENY
    assert [s.value for s in d.suggest] == ["2001:db8::1"]


def test_possible_hostname_in_argv_needs_approval_not_deny():
    d = evaluate(scan("www.example.com", "-oN", "results.sh"), BASE)
    assert d.verdict is Verdict.NEEDS_APPROVAL
    assert d.suggest == ()


def test_unreadable_argv_token_needs_approval():
    d = evaluate(scan("www.example.com", "--max-rate", "1.5"), BASE)
    assert d.verdict is Verdict.NEEDS_APPROVAL


def test_url_subtree_with_excluded_path_below_is_excluded():
    d = evaluate(req("content_discovery", url="https://shop.example.com/"), BASE)
    assert d.verdict is Verdict.DENY


def test_single_request_above_excluded_path_is_fine():
    d = evaluate(req("nuclei_scan", url="https://shop.example.com/"), BASE)
    assert d.verdict is Verdict.ALLOW


def test_url_entry_does_not_cover_host_level_actions():
    d = evaluate(scan("app.partner.com"), BASE)
    assert d.verdict is Verdict.DENY


def test_unreadable_scope_denies():
    d = evaluate(scan("www.example.com"), ctx(scope=None, scope_error="bad entry"))
    assert d.verdict is Verdict.DENY
    assert "bad entry" in d.reason


def test_no_target_for_active_tool_needs_approval():
    d = evaluate(req("port_scan", ["nmap", "-sV"]), BASE)
    assert d.verdict is Verdict.NEEDS_APPROVAL
    assert "no target" in d.reason


# --- passive lookups on suggestions ---------------------------------------------------------


def test_passive_lookup_on_pending_suggestion_is_allowed():
    d = evaluate(
        req("dns_resolve", ["dnsx", "-d", "new.other.net"], name="new.other.net"),
        ctx(pending_suggestions=frozenset({"new.other.net"})),
    )
    assert d.verdict is Verdict.ALLOW
    assert d.suggest == ()


def test_passive_lookup_without_suggestion_denies_and_suggests():
    d = evaluate(req("dns_resolve", name="new.other.net"), BASE)
    assert d.verdict is Verdict.DENY
    assert [s.value for s in d.suggest] == ["new.other.net"]


def test_pending_suggestion_does_not_help_active_tools():
    d = evaluate(scan("new.other.net"), ctx(pending_suggestions=frozenset({"new.other.net"})))
    assert d.verdict is Verdict.DENY


def test_excluded_beats_pending_suggestion():
    d = evaluate(
        req("dns_resolve", name="admin.example.com"),
        ctx(pending_suggestions=frozenset({"admin.example.com"})),
    )
    assert d.verdict is Verdict.DENY


# --- testing windows ------------------------------------------------------------------------


def test_outside_window_defers_until_next_opening():
    evening = datetime(2026, 11, 4, 23, 30, tzinfo=UTC)  # 17:30 Chicago
    d = evaluate(scan("www.example.com"), ctx(now=evening))
    assert d.verdict is Verdict.DEFER
    assert d.defer_until == datetime(2026, 11, 5, 14, 0, tzinfo=UTC)  # Thu 08:00 CST


def test_no_window_defers_indefinitely():
    d = evaluate(scan("www.example.com"), ctx(windows=()))
    assert d.verdict is Verdict.DEFER
    assert d.defer_until is None


def test_passive_ignores_windows():
    d = evaluate(req("dns_resolve", name="www.example.com"), ctx(windows=()))
    assert d.verdict is Verdict.ALLOW


def test_overnight_window_open_after_midnight():
    early = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)  # Thu 03:00 Chicago, Wed-night window
    assert evaluate(scan("www.example.com"), ctx(now=early, windows=(NIGHTS,))).verdict is (
        Verdict.ALLOW
    )


# --- autonomy and precedence ----------------------------------------------------------------


def test_intrusive_needs_approval_by_default():
    d = evaluate(req("validate_finding", url="https://www.example.com/x"), BASE)
    assert d.verdict is Verdict.NEEDS_APPROVAL


def test_autonomy_override_auto():
    auto = effective_autonomy({"intrusive": "auto"})
    d = evaluate(req("validate_finding", url="https://www.example.com/x"), ctx(autonomy=auto))
    assert d.verdict is Verdict.ALLOW


def test_autonomy_off_denies():
    off = effective_autonomy({"discovery": "off"})
    assert evaluate(scan("www.example.com"), ctx(autonomy=off)).verdict is Verdict.DENY


def test_run_command_always_needs_approval():
    forced = {**effective_autonomy({}), RiskTier.ARBITRARY: Autonomy.AUTO}
    d = evaluate(req("run_command", ["curl", "https://www.example.com/"]), ctx(autonomy=forced))
    assert d.verdict is Verdict.NEEDS_APPROVAL


def test_run_command_out_of_scope_denies():
    d = evaluate(req("run_command", ["curl", "-s", "https://evil.test.org/"]), BASE)
    assert d.verdict is Verdict.DENY


def test_run_command_flags_recursive_reach_into_excluded_path():
    d = evaluate(req("run_command", ["wget", "-r", "https://shop.example.com/"]), BASE)
    assert d.verdict is Verdict.NEEDS_APPROVAL
    assert any("recursive" in r for r in reasons(d, "scope"))


def test_approval_outranks_defer_and_approved_then_defers():
    evening = datetime(2026, 11, 4, 23, 30, tzinfo=UTC)
    request = req("validate_finding", url="https://www.example.com/x")
    assert evaluate(request, ctx(now=evening)).verdict is Verdict.NEEDS_APPROVAL
    assert evaluate(request, ctx(now=evening), approved=True).verdict is Verdict.DEFER


def test_approved_action_is_allowed_inside_window():
    request = req("validate_finding", url="https://www.example.com/x")
    d = evaluate(request, BASE, approved=True)
    assert d.verdict is Verdict.ALLOW
    assert d.reason == "approved by the operator"


def test_approved_action_denied_after_scope_removal():
    """Re-evaluation at execution: the scope changed while the approval waited."""
    request = req("validate_finding", url="https://www.example.com/x")
    shrunk = _scope("include hostname example.com")
    assert evaluate(request, ctx(scope=shrunk), approved=True).verdict is Verdict.DENY


def test_deny_outranks_everything():
    d = evaluate(scan("198.51.100.7"), ctx(windows=(), engagement_kill="stop"))
    assert d.verdict is Verdict.DENY
    assert "kill switch" in d.reason and "198.51.100.7" in d.reason


def test_defer_until_is_none_if_any_deferral_is_open_ended():
    evening = datetime(2026, 11, 4, 23, 30, tzinfo=UTC)
    d = evaluate(
        scan("www.example.com"), ctx(now=evening, engagement_status=EngagementStatus.PAUSED)
    )
    assert d.verdict is Verdict.DEFER
    assert d.defer_until is None
