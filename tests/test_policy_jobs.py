"""Gate pieces for jobs: check 6 limits, approvals bound to their reasons, target keys,
argv building, and limit validation."""

import ipaddress
import uuid
from dataclasses import replace
from datetime import UTC, date, datetime, time, timedelta

import pytest

from quiver.core.models import EngagementStatus
from quiver.core.policy import (
    RUN_COMMAND,
    ActionRequest,
    AuthorizationPeriod,
    GateContext,
    Load,
    RiskTier,
    TargetParam,
    ToolRegistry,
    ToolSpec,
    Verdict,
    WindowSpec,
    apply_approval,
    approval_reasons,
    effective_autonomy,
    effective_limits,
    evaluate,
    target_keys,
    validate_limits,
)
from quiver.core.policy.gate import LIMIT_RETRY
from quiver.core.policy.providers import ProviderIndex
from quiver.core.policy.resolve import Resolution
from quiver.core.scope import ScopeKind, ScopeMode
from quiver.core.scope_match import Scope, ScopeRule

NOW = datetime(2026, 11, 4, 15, 0, tzinfo=UTC)
SCOPE = Scope(
    [
        ScopeRule(ScopeKind.WILDCARD, "*.example.com", ScopeMode.INCLUDE),
        ScopeRule(ScopeKind.CIDR, "203.0.113.0/24", ScopeMode.INCLUDE),
    ]
)
REGISTRY = ToolRegistry(
    [
        RUN_COMMAND,
        ToolSpec("port_scan", RiskTier.DISCOVERY, {"targets": TargetParam()}),
        ToolSpec("validate", RiskTier.INTRUSIVE, {"url": TargetParam()}),
    ]
)
BASE = GateContext(
    now=NOW,
    engagement_status=EngagementStatus.ACTIVE,
    registry=REGISTRY,
    authorization=AuthorizationPeriod(date(2026, 10, 1), None),
    scope=SCOPE,
    autonomy=effective_autonomy({}),
    windows=(WindowSpec("UTC", frozenset(range(1, 8)), time(0), time(0)),),
    resolutions={
        h: Resolution(h, (ipaddress.ip_address("203.0.113.10"),))
        for h in ("www.example.com", "api.example.com")
    },
    providers=ProviderIndex({}, {}),
    load=Load(),
)


def ctx(**changes):
    return replace(BASE, **changes)


def scan(target):
    return ActionRequest(uuid.uuid4(), "port_scan", {"targets": target}, ("nmap", target), "t")


def command(*argv):
    return ActionRequest(uuid.uuid4(), "run_command", {"argv": list(argv)}, tuple(argv), "t")


def limit_reasons(d):
    return [c.reason for c in d.checks if c.name == "limits"]


# --- check 6: limits ------------------------------------------------------------------------


def test_within_limits_is_allowed():
    d = evaluate(scan("www.example.com"), BASE)
    assert d.verdict is Verdict.ALLOW
    assert limit_reasons(d) == ["within job limits"]


def test_no_load_means_no_limit_check():
    d = evaluate(scan("www.example.com"), ctx(load=None))
    assert d.verdict is Verdict.ALLOW and limit_reasons(d) == []


@pytest.mark.parametrize(
    ("load", "words"),
    [
        (Load(running=3), "jobs already running"),
        (Load(started_last_minute=30), "started in the last minute"),
        (Load(running_targets={"www.example.com": 1}), "already running against www.example.com"),
    ],
)
def test_each_limit_defers_briefly(load, words):
    d = evaluate(scan("www.example.com"), ctx(load=load))
    assert d.verdict is Verdict.DEFER
    assert d.defer_until == NOW + LIMIT_RETRY
    assert any(words in r for r in limit_reasons(d))


def test_per_target_limit_only_counts_this_jobs_targets():
    load = Load(running_targets={"api.example.com": 5})
    assert evaluate(scan("www.example.com"), ctx(load=load)).verdict is Verdict.ALLOW


def test_engagement_overrides_raise_limits():
    limits = effective_limits({"max_concurrent_jobs": 10})
    d = evaluate(scan("www.example.com"), ctx(load=Load(running=3), limits=limits))
    assert d.verdict is Verdict.ALLOW


def test_limits_apply_to_passive_tools_too():
    registry = ToolRegistry([ToolSpec("dns", RiskTier.PASSIVE, {"name": TargetParam()})])
    request = ActionRequest(uuid.uuid4(), "dns", {"name": "www.example.com"}, (), "t")
    d = evaluate(request, ctx(registry=registry, load=Load(running=3)))
    assert d.verdict is Verdict.DEFER


# --- approvals bind to their reasons --------------------------------------------------------


def test_approval_covers_exactly_the_reasons_shown():
    d = evaluate(command("curl", "https://www.example.com/"), BASE)
    assert d.verdict is Verdict.NEEDS_APPROVAL
    reasons = approval_reasons(d)
    assert reasons == ["arbitrary commands always need approval"]
    approved = apply_approval(d, reasons)
    assert approved.verdict is Verdict.ALLOW
    assert approved.reason == "approved by the operator"
    assert approved.resolutions == d.resolutions


def test_new_reason_after_approval_needs_a_new_approval():
    first = evaluate(command("curl", "https://www.example.com/"), BASE)
    # The same job's host now resolves somewhere new: a reason the operator never saw.
    moved = ctx(
        pins={"www.example.com": frozenset({"203.0.113.10"})},
        resolutions={
            "www.example.com": Resolution(
                "www.example.com", (ipaddress.ip_address("203.0.113.11"),)
            )
        },
    )
    later = evaluate(command("curl", "https://www.example.com/"), moved)
    still = apply_approval(later, approval_reasons(first))
    assert still.verdict is Verdict.NEEDS_APPROVAL
    assert "new address" in still.reason


def test_approval_does_not_override_deny_or_defer():
    out_of_scope = evaluate(command("curl", "https://evil.other.net/"), BASE)
    assert apply_approval(out_of_scope, approval_reasons(out_of_scope)).verdict is Verdict.DENY

    busy = evaluate(command("curl", "https://www.example.com/"), ctx(load=Load(running=3)))
    assert busy.verdict is Verdict.NEEDS_APPROVAL  # approval is collected while it waits
    after = apply_approval(busy, approval_reasons(busy))
    assert after.verdict is Verdict.DEFER and after.defer_until == NOW + LIMIT_RETRY


def test_unrelated_approval_changes_nothing():
    d = evaluate(command("curl", "https://www.example.com/"), BASE)
    assert apply_approval(d, ["something else"]) == d
    allowed = evaluate(scan("www.example.com"), BASE)
    assert apply_approval(allowed, ["anything"]) == allowed


# --- target keys ----------------------------------------------------------------------------


def test_target_keys_normalize_hosts_urls_and_addresses():
    request = ActionRequest(
        uuid.uuid4(),
        "run_command",
        {},
        ("x", "https://WWW.example.com/a", "www.example.com", "203.0.113.5", "203.0.113.0/28"),
        "t",
    )
    d = evaluate(request, BASE)
    assert target_keys(d.targets) == ["www.example.com", "203.0.113.5", "203.0.113.0/28"]


def test_out_of_scope_targets_have_no_key():
    d = evaluate(scan("evil.other.net"), BASE)
    assert target_keys(d.targets) == []


# --- argv building and limit validation -----------------------------------------------------


def test_run_command_builds_its_argv():
    assert RUN_COMMAND.argv_for({"argv": ["echo", "hi"]}) == ["echo", "hi"]


@pytest.mark.parametrize("params", [{}, {"argv": "echo hi"}, {"argv": []}, {"argv": ["a", 1]}])
def test_run_command_rejects_bad_params(params):
    with pytest.raises(ValueError):
        RUN_COMMAND.argv_for(params)


def test_builders_cannot_return_unusable_argv():
    for bad in ([""], ["ok", "a\0b"], "echo", []):
        spec = ToolSpec("t", RiskTier.DISCOVERY, build_argv=lambda params, bad=bad: bad)
        with pytest.raises(ValueError):
            spec.argv_for({})
    with pytest.raises(ValueError):
        ToolSpec("t", RiskTier.DISCOVERY).argv_for({})


def test_validate_limits():
    assert validate_limits({"max_concurrent_jobs": 5}) == {"max_concurrent_jobs": 5}
    for bad in ({"max_concurrent_jobs": 0}, {"max_jobs_per_minute": 1001}, {"nope": 1}):
        with pytest.raises(ValueError):
            validate_limits(bad)
    with pytest.raises(ValueError):
        validate_limits({"max_concurrent_jobs": True})
    assert effective_limits({"max_concurrent_jobs": "lots"})["max_concurrent_jobs"] == 3


def test_limit_retry_is_short():
    assert timedelta(seconds=5) <= LIMIT_RETRY <= timedelta(minutes=1)
