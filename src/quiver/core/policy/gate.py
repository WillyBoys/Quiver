"""The policy gate: may this action run, and if not, why? (Blueprint §4)

`evaluate(request, ctx)` is a pure function of the request and a `GateContext` snapshot
(loaded from the database by `quiver.core.policy.store`). Every check runs and is recorded;
the final verdict is the most severe one (DENY > NEEDS_APPROVAL > DEFER > ALLOW).

Deny if definitely wrong, ask if uncertain, allow only if definitely safe: any check that
cannot decide returns NEEDS_APPROVAL, never ALLOW.

DNS is the one input that needs I/O. The store resolves `hostnames_to_resolve(request, ctx)`
first and passes the answers in `ctx.resolutions`, so this module never touches the network.

Check 6 (limits) needs a snapshot of the engagement's running jobs (`Load`), which the worker
supplies. The model-usage budget joins check 6 with agent budgets (step 16).
"""

import ipaddress
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from urllib.parse import urlsplit

from quiver.core.models.engagement import EngagementStatus
from quiver.core.policy.argv import extract_targets
from quiver.core.policy.providers import ProviderIndex
from quiver.core.policy.resolve import Resolution
from quiver.core.policy.tools import DEFAULT_LIMITS, ToolRegistry, ToolSpec
from quiver.core.policy.types import (
    SEVERITY,
    ActionRequest,
    Autonomy,
    Check,
    GateDecision,
    RiskTier,
    TargetCheck,
    Verdict,
)
from quiver.core.policy.windows import WindowSpec, window_state
from quiver.core.scope import (
    FORBIDDEN_INCLUDE_NETWORKS,
    NormalizedScope,
    ScopeKind,
    ScopeMode,
    ScopeValueError,
    normalize_hostname,
    normalize_scope_value,
)
from quiver.core.scope_match import Scope, ScopeResult

# More hostnames than this in one action are not resolved; the operator decides instead.
MAX_RESOLVE = 20
# How long a job deferred by a limit waits before it is gated again.
LIMIT_RETRY = timedelta(seconds=15)


@dataclass(frozen=True)
class Load:
    """The engagement's job activity when the gate runs (check 6)."""

    running: int = 0  # dispatched or running jobs
    started_last_minute: int = 0
    running_targets: Mapping[str, int] = field(default_factory=dict)  # target key -> jobs


@dataclass(frozen=True)
class AuthorizationPeriod:
    valid_from: date | None
    valid_until: date | None


@dataclass(frozen=True)
class GateContext:
    """Everything the gate needs about an engagement, as of `now`."""

    now: datetime
    engagement_status: EngagementStatus
    registry: ToolRegistry
    authorization: AuthorizationPeriod | None
    scope: Scope | None  # None when the stored scope could not be loaded
    autonomy: Mapping[RiskTier, Autonomy]
    windows: tuple[WindowSpec, ...] = ()
    global_kill: str | None = None  # engaged: the reason (may be empty); None: not engaged
    engagement_kill: str | None = None
    scope_error: str | None = None
    # Normalized values of this engagement's pending scope suggestions.
    pending_suggestions: frozenset[str] = frozenset()
    # DNS answers for hostnames_to_resolve(), and this engagement's pinned addresses.
    resolutions: Mapping[str, Resolution] = field(default_factory=dict)
    pins: Mapping[str, frozenset[str]] = field(default_factory=dict)
    providers: ProviderIndex | None = None  # None: third-party hosting cannot be checked
    limits: Mapping[str, int] = field(default_factory=lambda: dict(DEFAULT_LIMITS))
    load: Load | None = None  # None: not gating a job (no limits apply)
    org_id: uuid.UUID | None = None  # for recording; not used by evaluate()


AddCheck = Callable[..., None]


def evaluate(request: ActionRequest, ctx: GateContext, *, approved: bool = False) -> GateDecision:
    """Decide on `request`. `approved=True` re-evaluates an action the operator approved:
    it satisfies NEEDS_APPROVAL checks, but DENY and DEFER still apply."""
    checks: list[Check] = []

    def add(name: str, verdict: Verdict, reason: str, until: datetime | None = None) -> None:
        checks.append(Check(name, verdict, reason, until))

    _kill_switch(ctx, add)
    _engagement(ctx, add)

    spec = ctx.registry.get(request.tool)
    tier = _tool(request, spec, add)
    targets: list[TargetCheck] = []
    suggest: dict[NormalizedScope, None] = {}
    pinned: dict[str, tuple[str, ...]] = {}
    new_pins: dict[str, tuple[str, ...]] = {}
    if spec is not None and tier is not None:
        _scope(request, spec, tier, ctx, add, targets, suggest)
        if tier is not RiskTier.PASSIVE and ctx.scope is not None:
            _resolution(targets, ctx, add, suggest, pinned, new_pins)
        _window(tier, ctx, add)
        _limits(target_keys(targets), ctx, add)  # usage budget joins in step 16
        _autonomy(tier, ctx, add)

    decision = _decide(checks, approved, tier, targets, tuple(suggest))
    return replace(decision, resolutions=tuple(pinned.items()), new_pins=tuple(new_pins.items()))


def apply_approval(decision: GateDecision, approved_reasons: Iterable[str]) -> GateDecision:
    """The decision once an operator approval is taken into account. An approval covers
    exactly the reasons the operator saw: if the gate now asks for any other reason, the
    decision still needs approval. DENY and DEFER are never covered."""
    approved = set(approved_reasons)
    pending = [c for c in decision.checks if c.verdict is Verdict.NEEDS_APPROVAL]
    if not pending or not {c.reason for c in pending} <= approved:
        return decision
    checks = [
        replace(c, verdict=Verdict.ALLOW, reason=f"approved: {c.reason}")
        if c.verdict is Verdict.NEEDS_APPROVAL
        else c
        for c in decision.checks
    ]
    redone = _decide(checks, False, decision.tier, list(decision.targets), decision.suggest)
    if redone.verdict is Verdict.ALLOW:
        redone = replace(redone, reason="approved by the operator")
    return replace(redone, resolutions=decision.resolutions, new_pins=decision.new_pins)


def approval_reasons(decision: GateDecision) -> list[str]:
    """What the operator is asked to approve: every NEEDS_APPROVAL reason, in check order."""
    return [c.reason for c in decision.checks if c.verdict is Verdict.NEEDS_APPROVAL]


def target_keys(targets: Iterable[TargetCheck]) -> list[str]:
    """Stable keys for the hosts and networks an action touches (per-target limits): the
    normalized hostname for names and URLs, the address or network otherwise."""
    keys: dict[str, None] = {}
    for tc in targets:
        if tc.decision.result is not ScopeResult.IN_SCOPE:
            continue
        key = _hostname_of(tc.target)
        if key is None:
            value = tc.target.strip()
            if "://" in value:
                value = urlsplit(value).hostname or value
            try:
                net = ipaddress.ip_network(value, strict=False)
                key = str(net.network_address) if net.num_addresses == 1 else str(net)
            except ValueError:
                continue
        keys[key] = None
    return list(keys)


def hostnames_to_resolve(request: ActionRequest, ctx: GateContext) -> set[str]:
    """The in-scope hostnames this request would contact, which the store resolves before
    calling evaluate(). Empty for passive tools: they never touch the asset."""
    spec = ctx.registry.get(request.tool)
    if spec is None or not spec.enabled or ctx.scope is None:
        return set()
    try:
        tier = spec.tier_of(request.params)
    except Exception:
        tier = RiskTier.ARBITRARY
    if tier is RiskTier.PASSIVE:
        return set()
    targets, _ = _collect_targets(request, spec, tier, ctx.scope)
    hosts = _resolvable(targets)
    return set(hosts) if len(hosts) <= MAX_RESOLVE else set()


# --- checks ---------------------------------------------------------------------------------


def _kill_switch(ctx: GateContext, add: AddCheck) -> None:
    engaged = False
    for scope, reason in (("global", ctx.global_kill), ("engagement", ctx.engagement_kill)):
        if reason is not None:
            engaged = True
            add("kill_switch", Verdict.DENY, f"{scope} kill switch is engaged{_suffix(reason)}")
    if not engaged:
        add("kill_switch", Verdict.ALLOW, "not engaged")


def _engagement(ctx: GateContext, add: AddCheck) -> None:
    status = ctx.engagement_status
    if status is EngagementStatus.PAUSED:
        add("engagement", Verdict.DEFER, "engagement is paused")
    elif status is not EngagementStatus.ACTIVE:
        add("engagement", Verdict.DENY, f"engagement is {status}, not active")
    else:
        add("engagement", Verdict.ALLOW, "active")

    auth = ctx.authorization
    today = ctx.now.date()
    if auth is None:
        add("authorization", Verdict.DENY, "no authorization record")
    elif auth.valid_until is not None and auth.valid_until < today:
        add("authorization", Verdict.DENY, f"authorization expired on {auth.valid_until}")
    elif auth.valid_from is not None and auth.valid_from > today:
        add("authorization", Verdict.DENY, f"authorization starts on {auth.valid_from}")
    else:
        add("authorization", Verdict.ALLOW, "authorization is valid")


def _tool(request: ActionRequest, spec: ToolSpec | None, add: AddCheck) -> RiskTier | None:
    if spec is None:
        add("tool", Verdict.DENY, f"unknown tool {request.tool!r}")
        return None
    if not spec.enabled:
        add("tool", Verdict.DENY, f"tool {spec.name!r} is disabled")
        return None
    try:
        tier = spec.tier_of(request.params)
    except Exception as exc:  # a classifier that cannot decide must not make the action safer
        add("tool", Verdict.NEEDS_APPROVAL, f"risk tier could not be determined: {exc}")
        return RiskTier.ARBITRARY
    add("tool", Verdict.ALLOW, f"{spec.name} ({tier})")
    return tier


def _scope(
    request: ActionRequest,
    spec: ToolSpec,
    tier: RiskTier,
    ctx: GateContext,
    add: AddCheck,
    targets: list[TargetCheck],
    suggest: dict[NormalizedScope, None],
) -> None:
    scope = ctx.scope
    if scope is None:
        add("scope", Verdict.DENY, f"engagement scope cannot be read: {ctx.scope_error}")
        return

    collected, problems = _collect_targets(request, spec, tier, scope)
    targets.extend(collected)
    for reason in problems:
        add("scope", Verdict.NEEDS_APPROVAL, reason)

    if not targets and tier is not RiskTier.PASSIVE:
        add("scope", Verdict.NEEDS_APPROVAL, "no target could be identified")

    for tc in targets:
        _target(tc, tier, ctx, add, suggest)


def _collect_targets(
    request: ActionRequest, spec: ToolSpec, tier: RiskTier, scope: Scope
) -> tuple[list[TargetCheck], list[str]]:
    """Every target in the request with its scope decision, plus reasons for approval when
    part of the request cannot be read."""
    targets: list[TargetCheck] = []
    problems: list[str] = []

    # Declared target parameters.
    for name, param in spec.target_params.items():
        value = request.params.get(name)
        if value is None:
            continue  # optional target parameter not used in this call
        values = [value] if isinstance(value, str) else value
        if not isinstance(values, list | tuple) or not all(isinstance(v, str) for v in values):
            problems.append(f"target parameter {name!r} is not a string")
            continue
        for v in values:
            targets.append(
                TargetCheck(v, f"param:{name}", scope.check(v, url_subtree=param.url_subtree))
            )

    # Everything in the argv that could be a target (defense in depth; the only check for
    # run_command). argv URLs are checked as the declared parameters are: as a subtree if any
    # declared parameter is one.
    subtree = any(p.url_subtree for p in spec.target_params.values())
    extraction = extract_targets(request.argv)
    for t in extraction.definite:
        targets.append(TargetCheck(t, "argv", scope.check(t, url_subtree=subtree)))
        if tier is RiskTier.ARBITRARY and "://" in t and not subtree:
            # A free-form command may crawl. An exclusion below the URL needs a human look.
            below = scope.check(t, url_subtree=True)
            if below.result is ScopeResult.EXCLUDED:
                problems.append(
                    f"{t}: a recursive request would reach an excluded path ({below.reason})"
                )
    for t in extraction.possible_hosts:
        targets.append(TargetCheck(t, "argv:possible", scope.check(t)))
    for token, reason in extraction.uncertain:
        problems.append(f"cannot read argv token {token!r}: {reason}")
    return targets, problems


def _target(
    tc: TargetCheck,
    tier: RiskTier,
    ctx: GateContext,
    add: AddCheck,
    suggest: dict[NormalizedScope, None],
) -> None:
    result, label = tc.decision.result, f"{tc.target} ({tc.source})"
    if result is not ScopeResult.OUT_OF_SCOPE:
        verdict = {
            ScopeResult.IN_SCOPE: Verdict.ALLOW,
            ScopeResult.EXCLUDED: Verdict.DENY,
            ScopeResult.UNCERTAIN: Verdict.NEEDS_APPROVAL,
        }[result]
        add("scope", verdict, f"{label}: {tc.decision.reason}")
        return

    suggestion = suggestion_for(tc.target)
    if (
        tier is RiskTier.PASSIVE
        and suggestion is not None
        and suggestion.value in ctx.pending_suggestions
    ):
        add("scope", Verdict.ALLOW, f"{label}: pending scope suggestion; passive lookup")
    elif tc.source == "argv:possible":
        # Might be a file name rather than a host; a human can tell.
        add("scope", Verdict.NEEDS_APPROVAL, f"{label} may be a hostname and is not in scope")
    else:
        add("scope", Verdict.DENY, f"{label}: {tc.decision.reason}")
        if suggestion is not None:
            suggest[suggestion] = None


def _resolvable(targets: list[TargetCheck]) -> dict[str, bool]:
    """In-scope hostnames among the targets (URL targets contribute their host), mapped to
    whether a wildcard entry is the only thing putting them in scope."""
    hosts: dict[str, bool] = {}
    for tc in targets:
        if tc.decision.result is not ScopeResult.IN_SCOPE:
            continue
        host = _hostname_of(tc.target)
        if host is None:
            continue
        rule = tc.decision.rule
        wildcard_only = rule is not None and rule.kind is ScopeKind.WILDCARD
        hosts[host] = hosts.get(host, True) and wildcard_only
    return hosts


def _hostname_of(target: str) -> str | None:
    value = target.strip()
    if "://" in value:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return None
    try:
        ipaddress.ip_network(value, strict=False)
        return None  # an address or network, not a name
    except ValueError:
        pass
    try:
        return normalize_hostname(value, ScopeMode.EXCLUDE)  # syntax only
    except ScopeValueError:
        return None


def _resolution(
    targets: list[TargetCheck],
    ctx: GateContext,
    add: AddCheck,
    suggest: dict[NormalizedScope, None],
    pinned: dict[str, tuple[str, ...]],
    new_pins: dict[str, tuple[str, ...]],
) -> None:
    """Where in-scope hostnames actually lead (Blueprint §4.1). Names are in scope, but the
    addresses they resolve to must be testable, and must not change unnoticed."""
    scope = ctx.scope
    assert scope is not None  # noqa: S101 (checked by the caller)
    hosts = _resolvable(targets)
    if len(hosts) > MAX_RESOLVE:
        add(
            "resolution",
            Verdict.NEEDS_APPROVAL,
            f"{len(hosts)} hostnames is more than the gate resolves ({MAX_RESOLVE})",
        )
        return

    for host, wildcard_only in sorted(hosts.items()):
        res = ctx.resolutions.get(host)
        if res is None:
            add("resolution", Verdict.NEEDS_APPROVAL, f"{host} was not resolved")
            continue
        if res.error or not res.addresses:
            reason = res.error or "no addresses"
            add("resolution", Verdict.NEEDS_APPROVAL, f"{host} could not be resolved: {reason}")
            continue

        blocked = False
        covered: list = []
        for ip in res.addresses:
            verdict, reason = _address_verdict(ip, scope)
            if verdict is Verdict.ALLOW and reason:
                covered.append(ip)
            elif verdict is not Verdict.ALLOW:
                add("resolution", verdict, f"{host} resolves to {ip}, {reason}")
                blocked = True
        if blocked:
            continue

        uncovered = [ip for ip in res.addresses if ip not in covered]
        if wildcard_only and uncovered:
            # Wildcards cover names, not infrastructure: someone else's servers need an
            # explicit entry for this exact name (or its addresses).
            if ctx.providers is None:
                add(
                    "resolution",
                    Verdict.NEEDS_APPROVAL,
                    f"{host}: third-party hosting cannot be checked (no provider data)",
                )
                continue
            provider = ctx.providers.classify(Resolution(host, tuple(uncovered), res.cnames))
            if provider:
                add(
                    "resolution",
                    Verdict.DENY,
                    f"{host} is in scope only through a wildcard and is hosted by {provider} "
                    "(third-party infrastructure); add the exact hostname to test it",
                )
                suggestion = suggestion_for(host)
                if suggestion is not None:
                    suggest[suggestion] = None
                continue

        current = res.address_strings
        known = ctx.pins.get(host)
        if known is None:
            new_pins[host] = current
            add("resolution", Verdict.ALLOW, f"{host} → {', '.join(current)} (pinned now)")
        elif set(current) <= known:
            add("resolution", Verdict.ALLOW, f"{host} → {', '.join(current)} (matches pin)")
        else:
            fresh = sorted(set(current) - known)
            add(
                "resolution",
                Verdict.NEEDS_APPROVAL,
                f"{host} now resolves to new address(es) {', '.join(fresh)}; "
                f"pinned: {', '.join(sorted(known))}",
            )
        pinned[host] = current


def _address_verdict(ip, scope: Scope) -> tuple[Verdict, str]:
    """What an address a hostname resolves to means for the action. ALLOW with a reason means
    the address is in scope itself; ALLOW with no reason means an acceptable public address
    that is not in scope by IP (the hostname entry is what puts it in scope)."""
    if any(ip.version == net.version and ip in net for net in FORBIDDEN_INCLUDE_NETWORKS):
        return Verdict.DENY, "which is never testable (loopback, link-local, metadata, reserved)"
    decision = scope.check(str(ip))
    if decision.result is ScopeResult.EXCLUDED:
        return Verdict.DENY, f"which is excluded ({decision.reason})"
    if decision.result is ScopeResult.IN_SCOPE:
        return Verdict.ALLOW, decision.reason
    if decision.result is ScopeResult.UNCERTAIN:
        # e.g. an address whose web root is excluded: host-level work may touch it.
        return Verdict.NEEDS_APPROVAL, f"which cannot be judged with confidence ({decision.reason})"
    if not ip.is_global:
        return Verdict.DENY, "a private or non-public address that no scope entry covers"
    return Verdict.ALLOW, ""


def _window(tier: RiskTier, ctx: GateContext, add: AddCheck) -> None:
    if tier is RiskTier.PASSIVE:
        # Passive lookups go to third parties, never the asset (operator decision 2026-11-03).
        add("window", Verdict.ALLOW, "passive actions are not limited to testing windows")
        return
    if not ctx.windows:
        add("window", Verdict.DEFER, "no testing window is configured")
        return
    state = window_state(ctx.windows, ctx.now)
    if state.open:
        add("window", Verdict.ALLOW, "inside a testing window")
    elif state.next_open is None:
        add("window", Verdict.DEFER, "no testing window opens in the next week")
    else:
        add(
            "window",
            Verdict.DEFER,
            f"outside testing windows until {state.next_open.isoformat()}",
            until=state.next_open,
        )


def _limits(keys: list[str], ctx: GateContext, add: AddCheck) -> None:
    load = ctx.load
    if load is None:
        return
    limits, until = ctx.limits, ctx.now + LIMIT_RETRY
    deferred = False
    if load.running >= limits["max_concurrent_jobs"]:
        add(
            "limits",
            Verdict.DEFER,
            f"{load.running} jobs already running (limit {limits['max_concurrent_jobs']})",
            until=until,
        )
        deferred = True
    if load.started_last_minute >= limits["max_jobs_per_minute"]:
        add(
            "limits",
            Verdict.DEFER,
            f"{load.started_last_minute} jobs started in the last minute "
            f"(limit {limits['max_jobs_per_minute']})",
            until=until,
        )
        deferred = True
    busy = [
        k for k in keys if load.running_targets.get(k, 0) >= limits["max_concurrent_per_target"]
    ]
    if busy:
        add(
            "limits",
            Verdict.DEFER,
            f"already running against {', '.join(busy)} "
            f"(limit {limits['max_concurrent_per_target']} per target)",
            until=until,
        )
        deferred = True
    if not deferred:
        add("limits", Verdict.ALLOW, "within job limits")


def _autonomy(tier: RiskTier, ctx: GateContext, add: AddCheck) -> None:
    if tier is RiskTier.ARBITRARY:
        add("autonomy", Verdict.NEEDS_APPROVAL, "arbitrary commands always need approval")
        return
    setting = ctx.autonomy.get(tier, Autonomy.APPROVAL)
    if setting is Autonomy.AUTO:
        add("autonomy", Verdict.ALLOW, f"{tier} actions run automatically")
    elif setting is Autonomy.OFF:
        add("autonomy", Verdict.DENY, f"{tier} actions are disabled for this engagement")
    else:
        add("autonomy", Verdict.NEEDS_APPROVAL, f"{tier} actions need approval")


# --- result ---------------------------------------------------------------------------------


def _decide(
    checks: list[Check],
    approved: bool,
    tier: RiskTier | None,
    targets: list[TargetCheck],
    suggest: tuple[NormalizedScope, ...],
) -> GateDecision:
    def effective(c: Check) -> Verdict:
        if approved and c.verdict is Verdict.NEEDS_APPROVAL:
            return Verdict.ALLOW
        return c.verdict

    verdict = max((effective(c) for c in checks), key=SEVERITY.__getitem__)
    deciding = [c for c in checks if effective(c) is verdict]
    if verdict is Verdict.ALLOW:
        reason = "approved by the operator" if approved else "all checks passed"
    else:
        reason = "; ".join(c.reason for c in deciding)
    until = None
    if verdict is Verdict.DEFER and all(c.until is not None for c in deciding):
        until = max(c.until for c in deciding)  # every deferring condition must clear
    return GateDecision(
        verdict=verdict,
        reason=reason,
        checks=tuple(checks),
        tier=tier,
        defer_until=until,
        targets=tuple(targets),
        suggest=suggest,
    )


def suggestion_for(target: str) -> NormalizedScope | None:
    """The scope entry an out-of-scope target would become: its host for URLs, else the
    target itself. None when it could never be an include entry (loopback, public suffix)."""
    value = target
    if "://" in target:
        try:
            value = urlsplit(target).hostname or ""
        except ValueError:
            return None
    try:
        return normalize_scope_value(value, ScopeMode.INCLUDE)
    except ScopeValueError:
        return None


def _suffix(reason: str) -> str:
    return f": {reason}" if reason else ""
