"""The policy gate: may this action run, and if not, why? (Blueprint §4)

`evaluate(request, ctx)` is a pure function of the request and a `GateContext` snapshot
(loaded from the database by `quiver.core.policy.store`). Every check runs and is recorded;
the final verdict is the most severe one (DENY > NEEDS_APPROVAL > DEFER > ALLOW).

Deny if definitely wrong, ask if uncertain, allow only if definitely safe: any check that
cannot decide returns NEEDS_APPROVAL, never ALLOW.

Rate, concurrency, and usage budgets (check 5) and DNS resolution, third-party hosting, and
pinning (part of check 3) are added in step 7b.
"""

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from urllib.parse import urlsplit

from quiver.core.models.engagement import EngagementStatus
from quiver.core.policy.argv import extract_targets
from quiver.core.policy.tools import ToolRegistry, ToolSpec
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
from quiver.core.scope import NormalizedScope, ScopeMode, ScopeValueError, normalize_scope_value
from quiver.core.scope_match import Scope, ScopeResult


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
    if spec is not None and tier is not None:
        _scope(request, spec, tier, ctx, add, targets, suggest)
        _window(tier, ctx, add)
        # (7b) rate, concurrency, and usage budgets go here.
        _autonomy(tier, ctx, add)

    return _decide(checks, approved, tier, targets, tuple(suggest))


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

    # Declared target parameters.
    for name, param in spec.target_params.items():
        value = request.params.get(name)
        if value is None:
            continue  # optional target parameter not used in this call
        values = [value] if isinstance(value, str) else value
        if not isinstance(values, list | tuple) or not all(isinstance(v, str) for v in values):
            add("scope", Verdict.NEEDS_APPROVAL, f"target parameter {name!r} is not a string")
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
                add(
                    "scope",
                    Verdict.NEEDS_APPROVAL,
                    f"{t}: a recursive request would reach an excluded path ({below.reason})",
                )
    for t in extraction.possible_hosts:
        targets.append(TargetCheck(t, "argv:possible", scope.check(t)))
    for token, reason in extraction.uncertain:
        add("scope", Verdict.NEEDS_APPROVAL, f"cannot read argv token {token!r}: {reason}")

    if not targets and tier is not RiskTier.PASSIVE:
        add("scope", Verdict.NEEDS_APPROVAL, "no target could be identified")

    for tc in targets:
        _target(tc, tier, ctx, add, suggest)


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
