"""Database side of the policy gate: load a `GateContext`, record decisions.

`gate()` is what the worker calls (step 8): load, resolve, evaluate, record. It flushes but
does not commit, so the caller can store the job in the same transaction as the decision.
"""

import json
import uuid
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from quiver.core.models import (
    Authorization,
    Engagement,
    Event,
    HostResolution,
    Organization,
    ScopeEntry,
    ScopeSuggestion,
    SuggestionStatus,
    TestingWindow,
)
from quiver.core.policy.gate import (
    AuthorizationPeriod,
    GateContext,
    evaluate,
    hostnames_to_resolve,
)
from quiver.core.policy.providers import ProviderIndex, bundled_providers
from quiver.core.policy.resolve import Resolution, Resolver, resolve_all
from quiver.core.policy.tools import ToolRegistry, effective_autonomy
from quiver.core.policy.types import ActionRequest, GateDecision
from quiver.core.policy.windows import WindowSpec
from quiver.core.scope import ScopeKind
from quiver.core.scope_match import Scope

POLICY_DECISION = "policy.decision"
SUGGESTION_SOURCE = "policy_gate"


async def load_context(
    db: AsyncSession,
    engagement_id: uuid.UUID,
    registry: ToolRegistry,
    now: datetime | None = None,
) -> GateContext:
    eng = await db.get(Engagement, engagement_id)
    if eng is None:
        raise LookupError(f"engagement {engagement_id} not found")
    org = await db.get(Organization, eng.org_id)

    auth = await db.scalar(select(Authorization).where(Authorization.engagement_id == eng.id))
    entries = await db.scalars(
        select(ScopeEntry).where(
            ScopeEntry.engagement_id == eng.id, ScopeEntry.removed_at.is_(None)
        )
    )
    scope, scope_error = None, None
    try:
        scope = Scope.from_entries(entries)
    except ValueError as exc:  # corrupted stored entry: the gate denies
        scope_error = str(exc)
    windows = await db.scalars(select(TestingWindow).where(TestingWindow.engagement_id == eng.id))
    pending = await db.scalars(
        select(ScopeSuggestion.value).where(
            ScopeSuggestion.engagement_id == eng.id,
            ScopeSuggestion.status == SuggestionStatus.PENDING,
        )
    )

    return GateContext(
        now=now or datetime.now(UTC),
        engagement_status=eng.status,
        registry=registry,
        authorization=AuthorizationPeriod(auth.valid_from, auth.valid_until) if auth else None,
        scope=scope,
        scope_error=scope_error,
        autonomy=effective_autonomy(eng.autonomy),
        windows=tuple(WindowSpec.from_row(w) for w in windows),
        global_kill=_kill_reason(org),
        engagement_kill=_kill_reason(eng),
        pending_suggestions=frozenset(pending),
        org_id=eng.org_id,
    )


async def record_decision(
    db: AsyncSession,
    request: ActionRequest,
    decision: GateDecision,
    ctx: GateContext,
    *,
    approved: bool = False,
    suggestion_lookups: Mapping[str, Resolution] | None = None,
) -> Event:
    """Write the decision to the event log, update host resolutions and pins, and upsert any
    scope suggestions it raised (with their passive lookups, when given)."""
    suggestion_lookups = suggestion_lookups or {}
    event = Event(
        org_id=ctx.org_id,
        engagement_id=request.engagement_id,
        kind=POLICY_DECISION,
        payload=_json_safe(
            {
                "tool": request.tool,
                "requester": request.requester,
                "argv": list(request.argv),
                "params": dict(request.params),
                "approved": approved,
                "verdict": decision.verdict,
                "reason": decision.reason,
                "tier": decision.tier,
                "defer_until": decision.defer_until.isoformat() if decision.defer_until else None,
                "checks": [
                    {"name": c.name, "verdict": c.verdict, "reason": c.reason}
                    for c in decision.checks
                ],
                "targets": [
                    {
                        "target": t.target,
                        "source": t.source,
                        "result": t.decision.result,
                        "reason": t.decision.reason,
                        "rule": t.decision.rule.value if t.decision.rule else None,
                    }
                    for t in decision.targets
                ],
                "suggested": [s.value for s in decision.suggest],
                "resolutions": {
                    host: {
                        "addresses": list(res.address_strings),
                        "cnames": list(res.cnames),
                        "error": res.error,
                    }
                    for host, res in ctx.resolutions.items()
                },
                "pinned_now": [host for host, _ in decision.new_pins],
            }
        ),
    )
    db.add(event)

    new_pins = dict(decision.new_pins)
    for host, res in ctx.resolutions.items():
        provider = (ctx.providers.classify(res) if ctx.providers else None) or ""
        last = {
            "last_addresses": list(res.address_strings),
            "last_cnames": list(res.cnames),
            "last_error": res.error or "",
            "provider": provider,
            "last_resolved_at": func.now(),
        }
        pin = list(new_pins.get(host, ()))
        stmt = insert(HostResolution).values(
            id=uuid.uuid4(),
            engagement_id=request.engagement_id,
            hostname=host,
            pinned_addresses=pin,
            **last,
        )
        # Pins are only ever set the first time (here) or widened by the operator (API).
        update = {**last, "pinned_addresses": stmt.excluded.pinned_addresses} if pin else last
        await db.execute(
            stmt.on_conflict_do_update(index_elements=["engagement_id", "hostname"], set_=update)
        )

    for suggestion in decision.suggest:
        evidence = _json_safe(
            {
                "tool": request.tool,
                "requester": request.requester,
                "argv": list(request.argv),
                "reason": decision.reason,
            }
        )
        lookup = suggestion_lookups.get(suggestion.value)
        found = {}
        if lookup is not None:
            provider = ctx.providers.classify(lookup) if ctx.providers else None
            found = {
                "resolved_addresses": list(lookup.address_strings),
                "hosting": _json_safe(
                    {"provider": provider, "cnames": list(lookup.cnames), "error": lookup.error}
                ),
            }
        stmt = insert(ScopeSuggestion).values(
            id=uuid.uuid4(),
            engagement_id=request.engagement_id,
            kind=suggestion.kind,
            value=suggestion.value,
            status=SuggestionStatus.PENDING,
            source=SUGGESTION_SOURCE,
            evidence=evidence,
            seen_count=1,
            decision_note="",
            **{"resolved_addresses": [], "hosting": {}, **found},
        )
        # A repeat sighting only refreshes the counters and lookups; a decided suggestion
        # stays decided.
        await db.execute(
            stmt.on_conflict_do_update(
                index_elements=["engagement_id", "kind", "value"],
                set_={
                    "last_seen_at": func.now(),
                    "seen_count": ScopeSuggestion.seen_count + 1,
                    **found,
                },
            )
        )
    await db.flush()
    return event


async def gate(
    db: AsyncSession,
    request: ActionRequest,
    registry: ToolRegistry,
    *,
    resolver: Resolver,
    providers: ProviderIndex | None = None,
    approved: bool = False,
    now: datetime | None = None,
) -> GateDecision:
    """Load the engagement's context, resolve the in-scope names the request touches,
    evaluate it, and record the decision. `providers` defaults to the bundled snapshot."""
    ctx = await load_context(db, request.engagement_id, registry, now)
    hosts = hostnames_to_resolve(request, ctx)
    resolutions = await resolve_all(resolver, hosts)
    ctx = replace(
        ctx,
        resolutions=resolutions,
        pins=await _load_pins(db, request.engagement_id, hosts),
        providers=providers or bundled_providers(),
    )
    decision = evaluate(request, ctx, approved=approved)

    # Passive lookups on new hostname suggestions give the operator evidence to decide with.
    names = [s.value for s in decision.suggest if s.kind is ScopeKind.HOSTNAME]
    lookups = await resolve_all(resolver, names)
    await record_decision(db, request, decision, ctx, approved=approved, suggestion_lookups=lookups)
    return decision


async def _load_pins(
    db: AsyncSession, engagement_id: uuid.UUID, hosts: set[str]
) -> dict[str, frozenset[str]]:
    if not hosts:
        return {}
    rows = await db.execute(
        select(HostResolution.hostname, HostResolution.pinned_addresses).where(
            HostResolution.engagement_id == engagement_id,
            HostResolution.hostname.in_(hosts),
        )
    )
    return {host: frozenset(addresses) for host, addresses in rows if addresses}


def _kill_reason(row) -> str | None:
    return row.kill_switch_reason if row.kill_switch_at is not None else None


def _json_safe(value: Any) -> Any:
    """Round-trip through JSON so enums, UUIDs, and odd parameter types become plain data."""
    return json.loads(json.dumps(value, default=str))
