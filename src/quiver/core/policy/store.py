"""Database side of the policy gate: load a `GateContext`, record decisions.

`gate()` is what the worker calls (step 8): load, evaluate, record. It flushes but does not
commit, so the caller can store the job in the same transaction as the decision.
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from quiver.core.models import (
    Authorization,
    Engagement,
    Event,
    Organization,
    ScopeEntry,
    ScopeSuggestion,
    SuggestionStatus,
    TestingWindow,
)
from quiver.core.policy.gate import AuthorizationPeriod, GateContext, evaluate
from quiver.core.policy.tools import ToolRegistry, effective_autonomy
from quiver.core.policy.types import ActionRequest, GateDecision
from quiver.core.policy.windows import WindowSpec
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
) -> Event:
    """Write the decision to the event log and upsert any scope suggestions it raised."""
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
            }
        ),
    )
    db.add(event)

    for suggestion in decision.suggest:
        evidence = _json_safe(
            {
                "tool": request.tool,
                "requester": request.requester,
                "argv": list(request.argv),
                "reason": decision.reason,
            }
        )
        stmt = insert(ScopeSuggestion).values(
            id=uuid.uuid4(),
            engagement_id=request.engagement_id,
            kind=suggestion.kind,
            value=suggestion.value,
            status=SuggestionStatus.PENDING,
            source=SUGGESTION_SOURCE,
            evidence=evidence,
            resolved_addresses=[],
            hosting={},
            seen_count=1,
            decision_note="",
        )
        # A repeat sighting only refreshes the counters; a decided suggestion stays decided.
        await db.execute(
            stmt.on_conflict_do_update(
                index_elements=["engagement_id", "kind", "value"],
                set_={
                    "last_seen_at": func.now(),
                    "seen_count": ScopeSuggestion.seen_count + 1,
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
    approved: bool = False,
    now: datetime | None = None,
) -> GateDecision:
    """Load the engagement's context, evaluate `request`, and record the decision."""
    ctx = await load_context(db, request.engagement_id, registry, now)
    decision = evaluate(request, ctx, approved=approved)
    await record_decision(db, request, decision, ctx, approved=approved)
    return decision


def _kill_reason(row) -> str | None:
    return row.kill_switch_reason if row.kill_switch_at is not None else None


def _json_safe(value: Any) -> Any:
    """Round-trip through JSON so enums, UUIDs, and odd parameter types become plain data."""
    return json.loads(json.dumps(value, default=str))
