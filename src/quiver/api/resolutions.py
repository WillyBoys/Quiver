"""Pinned host resolutions (Blueprint §4.1): what each in-scope hostname resolved to when it
was pinned, what it resolves to now, and the operator's way to accept new addresses.

The API never resolves names itself; resolutions are recorded by the policy gate.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from quiver.api.auth import DbDep, OperatorDep, require_operator
from quiver.api.engagements import OrmOut, Reason, get_engagement_or_404, require_editable
from quiver.core.models import Event, HostResolution

router = APIRouter(
    prefix="/engagements/{engagement_id}/resolutions",
    tags=["host resolutions"],
    dependencies=[Depends(require_operator)],
)


class ResolutionOut(OrmOut):
    id: uuid.UUID
    hostname: str
    pinned_addresses: list[str]
    last_addresses: list[str]
    last_cnames: list[str]
    last_error: str
    provider: str
    first_seen_at: datetime
    last_resolved_at: datetime
    accepted_at: datetime | None
    # Addresses seen in the latest answer that are not pinned: the gate asks before using them.
    unpinned_addresses: list[str] = Field(default_factory=list)

    @classmethod
    def of(cls, row: HostResolution) -> "ResolutionOut":
        out = cls.model_validate(row)
        out.unpinned_addresses = sorted(set(row.last_addresses) - set(row.pinned_addresses))
        return out


class AcceptIn(BaseModel):
    reason: Reason


@router.get("", response_model=list[ResolutionOut])
async def list_resolutions(engagement_id: uuid.UUID, db: DbDep, user: OperatorDep):
    eng = await get_engagement_or_404(db, user, engagement_id)
    rows = await db.scalars(
        select(HostResolution)
        .where(HostResolution.engagement_id == eng.id)
        .order_by(HostResolution.hostname)
    )
    return [ResolutionOut.of(r) for r in rows]


@router.post("/{resolution_id}/accept", response_model=ResolutionOut)
async def accept_resolution(
    engagement_id: uuid.UUID,
    resolution_id: uuid.UUID,
    body: AcceptIn,
    db: DbDep,
    user: OperatorDep,
):
    """Add the latest answer's addresses to the pin, so actions on this name stop asking.
    Forbidden, excluded, and private addresses stay denied: the gate checks every address on
    every evaluation, pinned or not."""
    eng = await get_engagement_or_404(db, user, engagement_id)
    require_editable(eng)
    row = await db.scalar(
        select(HostResolution)
        .where(HostResolution.id == resolution_id, HostResolution.engagement_id == eng.id)
        .with_for_update()
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Host resolution not found")
    added = sorted(set(row.last_addresses) - set(row.pinned_addresses))
    row.pinned_addresses = sorted(set(row.pinned_addresses) | set(row.last_addresses))
    row.accepted_at = datetime.now(UTC)
    row.accepted_by = user.id
    db.add(
        Event(
            org_id=user.org_id,
            engagement_id=eng.id,
            user_id=user.id,
            kind="resolution.accepted",
            payload={
                "hostname": row.hostname,
                "added": added,
                "pinned": row.pinned_addresses,
                "reason": body.reason.strip(),
            },
        )
    )
    await db.commit()
    await db.refresh(row)
    return ResolutionOut.of(row)
