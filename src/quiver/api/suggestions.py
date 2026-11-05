"""Scope suggestions: assets found outside scope, for the operator to add, dismiss, or exclude.

Suggestions never change scope by themselves. Adding or excluding one creates a scope entry
through the same path as the settings page, with a ScopeChange that links the suggestion.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from quiver.api.auth import DbDep, OperatorDep, require_operator
from quiver.api.engagements import (
    OrmOut,
    Reason,
    ScopeEntryOut,
    create_scope_entry,
    get_engagement_or_404,
    require_editable,
)
from quiver.core.models import ScopeSuggestion, SuggestionStatus
from quiver.core.scope import ScopeKind, ScopeMode

router = APIRouter(
    prefix="/engagements/{engagement_id}/suggestions",
    tags=["scope suggestions"],
    dependencies=[Depends(require_operator)],
)

# Which decisions are possible from each status. A dismissed suggestion can still be added
# or excluded later; added and excluded are final (change scope on the settings page instead).
_ALLOWED_FROM = {
    SuggestionStatus.ADDED: {SuggestionStatus.PENDING, SuggestionStatus.DISMISSED},
    SuggestionStatus.EXCLUDED: {SuggestionStatus.PENDING, SuggestionStatus.DISMISSED},
    SuggestionStatus.DISMISSED: {SuggestionStatus.PENDING},
}


class SuggestionOut(OrmOut):
    id: uuid.UUID
    kind: ScopeKind
    value: str
    status: SuggestionStatus
    source: str
    evidence: dict  # target-controlled data; show it as such
    resolved_addresses: list[str]
    hosting: dict
    first_seen_at: datetime
    last_seen_at: datetime
    seen_count: int
    decided_at: datetime | None
    decision_note: str
    scope_entry_id: uuid.UUID | None


class SuggestionAdd(BaseModel):
    # Defaults to the suggested value; the operator may enter a different entry instead
    # (e.g. a wildcard covering it).
    value: str | None = Field(default=None, min_length=1, max_length=2048)
    note: str = Field(default="", max_length=2000)
    reason: Reason


class SuggestionExclude(BaseModel):
    reason: Reason


class SuggestionDismiss(BaseModel):
    note: str = Field(default="", max_length=2000)


async def _get_suggestion(db, eng, suggestion_id: uuid.UUID, *, lock=False) -> ScopeSuggestion:
    stmt = select(ScopeSuggestion).where(
        ScopeSuggestion.id == suggestion_id, ScopeSuggestion.engagement_id == eng.id
    )
    if lock:
        stmt = stmt.with_for_update()
    suggestion = await db.scalar(stmt)
    if suggestion is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scope suggestion not found")
    return suggestion


async def _decide(db, user, engagement_id, suggestion_id, new_status: SuggestionStatus):
    eng = await get_engagement_or_404(db, user, engagement_id)
    require_editable(eng)
    suggestion = await _get_suggestion(db, eng, suggestion_id, lock=True)
    if suggestion.status not in _ALLOWED_FROM[new_status]:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Suggestion is already {suggestion.status}; it cannot be {new_status}",
        )
    suggestion.status = new_status
    suggestion.decided_at = datetime.now(UTC)
    suggestion.decided_by = user.id
    return eng, suggestion


@router.get("", response_model=list[SuggestionOut])
async def list_suggestions(
    engagement_id: uuid.UUID,
    db: DbDep,
    user: OperatorDep,
    status_filter: Annotated[SuggestionStatus | None, Query(alias="status")] = None,
):
    eng = await get_engagement_or_404(db, user, engagement_id)
    stmt = select(ScopeSuggestion).where(ScopeSuggestion.engagement_id == eng.id)
    if status_filter is not None:
        stmt = stmt.where(ScopeSuggestion.status == status_filter)
    rows = await db.scalars(stmt.order_by(ScopeSuggestion.first_seen_at, ScopeSuggestion.id))
    return list(rows)


@router.get("/{suggestion_id}", response_model=SuggestionOut)
async def get_suggestion(
    engagement_id: uuid.UUID, suggestion_id: uuid.UUID, db: DbDep, user: OperatorDep
):
    eng = await get_engagement_or_404(db, user, engagement_id)
    return await _get_suggestion(db, eng, suggestion_id)


@router.post("/{suggestion_id}/add", response_model=ScopeEntryOut)
async def add_suggestion(
    engagement_id: uuid.UUID,
    suggestion_id: uuid.UUID,
    body: SuggestionAdd,
    db: DbDep,
    user: OperatorDep,
):
    """Add the suggested asset (or an entry the operator enters instead) to scope."""
    eng, suggestion = await _decide(db, user, engagement_id, suggestion_id, SuggestionStatus.ADDED)
    entry = await create_scope_entry(
        db,
        eng,
        user,
        body.value or suggestion.value,
        ScopeMode.INCLUDE,
        body.note,
        body.reason,
        suggestion_id=suggestion.id,
    )
    suggestion.scope_entry_id = entry.id
    suggestion.decision_note = body.reason.strip()
    await db.commit()
    await db.refresh(entry)
    return entry


@router.post("/{suggestion_id}/exclude", response_model=ScopeEntryOut)
async def exclude_suggestion(
    engagement_id: uuid.UUID,
    suggestion_id: uuid.UUID,
    body: SuggestionExclude,
    db: DbDep,
    user: OperatorDep,
):
    """Exclude the suggested asset, so it is denied and never suggested again."""
    eng, suggestion = await _decide(
        db, user, engagement_id, suggestion_id, SuggestionStatus.EXCLUDED
    )
    entry = await create_scope_entry(
        db,
        eng,
        user,
        suggestion.value,
        ScopeMode.EXCLUDE,
        "",
        body.reason,
        suggestion_id=suggestion.id,
    )
    suggestion.scope_entry_id = entry.id
    suggestion.decision_note = body.reason.strip()
    await db.commit()
    await db.refresh(entry)
    return entry


@router.post("/{suggestion_id}/dismiss", response_model=SuggestionOut)
async def dismiss_suggestion(
    engagement_id: uuid.UUID,
    suggestion_id: uuid.UUID,
    body: SuggestionDismiss,
    db: DbDep,
    user: OperatorDep,
):
    _, suggestion = await _decide(
        db, user, engagement_id, suggestion_id, SuggestionStatus.DISMISSED
    )
    suggestion.decision_note = body.note.strip()
    await db.commit()
    await db.refresh(suggestion)
    return suggestion
