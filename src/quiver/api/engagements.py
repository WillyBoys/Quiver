"""Engagement API: engagements, scope (with audit log), testing windows, authorization.

All routes require an operator session and only see the operator's organization; another
organization's engagement is indistinguishable from a missing one (404).
"""

import uuid
import zoneinfo
from datetime import UTC, date, datetime, time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from quiver.api.auth import DbDep, OperatorDep, require_operator
from quiver.core.models import (
    Authorization,
    Engagement,
    EngagementStatus,
    ScopeAction,
    ScopeChange,
    ScopeEntry,
    TestingWindow,
)
from quiver.core.scope import ScopeKind, ScopeMode, ScopeValueError, normalize_scope_value

router = APIRouter(
    prefix="/engagements", tags=["engagements"], dependencies=[Depends(require_operator)]
)

TRACKS = {"external"}  # tracks available in the PoC (Blueprint §9)

# Allowed status transitions. Archived is terminal.
TRANSITIONS: dict[EngagementStatus, set[EngagementStatus]] = {
    EngagementStatus.DRAFT: {EngagementStatus.ACTIVE, EngagementStatus.ARCHIVED},
    EngagementStatus.ACTIVE: {EngagementStatus.PAUSED, EngagementStatus.ARCHIVED},
    EngagementStatus.PAUSED: {EngagementStatus.ACTIVE, EngagementStatus.ARCHIVED},
    EngagementStatus.ARCHIVED: set(),
}

Reason = Annotated[str, Field(min_length=3, max_length=2000)]


# --- schemas --------------------------------------------------------------------------------


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10_000)
    tracks: list[str] = Field(default_factory=lambda: ["external"], min_length=1)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @field_validator("tracks")
    @classmethod
    def _known_tracks(cls, v: list[str]) -> list[str]:
        unknown = set(v) - TRACKS
        if unknown:
            raise ValueError(f"unknown track(s): {sorted(unknown)}; available: {sorted(TRACKS)}")
        return sorted(set(v))


class EngagementUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    status: EngagementStatus | None = None


class EngagementOut(_Out):
    id: uuid.UUID
    name: str
    description: str
    tracks: list[str]
    status: EngagementStatus
    created_at: datetime
    updated_at: datetime


class ScopeEntryCreate(BaseModel):
    value: str = Field(min_length=1, max_length=2048)
    mode: ScopeMode = ScopeMode.INCLUDE
    note: str = Field(default="", max_length=2000)
    reason: Reason


class ScopeEntryRemove(BaseModel):
    reason: Reason


class ScopeEntryOut(_Out):
    id: uuid.UUID
    kind: ScopeKind
    value: str
    mode: ScopeMode
    note: str
    created_at: datetime


class ScopeChangeOut(_Out):
    id: uuid.UUID
    scope_entry_id: uuid.UUID
    user_id: uuid.UUID
    action: ScopeAction
    kind: ScopeKind
    value: str
    mode: ScopeMode
    reason: str
    created_at: datetime


class WindowCreate(BaseModel):
    timezone: str
    days: list[int] = Field(min_length=1, description="ISO weekdays: 1 = Monday .. 7 = Sunday")
    start_time: time
    end_time: time

    @field_validator("timezone")
    @classmethod
    def _valid_tz(cls, v: str) -> str:
        try:
            zoneinfo.ZoneInfo(v)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(
                f"unknown time zone {v!r} (use an IANA name like America/Chicago)"
            ) from exc
        return v

    @field_validator("days")
    @classmethod
    def _valid_days(cls, v: list[int]) -> list[int]:
        if any(d < 1 or d > 7 for d in v):
            raise ValueError("days must be ISO weekdays 1 (Monday) to 7 (Sunday)")
        return sorted(set(v))

    @field_validator("start_time", "end_time")
    @classmethod
    def _naive_minutes(cls, v: time) -> time:
        if v.tzinfo is not None:
            raise ValueError("times must not include an offset; the window's timezone applies")
        return v.replace(second=0, microsecond=0)


class WindowOut(_Out):
    id: uuid.UUID
    timezone: str
    days: list[int]
    start_time: time
    end_time: time


class AuthorizationIn(BaseModel):
    authorized_by: str = Field(min_length=1, max_length=200)
    authorizer_title: str = Field(default="", max_length=200)
    authorizer_organization: str = Field(min_length=1, max_length=200)
    contact: str = Field(default="", max_length=200)
    authorized_on: date
    valid_from: date | None = None
    valid_until: date | None = None
    notes: str = Field(default="", max_length=10_000)

    @model_validator(mode="after")
    def _period(self):
        if self.valid_from and self.valid_until and self.valid_until < self.valid_from:
            raise ValueError("valid_until must not be before valid_from")
        return self


class AuthorizationOut(AuthorizationIn, _Out):
    updated_at: datetime


# --- helpers --------------------------------------------------------------------------------


async def _get_engagement(db, user, engagement_id: uuid.UUID) -> Engagement:
    eng = await db.scalar(
        select(Engagement).where(Engagement.id == engagement_id, Engagement.org_id == user.org_id)
    )
    if eng is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engagement not found")
    return eng


def _require_editable(eng: Engagement) -> None:
    if eng.status is EngagementStatus.ARCHIVED:
        raise HTTPException(status.HTTP_409_CONFLICT, "Archived engagements cannot be changed")


async def activation_problems(db, eng: Engagement) -> list[str]:
    """What is missing before this engagement may become active. Empty means ready."""
    problems = []
    auth = await db.scalar(select(Authorization).where(Authorization.engagement_id == eng.id))
    today = datetime.now(UTC).date()
    if auth is None:
        problems.append("no authorization record")
    elif auth.valid_until is not None and auth.valid_until < today:
        problems.append("authorization has expired")
    elif auth.valid_from is not None and auth.valid_from > today:
        problems.append("authorization period has not started")
    include = await db.scalar(
        select(ScopeEntry.id).where(
            ScopeEntry.engagement_id == eng.id,
            ScopeEntry.mode == ScopeMode.INCLUDE,
            ScopeEntry.removed_at.is_(None),
        )
    )
    if include is None:
        problems.append("no include scope entries")
    window = await db.scalar(select(TestingWindow.id).where(TestingWindow.engagement_id == eng.id))
    if window is None:
        problems.append("no testing window")
    return problems


# --- engagements ----------------------------------------------------------------------------


@router.get("", response_model=list[EngagementOut])
async def list_engagements(db: DbDep, user: OperatorDep):
    rows = await db.scalars(
        select(Engagement).where(Engagement.org_id == user.org_id).order_by(Engagement.created_at)
    )
    return list(rows)


@router.post("", response_model=EngagementOut, status_code=status.HTTP_201_CREATED)
async def create_engagement(body: EngagementCreate, db: DbDep, user: OperatorDep):
    eng = Engagement(
        org_id=user.org_id,
        user_id=user.id,
        name=body.name,
        description=body.description,
        tracks=body.tracks,
        status=EngagementStatus.DRAFT,
    )
    db.add(eng)
    try:
        await db.commit()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "An engagement with that name exists"
        ) from exc
    await db.refresh(eng)
    return eng


@router.get("/{engagement_id}", response_model=EngagementOut)
async def get_engagement(engagement_id: uuid.UUID, db: DbDep, user: OperatorDep):
    return await _get_engagement(db, user, engagement_id)


@router.patch("/{engagement_id}", response_model=EngagementOut)
async def update_engagement(
    engagement_id: uuid.UUID, body: EngagementUpdate, db: DbDep, user: OperatorDep
):
    eng = await _get_engagement(db, user, engagement_id)
    _require_editable(eng)

    if body.status is not None and body.status is not eng.status:
        if body.status not in TRANSITIONS[eng.status]:
            raise HTTPException(
                status.HTTP_409_CONFLICT, f"Cannot change status from {eng.status} to {body.status}"
            )
        if body.status is EngagementStatus.ACTIVE:
            problems = await activation_problems(db, eng)
            if problems:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    {"message": "Engagement is not ready to activate", "problems": problems},
                )
        eng.status = body.status
    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "name must not be blank")
        eng.name = name
    if body.description is not None:
        eng.description = body.description

    try:
        await db.commit()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "An engagement with that name exists"
        ) from exc
    await db.refresh(eng)
    return eng


# --- scope ----------------------------------------------------------------------------------


@router.get("/{engagement_id}/scope", response_model=list[ScopeEntryOut])
async def list_scope(engagement_id: uuid.UUID, db: DbDep, user: OperatorDep):
    eng = await _get_engagement(db, user, engagement_id)
    rows = await db.scalars(
        select(ScopeEntry)
        .where(ScopeEntry.engagement_id == eng.id, ScopeEntry.removed_at.is_(None))
        .order_by(ScopeEntry.mode, ScopeEntry.kind, ScopeEntry.value)
    )
    return list(rows)


@router.post(
    "/{engagement_id}/scope", response_model=ScopeEntryOut, status_code=status.HTTP_201_CREATED
)
async def add_scope_entry(
    engagement_id: uuid.UUID, body: ScopeEntryCreate, db: DbDep, user: OperatorDep
):
    eng = await _get_engagement(db, user, engagement_id)
    _require_editable(eng)
    try:
        normalized = normalize_scope_value(body.value, body.mode)
    except ScopeValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    entry = ScopeEntry(
        engagement_id=eng.id,
        kind=normalized.kind,
        value=normalized.value,
        mode=body.mode,
        note=body.note,
        created_by=user.id,
    )
    db.add(entry)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{normalized.value} is already in scope as {body.mode}"
        ) from exc
    db.add(_change(entry, user, ScopeAction.ADD, body.reason))
    await db.commit()
    await db.refresh(entry)
    return entry


@router.delete("/{engagement_id}/scope/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_scope_entry(
    engagement_id: uuid.UUID,
    entry_id: uuid.UUID,
    body: ScopeEntryRemove,
    db: DbDep,
    user: OperatorDep,
):
    eng = await _get_engagement(db, user, engagement_id)
    _require_editable(eng)
    entry = await db.scalar(
        select(ScopeEntry).where(
            ScopeEntry.id == entry_id,
            ScopeEntry.engagement_id == eng.id,
            ScopeEntry.removed_at.is_(None),
        )
    )
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scope entry not found")
    entry.removed_at = datetime.now(UTC)
    entry.removed_by = user.id
    db.add(_change(entry, user, ScopeAction.REMOVE, body.reason))
    await db.commit()


@router.get("/{engagement_id}/scope/changes", response_model=list[ScopeChangeOut])
async def list_scope_changes(engagement_id: uuid.UUID, db: DbDep, user: OperatorDep):
    eng = await _get_engagement(db, user, engagement_id)
    rows = await db.scalars(
        select(ScopeChange)
        .where(ScopeChange.engagement_id == eng.id)
        .order_by(ScopeChange.created_at, ScopeChange.id)
    )
    return list(rows)


def _change(entry: ScopeEntry, user, action: ScopeAction, reason: str) -> ScopeChange:
    return ScopeChange(
        engagement_id=entry.engagement_id,
        scope_entry_id=entry.id,
        user_id=user.id,
        action=action,
        kind=entry.kind,
        value=entry.value,
        mode=entry.mode,
        reason=reason.strip(),
    )


# --- testing windows ------------------------------------------------------------------------


@router.get("/{engagement_id}/windows", response_model=list[WindowOut])
async def list_windows(engagement_id: uuid.UUID, db: DbDep, user: OperatorDep):
    eng = await _get_engagement(db, user, engagement_id)
    rows = await db.scalars(
        select(TestingWindow)
        .where(TestingWindow.engagement_id == eng.id)
        .order_by(TestingWindow.created_at)
    )
    return list(rows)


@router.post(
    "/{engagement_id}/windows", response_model=WindowOut, status_code=status.HTTP_201_CREATED
)
async def add_window(engagement_id: uuid.UUID, body: WindowCreate, db: DbDep, user: OperatorDep):
    eng = await _get_engagement(db, user, engagement_id)
    _require_editable(eng)
    window = TestingWindow(engagement_id=eng.id, **body.model_dump())
    db.add(window)
    await db.commit()
    await db.refresh(window)
    return window


@router.delete("/{engagement_id}/windows/{window_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_window(
    engagement_id: uuid.UUID, window_id: uuid.UUID, db: DbDep, user: OperatorDep
):
    eng = await _get_engagement(db, user, engagement_id)
    _require_editable(eng)
    window = await db.scalar(
        select(TestingWindow).where(
            TestingWindow.id == window_id, TestingWindow.engagement_id == eng.id
        )
    )
    if window is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Testing window not found")
    await db.delete(window)
    await db.commit()


# --- authorization --------------------------------------------------------------------------


@router.get("/{engagement_id}/authorization", response_model=AuthorizationOut)
async def get_authorization(engagement_id: uuid.UUID, db: DbDep, user: OperatorDep):
    eng = await _get_engagement(db, user, engagement_id)
    auth = await db.scalar(select(Authorization).where(Authorization.engagement_id == eng.id))
    if auth is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No authorization recorded")
    return auth


@router.put("/{engagement_id}/authorization", response_model=AuthorizationOut)
async def put_authorization(
    engagement_id: uuid.UUID, body: AuthorizationIn, db: DbDep, user: OperatorDep
):
    eng = await _get_engagement(db, user, engagement_id)
    _require_editable(eng)
    auth = await db.scalar(select(Authorization).where(Authorization.engagement_id == eng.id))
    if auth is None:
        auth = Authorization(engagement_id=eng.id, **body.model_dump())
        db.add(auth)
    else:
        for field, value in body.model_dump().items():
            setattr(auth, field, value)
    await db.commit()
    await db.refresh(auth)
    return auth
