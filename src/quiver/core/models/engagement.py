"""Engagement layer (Blueprint §5.1): engagements, scope, testing windows, authorization."""

import uuid
from datetime import date, datetime, time
from enum import StrEnum

from sqlalchemy import (
    ARRAY,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    Time,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from quiver.core.models.base import Base, IdMixin, OwnedMixin, TimestampMixin
from quiver.core.scope import ScopeKind, ScopeMode


class EngagementStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class ScopeAction(StrEnum):
    ADD = "add"
    REMOVE = "remove"


def _enum(enum_cls: type[StrEnum], name: str) -> Enum:
    """Store enums as text with a CHECK constraint (no native Postgres enum types)."""
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=20,
        values_callable=lambda e: [m.value for m in e],
    )


class Engagement(IdMixin, TimestampMixin, OwnedMixin, Base):
    __tablename__ = "engagements"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_engagements_org_id_name"),)

    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    tracks: Mapped[list[str]] = mapped_column(ARRAY(String(20)))
    status: Mapped[EngagementStatus] = mapped_column(
        _enum(EngagementStatus, "engagement_status"), default=EngagementStatus.DRAFT
    )


class ScopeEntry(IdMixin, Base):
    """One include or exclude entry. The settings page (this table) is the only source of scope.

    Entries are never deleted: removal sets removed_at, so jobs and audit records that refer to
    an entry keep a valid reference. Every add and remove is also recorded as a ScopeChange.
    """

    __tablename__ = "scope_entries"
    __table_args__ = (
        # At most one active entry per (engagement, kind, value, mode).
        Index(
            "uq_scope_entries_active",
            "engagement_id",
            "kind",
            "value",
            "mode",
            unique=True,
            postgresql_where=text("removed_at IS NULL"),
        ),
    )

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), index=True)
    kind: Mapped[ScopeKind] = mapped_column(_enum(ScopeKind, "scope_kind"))
    value: Mapped[str] = mapped_column(String(2048))
    mode: Mapped[ScopeMode] = mapped_column(_enum(ScopeMode, "scope_mode"))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))


class ScopeChange(IdMixin, Base):
    """Append-only audit record of a scope edit: who, when, what, and why."""

    __tablename__ = "scope_changes"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), index=True)
    scope_entry_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scope_entries.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    action: Mapped[ScopeAction] = mapped_column(_enum(ScopeAction, "scope_action"))
    # Snapshot of the entry at the time of the change.
    kind: Mapped[ScopeKind] = mapped_column(_enum(ScopeKind, "scope_change_kind"))
    value: Mapped[str] = mapped_column(String(2048))
    mode: Mapped[ScopeMode] = mapped_column(_enum(ScopeMode, "scope_change_mode"))
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TestingWindow(IdMixin, Base):
    """When testing may run. No windows means no testing (the gate defers everything).

    days: ISO weekdays 1 (Mon) .. 7 (Sun), evaluated in `timezone`.
    end_time < start_time crosses midnight (the window belongs to the day it starts on).
    end_time == start_time means the whole day.
    """

    __tablename__ = "testing_windows"
    __test__ = False  # not a pytest test class, despite the name

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), index=True)
    timezone: Mapped[str] = mapped_column(String(64))
    days: Mapped[list[int]] = mapped_column(ARRAY(SmallInteger))
    start_time: Mapped[time] = mapped_column(Time)
    end_time: Mapped[time] = mapped_column(Time)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Authorization(IdMixin, TimestampMixin, Base):
    """Who authorized testing, and for which period. One per engagement.

    Uploading the signed document itself is not supported yet; reference it in `notes`.
    """

    __tablename__ = "authorizations"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), unique=True)
    authorized_by: Mapped[str] = mapped_column(String(200))
    authorizer_title: Mapped[str] = mapped_column(String(200), default="")
    authorizer_organization: Mapped[str] = mapped_column(String(200))
    contact: Mapped[str] = mapped_column(String(200), default="")
    authorized_on: Mapped[date] = mapped_column(Date)
    valid_from: Mapped[date | None] = mapped_column(Date)
    valid_until: Mapped[date | None] = mapped_column(Date)
    notes: Mapped[str] = mapped_column(Text, default="")
