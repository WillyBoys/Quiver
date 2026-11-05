"""Append-only event log (Blueprint §5.2): policy decisions, kill switch changes, and later job
status, agent messages, and graph changes. Drives the dashboard and the audit trail."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from quiver.core.models.base import Base, IdMixin


class Event(IdMixin, Base):
    __tablename__ = "events"
    __table_args__ = (Index("ix_events_engagement_id_created_at", "engagement_id", "created_at"),)

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), index=True)
    # None for organization-wide events such as the global kill switch.
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("engagements.id"))
    # The operator who caused it; None for events raised by the platform itself.
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    kind: Mapped[str] = mapped_column(String(64), index=True)  # e.g. "policy.decision"
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
