from sqlalchemy import String, Text, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base
from datetime import datetime, timezone
import uuid


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)      # IP / domain / range
    scope: Mapped[str] = mapped_column(Text, default="")             # notes on scope
    engagement_type: Mapped[str] = mapped_column(String, default="external")  # external/internal/web
    notes: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String, default="active")    # active / archived
    findings: Mapped[list] = mapped_column(JSON, default=list)        # [{title, severity, notes}]
    checklist_state: Mapped[dict] = mapped_column(JSON, default=dict) # {phase_checks: {key: bool}}
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc),
                                                  onupdate=lambda: datetime.now(timezone.utc))
