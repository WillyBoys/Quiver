from sqlalchemy import String, Text, DateTime, JSON, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base
from datetime import datetime, timezone
import uuid


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    target_scope: Mapped[list] = mapped_column(JSON, default=list)   # ["10.0.0.1", "example.com"]
    schedule: Mapped[str | None] = mapped_column(String, nullable=True)  # cron string; None = manual only
    status: Mapped[str] = mapped_column(String, default="paused", index=True)   # active / paused / completed / awaiting_approval
    risk_level: Mapped[str] = mapped_column(String, default="passive")   # approve_all / passive / active / autonomous
    ai_provider: Mapped[str] = mapped_column(String, default="local")   # local / claude
    session_id: Mapped[str | None] = mapped_column(String, ForeignKey("sessions.id"), nullable=True, index=True)
    last_agent_reasoning: Mapped[str] = mapped_column(Text, default="")  # most recent agent thought
    max_iterations: Mapped[int | None] = mapped_column(nullable=True)   # None = unlimited
    iteration_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc),
                                                  onupdate=lambda: datetime.now(timezone.utc))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id: Mapped[str] = mapped_column(String, ForeignKey("campaigns.id"), nullable=False, index=True)
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    reasoning: Mapped[str] = mapped_column(Text, default="")
    target: Mapped[str] = mapped_column(String, default="")
    status: Mapped[str] = mapped_column(String, default="pending", index=True)   # pending / approved / rejected / dismissed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
