from sqlalchemy import String, Text, DateTime, JSON, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base
from datetime import datetime, timezone
import uuid


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id: Mapped[str] = mapped_column(String, ForeignKey("campaigns.id"), nullable=False, index=True)
    session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    engagement_type: Mapped[str] = mapped_column(String, default="external")
    status: Mapped[str] = mapped_column(String, default="running", index=True)
    # running / paused / completed / error
    current_phase: Mapped[int] = mapped_column(Integer, default=1)
    phase_count: Mapped[int] = mapped_column(Integer, default=0)
    specialist_results: Mapped[dict] = mapped_column(JSON, default=dict)   # {phase_num: {role: summary}}
    synthesis_outputs: Mapped[list] = mapped_column(JSON, default=list)    # [{phase, directives}]
    skipped_phases: Mapped[list] = mapped_column(JSON, default=list)       # [{phase, name, reason}]
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc),
                                                  onupdate=lambda: datetime.now(timezone.utc))
