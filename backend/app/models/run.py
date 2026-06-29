from sqlalchemy import String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base
from datetime import datetime, timezone
import uuid


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id: Mapped[str] = mapped_column(String, ForeignKey("sessions.id"), nullable=False)
    tool_id: Mapped[str] = mapped_column(String, ForeignKey("tools.id"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String, nullable=False)   # snapshot at run time
    command: Mapped[str] = mapped_column(Text, nullable=False)        # exact command string
    output: Mapped[str] = mapped_column(Text, default="")            # full stdout/stderr
    status: Mapped[str] = mapped_column(String, default="pending")   # pending/running/complete/error
    exit_code: Mapped[int | None] = mapped_column(nullable=True)
    param_values: Mapped[dict] = mapped_column(JSON, default=dict)   # {param_name: value}
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
