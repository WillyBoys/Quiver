"""Execution layer (Blueprint §5.2): jobs and the approvals they wait on."""

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from quiver.core.models.base import Base, IdMixin
from quiver.core.models.engagement import _enum


class JobStatus(StrEnum):
    SUBMITTED = "submitted"  # recorded, not gated yet
    QUEUED = "queued"  # allowed; waiting for the scheduler to hand it to the executor
    DEFERRED = "deferred"  # allowed but not now (window, paused, limits)
    AWAITING_APPROVAL = "awaiting_approval"
    DENIED = "denied"  # final: the gate said no
    DISPATCHED = "dispatched"  # spec written for the executor
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    LOST = "lost"  # the executor never reported a result

    @property
    def final(self) -> bool:
        return self in FINAL_JOB_STATUSES


FINAL_JOB_STATUSES = frozenset(
    {
        JobStatus.DENIED,
        JobStatus.SUCCEEDED,
        JobStatus.FAILED,
        JobStatus.TIMED_OUT,
        JobStatus.CANCELLED,
        JobStatus.LOST,
    }
)


class ParseStatus(StrEnum):
    """Whether a finished job's output has been turned into graph records."""

    NOT_APPLICABLE = "not_applicable"  # no parser for the tool, or the job did not succeed
    PENDING = "pending"  # succeeded; the parse stage has not run yet
    PARSED = "parsed"
    FAILED = "failed"  # the parser or recording failed; see parse_error


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"  # approved, but the job did not start in time; ask again


class Job(IdMixin, Base):
    """One tool execution. Raw output stays on disk (job output volume), never in the DB."""

    __tablename__ = "jobs"
    __table_args__ = (
        # The scheduler's claim query: due work in submission order.
        Index("ix_jobs_status_defer_until", "status", "defer_until"),
    )

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), index=True)
    tool: Mapped[str] = mapped_column(String(100))
    params: Mapped[dict] = mapped_column(JSONB, default=dict)
    argv: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Lines fed to the tool on standard input (target lists), fixed at submission like argv.
    stdin: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default=text("'[]'"))
    requester: Mapped[str] = mapped_column(String(200))
    status: Mapped[JobStatus] = mapped_column(
        _enum(JobStatus, "job_status"), default=JobStatus.SUBMITTED
    )
    reason: Mapped[str] = mapped_column(Text, default="")  # latest gate or executor reason
    defer_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Normalized targets from the latest gate decision (per-target limits) and the addresses
    # each hostname was pinned to for this run.
    targets: Mapped[list[str]] = mapped_column(JSONB, default=list)
    resolutions: Mapped[dict] = mapped_column(JSONB, default=dict)
    worker_label: Mapped[str] = mapped_column(String(50), default="local")
    # The run this job belongs to; None for on-demand jobs outside a run.
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    gated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None] = mapped_column()
    output_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    parse_status: Mapped[ParseStatus] = mapped_column(
        _enum(ParseStatus, "parse_status"),
        default=ParseStatus.NOT_APPLICABLE,
        server_default=ParseStatus.NOT_APPLICABLE.value,
    )
    parsed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    parse_error: Mapped[str] = mapped_column(Text, default="", server_default="")


class ApprovalRequest(IdMixin, Base):
    """An operator decision on a job the gate could not allow by itself.

    An approval covers exactly the reasons shown to the operator. If the gate later asks for
    approval for a different reason (another target, a changed pin), a new request is made.
    """

    __tablename__ = "approval_requests"
    __table_args__ = (
        # At most one open request per job.
        Index(
            "uq_approval_requests_pending",
            "job_id",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("jobs.id"), index=True)
    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), index=True)
    reasons: Mapped[list[str]] = mapped_column(JSONB, default=list)
    status: Mapped[ApprovalStatus] = mapped_column(
        _enum(ApprovalStatus, "approval_status"), default=ApprovalStatus.PENDING
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    note: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
