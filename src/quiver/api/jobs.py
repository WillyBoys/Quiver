"""Jobs: on-demand tool runs (Blueprint §8) and their status.

Submitting only records the request. The worker gates it (the API never resolves DNS or
decides policy) and the executor runs it; neither happens in this process.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from quiver.api.auth import DbDep, OperatorDep, require_operator
from quiver.api.engagements import OrmOut, get_engagement_or_404, require_editable
from quiver.core.models import (
    ApprovalRequest,
    ApprovalStatus,
    Event,
    Job,
    JobStatus,
    ParseStatus,
)
from quiver.worker.queue import ACTIVE, enqueue
from quiver.worker.registry import default_registry

router = APIRouter(
    prefix="/engagements/{engagement_id}/jobs",
    tags=["jobs"],
    dependencies=[Depends(require_operator)],
)

# Jobs that have not reached the executor can be cancelled directly.
WAITING = (
    JobStatus.SUBMITTED,
    JobStatus.QUEUED,
    JobStatus.DEFERRED,
    JobStatus.AWAITING_APPROVAL,
)


class JobCreate(BaseModel):
    tool: str = Field(min_length=1, max_length=100)
    params: dict[str, Any] = Field(default_factory=dict)


class JobOut(OrmOut):
    id: uuid.UUID
    tool: str
    params: dict
    argv: list[str]
    stdin: list[str]
    requester: str
    status: JobStatus
    reason: str
    defer_until: datetime | None
    targets: list[str]
    resolutions: dict
    created_at: datetime
    gated_at: datetime | None
    dispatched_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    exit_code: int | None
    output_bytes: int
    truncated: bool
    cancel_requested_at: datetime | None
    parse_status: ParseStatus
    parsed_at: datetime | None
    parse_error: str


@router.post("", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
async def submit_job(engagement_id: uuid.UUID, body: JobCreate, db: DbDep, user: OperatorDep):
    """Queue a tool run. The response is the submitted job; poll it for the gate's verdict."""
    eng = await get_engagement_or_404(db, user, engagement_id)
    require_editable(eng)
    try:
        job = await enqueue(
            db,
            engagement_id=eng.id,
            tool=body.tool,
            params=body.params,
            requester=f"operator:{user.username}",
            registry=default_registry(),
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    db.add(
        Event(
            org_id=user.org_id,
            engagement_id=eng.id,
            user_id=user.id,
            kind="job.submitted",
            payload={
                "job_id": str(job.id),
                "tool": job.tool,
                "argv": job.argv,
                "stdin": job.stdin,
            },
        )
    )
    await db.commit()
    await db.refresh(job)
    return job


@router.get("", response_model=list[JobOut])
async def list_jobs(
    engagement_id: uuid.UUID,
    db: DbDep,
    user: OperatorDep,
    status_filter: Annotated[JobStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    eng = await get_engagement_or_404(db, user, engagement_id)
    stmt = select(Job).where(Job.engagement_id == eng.id)
    if status_filter is not None:
        stmt = stmt.where(Job.status == status_filter)
    rows = await db.scalars(stmt.order_by(Job.created_at.desc(), Job.id).limit(limit))
    return list(rows)


async def get_job_or_404(db, eng, job_id: uuid.UUID, *, lock=False) -> Job:
    stmt = select(Job).where(Job.id == job_id, Job.engagement_id == eng.id)
    if lock:
        stmt = stmt.with_for_update()
    job = await db.scalar(stmt)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Job not found")
    return job


@router.get("/{job_id}", response_model=JobOut)
async def get_job(engagement_id: uuid.UUID, job_id: uuid.UUID, db: DbDep, user: OperatorDep):
    eng = await get_engagement_or_404(db, user, engagement_id)
    return await get_job_or_404(db, eng, job_id)


@router.post("/{job_id}/cancel", response_model=JobOut)
async def cancel_job(engagement_id: uuid.UUID, job_id: uuid.UUID, db: DbDep, user: OperatorDep):
    """Cancel a job. Waiting jobs are cancelled at once; a running job is stopped by the
    worker and reported as cancelled when the executor confirms."""
    eng = await get_engagement_or_404(db, user, engagement_id)
    job = await get_job_or_404(db, eng, job_id, lock=True)
    now = datetime.now(UTC)
    if job.status in WAITING:
        job.status = JobStatus.CANCELLED
        job.reason = f"cancelled by {user.username}"
        job.finished_at = now
        pending = await db.scalars(
            select(ApprovalRequest).where(
                ApprovalRequest.job_id == job.id,
                ApprovalRequest.status == ApprovalStatus.PENDING,
            )
        )
        for request in pending:
            request.status = ApprovalStatus.EXPIRED
            request.decided_at = now
            request.note = "job cancelled before a decision"
    elif job.status in ACTIVE:
        job.cancel_requested_at = job.cancel_requested_at or now
    else:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Job is already {job.status}")
    db.add(
        Event(
            org_id=user.org_id,
            engagement_id=eng.id,
            user_id=user.id,
            kind="job.cancel_requested",
            payload={"job_id": str(job.id), "tool": job.tool},
        )
    )
    await db.commit()
    await db.refresh(job)
    return job
