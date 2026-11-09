"""Approvals: operator decisions on jobs the gate would not allow by itself (Blueprint §4).

A request shows the exact command and targets first, and the gate's reasons. Approving covers
those reasons only, for `approval_ttl_hours`; the worker gates the job again before it runs.
Agent reasoning (step 15) and the dashboard (step 20) build on this.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from quiver.api.auth import DbDep, OperatorDep, require_operator
from quiver.api.engagements import OrmOut, get_engagement_or_404, require_editable
from quiver.core.models import ApprovalRequest, ApprovalStatus, Event, Job, JobStatus

router = APIRouter(
    prefix="/engagements/{engagement_id}/approvals",
    tags=["approvals"],
    dependencies=[Depends(require_operator)],
)


class ApprovalOut(OrmOut):
    id: uuid.UUID
    job_id: uuid.UUID
    status: ApprovalStatus
    reasons: list[str]
    requested_at: datetime
    decided_at: datetime | None
    note: str
    expires_at: datetime | None
    # The action itself, first: what would run and against what.
    tool: str = ""
    argv: list[str] = Field(default_factory=list)
    stdin: list[str] = Field(default_factory=list)  # input lines fed to the tool
    targets: list[str] = Field(default_factory=list)

    @classmethod
    def of(cls, row: ApprovalRequest, job: Job) -> "ApprovalOut":
        out = cls.model_validate(row)
        out.tool, out.argv, out.targets = job.tool, list(job.argv), list(job.targets)
        out.stdin = list(job.stdin or [])
        return out


class Decision(BaseModel):
    note: str = Field(default="", max_length=2000)


@router.get("", response_model=list[ApprovalOut])
async def list_approvals(
    engagement_id: uuid.UUID,
    db: DbDep,
    user: OperatorDep,
    status_filter: Annotated[ApprovalStatus | None, Query(alias="status")] = None,
):
    eng = await get_engagement_or_404(db, user, engagement_id)
    stmt = (
        select(ApprovalRequest, Job)
        .join(Job, Job.id == ApprovalRequest.job_id)
        .where(ApprovalRequest.engagement_id == eng.id)
    )
    if status_filter is not None:
        stmt = stmt.where(ApprovalRequest.status == status_filter)
    rows = await db.execute(stmt.order_by(ApprovalRequest.requested_at, ApprovalRequest.id))
    return [ApprovalOut.of(a, j) for a, j in rows]


async def _decide(db, user, engagement_id, approval_id, body: Decision, approve: bool, ttl):
    eng = await get_engagement_or_404(db, user, engagement_id)
    require_editable(eng)
    approval = await db.scalar(
        select(ApprovalRequest)
        .where(ApprovalRequest.id == approval_id, ApprovalRequest.engagement_id == eng.id)
        .with_for_update()
    )
    if approval is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval request not found")
    if approval.status is not ApprovalStatus.PENDING:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Approval is already {approval.status}")
    job = await db.scalar(select(Job).where(Job.id == approval.job_id).with_for_update())
    now = datetime.now(UTC)
    approval.decided_at = now
    approval.decided_by = user.id
    approval.note = body.note.strip()
    if approve:
        approval.status = ApprovalStatus.APPROVED
        approval.expires_at = now + ttl
        if job.status is JobStatus.AWAITING_APPROVAL:
            job.status = JobStatus.QUEUED  # gated again, with this approval, before it runs
            job.reason = f"approved by {user.username}"
    else:
        approval.status = ApprovalStatus.DENIED
        if not job.status.final:
            job.status = JobStatus.CANCELLED
            job.reason = f"approval denied by {user.username}"
            job.finished_at = now
    db.add(
        Event(
            org_id=user.org_id,
            engagement_id=eng.id,
            user_id=user.id,
            kind=f"approval.{approval.status}",
            payload={
                "approval_id": str(approval.id),
                "job_id": str(job.id),
                "argv": job.argv,
                "reasons": approval.reasons,
                "note": approval.note,
            },
        )
    )
    await db.commit()
    await db.refresh(approval)
    await db.refresh(job)
    return ApprovalOut.of(approval, job)


def _ttl(request: Request) -> timedelta:
    return timedelta(hours=request.app.state.settings.approval_ttl_hours)


@router.post("/{approval_id}/approve", response_model=ApprovalOut)
async def approve(
    engagement_id: uuid.UUID,
    approval_id: uuid.UUID,
    body: Decision,
    request: Request,
    db: DbDep,
    user: OperatorDep,
):
    return await _decide(db, user, engagement_id, approval_id, body, True, _ttl(request))


@router.post("/{approval_id}/deny", response_model=ApprovalOut)
async def deny(
    engagement_id: uuid.UUID,
    approval_id: uuid.UUID,
    body: Decision,
    request: Request,
    db: DbDep,
    user: OperatorDep,
):
    """Deny the request; the job is cancelled."""
    return await _decide(db, user, engagement_id, approval_id, body, False, _ttl(request))
