"""Postgres-backed job queue (Blueprint §6): enqueue, and claim due work with
SELECT … FOR UPDATE SKIP LOCKED so several schedulers never take the same job."""

import uuid
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from quiver.core.models import Job, JobStatus
from quiver.core.policy import Load, ToolRegistry

# A job deferred with no end time (no window, paused engagement) is gated again this often.
OPEN_DEFER_RETRY = timedelta(seconds=60)
ACTIVE = (JobStatus.DISPATCHED, JobStatus.RUNNING)


async def enqueue(
    db: AsyncSession,
    *,
    engagement_id: uuid.UUID,
    tool: str,
    params: dict[str, Any],
    requester: str,
    registry: ToolRegistry,
) -> Job:
    """Record a job request. It is gated by the scheduler, never here.

    The argv is built now from the tool's structured parameters, so what the operator or agent
    sees is exactly what the gate checks and the executor runs. Raises ValueError when a known
    tool cannot use the parameters; an unknown tool is recorded and the gate denies it.
    """
    spec = registry.get(tool)
    argv = spec.argv_for(params) if spec is not None and spec.build_argv else []
    job = Job(
        engagement_id=engagement_id,
        tool=tool,
        params=params,
        argv=argv,
        requester=requester,
        status=JobStatus.SUBMITTED,
    )
    db.add(job)
    await db.flush()
    return job


async def claim_due(db: AsyncSession, now: datetime, limit: int = 20) -> list[Job]:
    """Lock and return jobs that need gating now, oldest first. Locks are held until the
    caller's transaction ends; rows another scheduler holds are skipped."""
    due = or_(
        Job.status.in_([JobStatus.SUBMITTED, JobStatus.QUEUED]),
        and_(
            Job.status == JobStatus.DEFERRED,
            or_(
                Job.defer_until <= now,
                and_(Job.defer_until.is_(None), Job.gated_at <= now - OPEN_DEFER_RETRY),
            ),
        ),
    )
    rows = await db.scalars(
        select(Job)
        .where(due)
        .order_by(Job.created_at, Job.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    return list(rows)


async def engagement_load(db: AsyncSession, engagement_id: uuid.UUID, now: datetime) -> Load:
    active = list(
        await db.scalars(
            select(Job.targets).where(Job.engagement_id == engagement_id, Job.status.in_(ACTIVE))
        )
    )
    started = await db.scalar(
        select(func.count(Job.id)).where(
            Job.engagement_id == engagement_id, Job.dispatched_at >= now - timedelta(minutes=1)
        )
    )
    targets = Counter(key for keys in active for key in (keys or []))
    return Load(running=len(active), started_last_minute=started or 0, running_targets=targets)
