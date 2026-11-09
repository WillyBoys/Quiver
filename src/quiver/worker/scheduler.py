"""The job scheduler: the worker's main loop (Blueprint §6).

Every tick, in order:
1. collect   results the executor reported (running, then a final status);
2. cancel    jobs hit by a kill switch, an operator's cancel, or a scope change that now
             denies them (running jobs get a cancel file; waiting jobs are just cancelled);
3. gate      due jobs (new, approved, or whose deferral ended), and hand allowed ones to the
             executor by writing their spec;
4. watchdog  jobs the executor never started or never finished are marked lost.

Separately, the parse loop turns the output of succeeded jobs into graph records (one job per
transaction). It runs beside the tick, so a large result never holds up gating, and a parser
failure only marks that job's parse as failed.

Every job is gated immediately before it is handed over, so scope, windows, the kill switch,
and limits are always current. An approval covers exactly the reasons the operator saw.
"""

import asyncio
import contextlib
import logging
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from quiver.core.config import Settings
from quiver.core.models import (
    FINAL_JOB_STATUSES,
    ApprovalRequest,
    ApprovalStatus,
    Engagement,
    EngagementStatus,
    Event,
    Job,
    JobStatus,
    Organization,
    ParseStatus,
)
from quiver.core.policy import (
    ActionRequest,
    ToolRegistry,
    Verdict,
    apply_approval,
    approval_reasons,
    target_keys,
)
from quiver.core.policy.providers import ProviderIndex
from quiver.core.policy.resolve import DnsResolver, Resolver
from quiver.core.policy.store import gate
from quiver.worker import handoff, queue
from quiver.worker.parsing import record_parsed
from quiver.worker.registry import default_parsers, default_registry
from quiver.worker.tracks.external.parsers import Parser

log = logging.getLogger("quiver.worker")

# How long to wait before retrying a job whose spec could not be written.
DISPATCH_RETRY = timedelta(seconds=15)
# Extra time past the hard timeout before a silent running job is considered lost.
RESULT_GRACE = timedelta(seconds=60)
# Jobs parsed per pass of the parse loop before it checks for shutdown.
PARSE_BATCH = 10


class Scheduler:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        settings: Settings,
        *,
        registry: ToolRegistry | None = None,
        resolver: Resolver | None = None,
        providers: ProviderIndex | None = None,
        parsers: Mapping[str, Parser] | None = None,
        clock=lambda: datetime.now(UTC),
    ):
        self.sessionmaker = sessionmaker
        self.settings = settings
        self.registry = registry or default_registry()
        self.resolver = resolver or DnsResolver()
        self.providers = providers
        self.parsers = default_parsers() if parsers is None else parsers
        self.clock = clock
        self._orgs: dict[uuid.UUID, uuid.UUID] = {}

    async def run(self, stop: asyncio.Event) -> None:
        await asyncio.gather(self._loop(stop, self.tick), self._loop(stop, self.parse))

    async def _loop(self, stop: asyncio.Event, step) -> None:
        while not stop.is_set():
            try:
                await step()
            except Exception:
                log.exception("scheduler %s failed", step.__name__)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), self.settings.scheduler_interval)

    async def tick(self) -> None:
        await self.collect()
        await self.cancellations()
        await self.gate_due()
        await self.watchdog()

    # --- 1. collect -----------------------------------------------------------------------

    async def collect(self) -> None:
        async with self.sessionmaker() as db:
            for job in await self._locked(db, Job.status.in_(queue.ACTIVE)):
                state = handoff.read_state(self.settings.job_output_dir, str(job.id))
                if state.result is not None:
                    r = state.result
                    if job.status is JobStatus.DISPATCHED:  # finished between two ticks
                        await self._status(db, job, JobStatus.RUNNING, "started")
                    job.started_at = job.started_at or r["started_at"] or state.started_at
                    job.finished_at = r["finished_at"] or self.clock()
                    job.exit_code = r["exit_code"]
                    job.output_bytes = r["output_bytes"]
                    job.truncated = r["truncated"]
                    await self._status(db, job, JobStatus(r["status"]), r["reason"])
                    if job.status is JobStatus.SUCCEEDED and job.tool in self.parsers:
                        job.parse_status = ParseStatus.PENDING
                    handoff.cleanup(self.settings.job_spec_dir, str(job.id))
                elif state.started_at is not None and job.status is JobStatus.DISPATCHED:
                    job.started_at = state.started_at
                    await self._status(db, job, JobStatus.RUNNING, "started")
            await db.commit()

    # --- 2. cancel ------------------------------------------------------------------------

    async def cancellations(self) -> None:
        async with self.sessionmaker() as db:
            now = self.clock()
            stopped = (
                select(Engagement.id)
                .join(Organization, Organization.id == Engagement.org_id)
                .where(
                    or_(
                        Engagement.kill_switch_at.is_not(None),
                        Organization.kill_switch_at.is_not(None),
                        Engagement.status == EngagementStatus.ARCHIVED,
                    )
                )
            )
            for job in await self._locked(
                db, Job.engagement_id.in_(stopped), Job.status.not_in(FINAL_JOB_STATUSES)
            ):
                await self._cancel(db, job, now, "kill switch engaged")

            # Operator cancels of running jobs: the API records them, the cancel file is ours.
            for job in await self._locked(
                db, Job.cancel_requested_at.is_not(None), Job.status.in_(queue.ACTIVE)
            ):
                handoff.request_cancel(self.settings.job_spec_dir, str(job.id))

            # Scope changed since a running job was gated: it must still pass.
            changed = select(Engagement.id).where(Engagement.scope_changed_at.is_not(None))
            for job in await self._locked(
                db,
                Job.status.in_(queue.ACTIVE),
                Job.cancel_requested_at.is_(None),
                Job.engagement_id.in_(changed),
            ):
                eng = await db.get(Engagement, job.engagement_id)
                if job.gated_at is not None and eng.scope_changed_at <= job.gated_at:
                    continue
                decision = await gate(
                    db,
                    _request(job),
                    self.registry,
                    resolver=self.resolver,
                    providers=self.providers,
                    now=now,
                )
                job.gated_at = now
                if decision.verdict is Verdict.DENY:
                    await self._cancel(db, job, now, f"scope changed: {decision.reason}")
            await db.commit()

    async def _cancel(self, db: AsyncSession, job: Job, now: datetime, reason: str) -> None:
        if job.status in queue.ACTIVE:
            handoff.request_cancel(self.settings.job_spec_dir, str(job.id))
            if job.cancel_requested_at is None:
                job.cancel_requested_at = now
                await self._event(db, job, "job.cancel_requested", reason)
            return
        job.finished_at = now
        await self._status(db, job, JobStatus.CANCELLED, reason)
        await self._close_pending_approvals(db, job, now)

    # --- 3. gate --------------------------------------------------------------------------

    async def gate_due(self) -> None:
        async with self.sessionmaker() as db:
            now = self.clock()
            for job in await queue.claim_due(db, now):
                await self._gate(db, job, now)
            await db.commit()

    async def _gate(self, db: AsyncSession, job: Job, now: datetime) -> None:
        load = await queue.engagement_load(db, job.engagement_id, now)
        try:
            decision = await gate(
                db,
                _request(job),
                self.registry,
                resolver=self.resolver,
                providers=self.providers,
                now=now,
                load=load,
            )
        except LookupError:
            job.finished_at = now
            await self._status(db, job, JobStatus.DENIED, "engagement not found")
            return
        approval = await self._current_approval(db, job, now)
        if approval is not None and decision.verdict is Verdict.NEEDS_APPROVAL:
            decision = apply_approval(decision, approval.reasons)

        job.gated_at = now
        job.targets = target_keys(decision.targets)
        job.resolutions = {host: list(addresses) for host, addresses in decision.resolutions}
        job.defer_until = None

        if decision.verdict is Verdict.ALLOW:
            try:
                handoff.write_spec(
                    self.settings.job_spec_dir,
                    str(job.id),
                    list(job.argv),
                    idle_timeout=self.settings.job_idle_timeout,
                    hard_timeout=self.settings.job_hard_timeout,
                    output_cap=self.settings.job_output_cap,
                    stdin=list(job.stdin or []),
                )
            except OSError as exc:
                log.error("job %s: cannot write spec: %s", job.id, exc)
                job.defer_until = now + DISPATCH_RETRY
                await self._status(db, job, JobStatus.DEFERRED, f"could not hand over: {exc}")
                return
            job.dispatched_at = now
            await self._status(db, job, JobStatus.DISPATCHED, decision.reason)
        elif decision.verdict is Verdict.DEFER:
            job.defer_until = decision.defer_until
            await self._status(db, job, JobStatus.DEFERRED, decision.reason)
        elif decision.verdict is Verdict.NEEDS_APPROVAL:
            await self._request_approval(db, job, approval_reasons(decision), now)
            await self._status(db, job, JobStatus.AWAITING_APPROVAL, decision.reason)
        else:
            job.finished_at = now
            await self._status(db, job, JobStatus.DENIED, decision.reason)

    async def _current_approval(
        self, db: AsyncSession, job: Job, now: datetime
    ) -> ApprovalRequest | None:
        """The newest approval that is still valid. Approvals past their expiry are marked
        expired, so the operator is asked again."""
        rows = await db.scalars(
            select(ApprovalRequest)
            .where(
                ApprovalRequest.job_id == job.id,
                ApprovalRequest.status == ApprovalStatus.APPROVED,
            )
            .order_by(ApprovalRequest.decided_at.desc())
        )
        current = None
        for row in rows:
            if row.expires_at is not None and row.expires_at <= now:
                row.status = ApprovalStatus.EXPIRED
                await self._event(
                    db, job, "approval.expired", "approval expired before the job ran"
                )
            elif current is None:
                current = row
        return current

    async def _request_approval(
        self, db: AsyncSession, job: Job, reasons: list[str], now: datetime
    ) -> None:
        pending = await db.scalar(
            select(ApprovalRequest).where(
                ApprovalRequest.job_id == job.id,
                ApprovalRequest.status == ApprovalStatus.PENDING,
            )
        )
        if pending is not None:
            if pending.reasons != reasons:  # what needs approval changed before a decision
                pending.reasons = reasons
                pending.requested_at = now
            return
        db.add(
            ApprovalRequest(
                job_id=job.id,
                engagement_id=job.engagement_id,
                reasons=reasons,
                status=ApprovalStatus.PENDING,
                requested_at=now,
            )
        )
        await self._event(db, job, "approval.requested", "; ".join(reasons))

    async def _close_pending_approvals(self, db: AsyncSession, job: Job, now: datetime) -> None:
        rows = await db.scalars(
            select(ApprovalRequest).where(
                ApprovalRequest.job_id == job.id,
                ApprovalRequest.status == ApprovalStatus.PENDING,
            )
        )
        for row in rows:
            row.status = ApprovalStatus.EXPIRED
            row.decided_at = now
            row.note = "job cancelled before a decision"

    # --- parse (its own loop) ---------------------------------------------------------------

    async def parse(self) -> int:
        """Parse up to PARSE_BATCH succeeded jobs, one transaction each. Returns how many."""
        done = 0
        for _ in range(PARSE_BATCH):
            async with self.sessionmaker() as db:
                job = await db.scalar(
                    select(Job)
                    .where(Job.parse_status == ParseStatus.PENDING)
                    .order_by(Job.finished_at, Job.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if job is None:
                    break
                await self._parse(db, job)
                await db.commit()
                done += 1
        return done

    async def _parse(self, db: AsyncSession, job: Job) -> None:
        now = self.clock()
        parser = self.parsers.get(job.tool)
        if parser is None:
            job.parse_status = ParseStatus.NOT_APPLICABLE
            return
        output = handoff.read_output(
            self.settings.job_output_dir, str(job.id), self.settings.job_output_cap
        )
        if output is None:
            await self._parse_failed(db, job, now, "output is missing or not a regular file")
            return
        try:
            async with db.begin_nested():  # a failure undoes only this job's graph writes
                parsed = parser(output.data, dict(job.params))
                recorded = await record_parsed(
                    db,
                    parsed,
                    engagement_id=job.engagement_id,
                    source=f"parser:{job.tool}",
                    job_id=job.id,
                    run_id=job.run_id,
                    now=now,
                )
        except Exception as exc:  # a parser bug or a record() rejection: never crash the loop
            log.exception("job %s: parsing %s output failed", job.id, job.tool)
            await self._parse_failed(db, job, now, f"{type(exc).__name__}: {exc}")
            return
        job.parse_status = ParseStatus.PARSED
        job.parsed_at = now
        job.parse_error = ""
        await self._event(
            db,
            job,
            "job.parsed",
            f"{recorded.entities_created} new, {recorded.entities_updated} updated",
            entities_created=recorded.entities_created,
            entities_updated=recorded.entities_updated,
            relationships=recorded.relationships,
            findings=recorded.findings,
            suggestions=recorded.suggestions,
            skipped=parsed.skipped,
            capped=parsed.capped,
            truncated=output.truncated or job.truncated,
            notes=dict(parsed.notes),
        )

    async def _parse_failed(self, db: AsyncSession, job: Job, now: datetime, error: str) -> None:
        job.parse_status = ParseStatus.FAILED
        job.parsed_at = now
        job.parse_error = error[:1000]
        await self._event(db, job, "job.parse_failed", job.parse_error)

    # --- 4. watchdog ----------------------------------------------------------------------

    async def watchdog(self) -> None:
        async with self.sessionmaker() as db:
            now = self.clock()
            never_started = now - timedelta(seconds=self.settings.dispatch_timeout)
            never_finished = now - timedelta(seconds=self.settings.job_hard_timeout) - RESULT_GRACE
            for job in await self._locked(
                db,
                or_(
                    (Job.status == JobStatus.DISPATCHED) & (Job.dispatched_at <= never_started),
                    (Job.status == JobStatus.RUNNING) & (Job.started_at <= never_finished),
                ),
            ):
                started = job.status is JobStatus.RUNNING
                handoff.request_cancel(self.settings.job_spec_dir, str(job.id))
                job.finished_at = now
                await self._status(
                    db,
                    job,
                    JobStatus.LOST,
                    "the executor never reported a result"
                    if started
                    else "the executor never started the job",
                )
            await db.commit()

    # --- helpers --------------------------------------------------------------------------

    async def _locked(self, db: AsyncSession, *where) -> list[Job]:
        rows = await db.scalars(
            select(Job).where(*where).order_by(Job.created_at).with_for_update(skip_locked=True)
        )
        return list(rows)

    async def _status(self, db: AsyncSession, job: Job, status: JobStatus, reason: str) -> None:
        job.status = status
        job.reason = reason
        await self._event(db, job, f"job.{status}", reason)

    async def _event(self, db: AsyncSession, job: Job, kind: str, reason: str, **extra) -> None:
        org_id = self._orgs.get(job.engagement_id)
        if org_id is None:
            org_id = await db.scalar(
                select(Engagement.org_id).where(Engagement.id == job.engagement_id)
            )
            self._orgs[job.engagement_id] = org_id
        db.add(
            Event(
                org_id=org_id,
                engagement_id=job.engagement_id,
                kind=kind,
                payload={"job_id": str(job.id), "tool": job.tool, "reason": reason, **extra},
            )
        )


def _request(job: Job) -> ActionRequest:
    return ActionRequest(
        job.engagement_id,
        job.tool,
        dict(job.params),
        tuple(job.argv),
        job.requester,
        stdin=tuple(job.stdin or ()),
    )
