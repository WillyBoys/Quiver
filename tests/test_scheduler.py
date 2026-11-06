"""The job pipeline end to end: API or enqueue → scheduler (gate, approvals, limits,
cancellation, watchdog) → the real executor, in-process, on temporary directories."""

import asyncio
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from quiver.core.config import Settings
from quiver.core.db import make_engine, make_sessionmaker
from quiver.core.models import ApprovalRequest, Event, Job, JobStatus
from quiver.core.policy import RUN_COMMAND, RiskTier, TargetParam, ToolRegistry, ToolSpec
from quiver.core.policy.providers import ProviderIndex
from quiver.core.policy.resolve import StaticResolver
from quiver.executor import protocol as p
from quiver.executor.runner import Executor
from quiver.worker import queue
from quiver.worker.scheduler import Scheduler
from tests.api_helpers import activate

PY = sys.executable
PATH_ENV = f"{Path(PY).parent}:/usr/bin:/bin"
DNS = StaticResolver({"www.example.com": ["203.0.113.10"]})


def _scan_argv(params):
    return [PY, "-c", params.get("code", "print('scanned')"), params["target"]]


REGISTRY = ToolRegistry(
    [
        RUN_COMMAND,
        ToolSpec("probe", RiskTier.DISCOVERY, {"target": TargetParam()}, build_argv=_scan_argv),
    ]
)
SLEEP = "import time; time.sleep(30)"


@pytest.fixture
def settings(migrated_db, secret_key_file, tmp_path):
    specs, output = tmp_path / "specs", tmp_path / "output"
    specs.mkdir()
    output.mkdir()
    return Settings(
        database_url=migrated_db,
        secret_key_file=secret_key_file,
        job_spec_dir=specs,
        job_output_dir=output,
        job_idle_timeout=30,
        job_hard_timeout=30,
        approval_ttl_hours=1,
        dispatch_timeout=5,
    )


@pytest.fixture
def executor(settings):
    ex = Executor(settings.job_spec_dir, settings.job_output_dir, path_env=PATH_ENV)
    yield ex
    ex.shutdown()  # cancels anything a failed test left running


@pytest.fixture
def active(client, eng):
    activate(client, eng, "*.example.com", "203.0.113.0/24")
    return eng


def tick(settings, *, resolver=DNS, clock=None, registry=REGISTRY):
    async def go():
        engine = make_engine(settings)
        try:
            scheduler = Scheduler(
                make_sessionmaker(engine),
                settings,
                registry=registry,
                resolver=resolver,
                providers=ProviderIndex({}, {}),
                **({"clock": clock} if clock else {}),
            )
            await scheduler.tick()
        finally:
            await engine.dispose()

    asyncio.run(go())


def submit(run_db, eng, tool="probe", **params):
    async def go(db):
        job = await queue.enqueue(
            db,
            engagement_id=uuid.UUID(eng["id"]),
            tool=tool,
            params=params,
            requester="test",
            registry=REGISTRY,
        )
        await db.commit()
        return job.id

    return run_db(go)


def get_job(run_db, job_id) -> Job:
    return run_db(lambda db: db.get(Job, job_id))


def approvals(run_db, job_id) -> list[ApprovalRequest]:
    async def go(db):
        rows = await db.scalars(
            select(ApprovalRequest)
            .where(ApprovalRequest.job_id == job_id)
            .order_by(ApprovalRequest.requested_at)
        )
        return list(rows)

    return run_db(go)


def drive(settings, executor, run_db, job_id, until, timeout=15, **kwargs) -> Job:
    """Alternate scheduler ticks and executor polls until the job reaches a status in `until`."""
    deadline = time.monotonic() + timeout
    job = None
    while time.monotonic() < deadline:
        tick(settings, **kwargs)
        if executor is not None:
            executor.poll_once()
        job = get_job(run_db, job_id)
        if job.status in until:
            return job
        time.sleep(0.05)
    raise AssertionError(f"job stuck in {job.status}: {job.reason}")


def job_events(run_db, job_id) -> list[tuple[str, str]]:
    async def go(db):
        rows = await db.scalars(select(Event).order_by(Event.seq))
        return [
            (e.kind, e.payload.get("reason", ""))
            for e in rows
            if e.payload.get("job_id") == str(job_id)
        ]

    return run_db(go)


# --- the happy path and the gate ------------------------------------------------------------


def test_allowed_job_runs_to_success(active, settings, executor, run_db):
    job_id = submit(run_db, active, target="203.0.113.5")
    tick(settings)
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.DISPATCHED
    assert job.targets == ["203.0.113.5"]
    assert p.spec_path(settings.job_spec_dir, str(job_id)).exists()

    job = drive(settings, executor, run_db, job_id, {JobStatus.SUCCEEDED})
    assert job.exit_code == 0 and job.output_bytes > 0
    assert job.started_at and job.finished_at
    out = (settings.job_output_dir / str(job_id) / p.OUTPUT).read_text()
    assert out == "scanned\n"
    assert not p.spec_path(settings.job_spec_dir, str(job_id)).exists()  # cleaned up
    kinds = [kind for kind, _ in job_events(run_db, job_id)]
    assert kinds[-3:] == ["job.dispatched", "job.running", "job.succeeded"]


def test_out_of_scope_job_is_denied_and_never_handed_over(active, settings, run_db):
    job_id = submit(run_db, active, target="198.51.100.7")
    tick(settings)
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.DENIED and "198.51.100.7" in job.reason
    assert list(settings.job_spec_dir.iterdir()) == []


def test_failing_command_is_reported(active, settings, executor, run_db):
    job_id = submit(run_db, active, target="203.0.113.5", code="import sys; sys.exit(4)")
    job = drive(settings, executor, run_db, job_id, {JobStatus.FAILED})
    assert job.exit_code == 4 and job.reason == "exited 4"


def test_outside_window_defers_until_it_opens(client, eng, settings, run_db):
    today = datetime.now(UTC).isoweekday()
    other_day = today % 7 + 1
    window = {"timezone": "UTC", "days": [other_day], "start_time": "09:00", "end_time": "10:00"}
    activate(client, eng, "203.0.113.0/24", window=window)
    job_id = submit(run_db, eng, target="203.0.113.5")
    tick(settings)
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.DEFERRED
    assert job.defer_until is not None and job.defer_until.isoweekday() == other_day
    tick(settings)  # not due yet: untouched
    assert get_job(run_db, job_id).gated_at == job.gated_at


# --- approvals ------------------------------------------------------------------------------


def run_command_via_api(client, eng, *argv):
    resp = client.post(
        f"/engagements/{eng['id']}/jobs", json={"tool": "run_command", "params": {"argv": argv}}
    )
    assert resp.status_code == 202, resp.text
    return uuid.UUID(resp.json()["id"])


def pending_approval(client, eng):
    [a] = client.get(f"/engagements/{eng['id']}/approvals", params={"status": "pending"}).json()
    return a


def test_run_command_waits_for_approval_then_runs(client, active, settings, executor, run_db):
    job_id = run_command_via_api(client, active, PY, "-c", "print('approved run')")
    tick(settings)
    assert get_job(run_db, job_id).status is JobStatus.AWAITING_APPROVAL
    a = pending_approval(client, active)
    assert a["argv"][0] == PY and "arbitrary commands always need approval" in a["reasons"]

    resp = client.post(
        f"/engagements/{active['id']}/approvals/{a['id']}/approve", json={"note": "fine"}
    )
    assert resp.json()["status"] == "approved" and resp.json()["expires_at"]
    job = drive(settings, executor, run_db, job_id, {JobStatus.SUCCEEDED})
    assert job.reason == "exited 0"
    assert "job.dispatched" in [kind for kind, _ in job_events(run_db, job_id)]


def test_denied_approval_cancels_the_job(client, active, settings, run_db):
    job_id = run_command_via_api(client, active, PY, "-c", "print(1)")
    tick(settings)
    a = pending_approval(client, active)
    client.post(f"/engagements/{active['id']}/approvals/{a['id']}/deny", json={"note": "no"})
    tick(settings)
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.CANCELLED and "denied" in job.reason
    assert list(settings.job_spec_dir.iterdir()) == []


def test_expired_approval_is_asked_again(client, active, settings, run_db):
    job_id = run_command_via_api(client, active, PY, "-c", "print(1)")
    tick(settings)
    a = pending_approval(client, active)
    client.post(f"/engagements/{active['id']}/approvals/{a['id']}/approve", json={})
    later = datetime.now(UTC) + timedelta(hours=2)  # past the 1-hour TTL
    tick(settings, clock=lambda: later)
    assert get_job(run_db, job_id).status is JobStatus.AWAITING_APPROVAL
    assert [r.status for r in approvals(run_db, job_id)] == ["expired", "pending"]
    assert list(settings.job_spec_dir.iterdir()) == []


def test_new_reason_after_approval_needs_new_approval(client, active, settings, run_db):
    job_id = run_command_via_api(client, active, "curl", "https://www.example.com/")
    tick(settings)  # pins www.example.com to 203.0.113.10, asks for approval
    a = pending_approval(client, active)
    client.post(f"/engagements/{active['id']}/approvals/{a['id']}/approve", json={})

    moved = StaticResolver({"www.example.com": ["203.0.113.11"]})
    tick(settings, resolver=moved)
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.AWAITING_APPROVAL
    rows = approvals(run_db, job_id)
    assert [r.status for r in rows] == ["approved", "pending"]
    assert any("new address" in r for r in rows[-1].reasons)


# --- cancellation ---------------------------------------------------------------------------


def start_sleeper(settings, executor, run_db, eng, target="203.0.113.5"):
    job_id = submit(run_db, eng, target=target, code=SLEEP)
    return drive(settings, executor, run_db, job_id, {JobStatus.RUNNING}).id


def test_kill_switch_stops_a_running_job(client, active, settings, executor, run_db):
    job_id = start_sleeper(settings, executor, run_db, active)
    client.put(
        f"/engagements/{active['id']}/kill-switch", json={"engaged": True, "reason": "stop now"}
    )
    job = drive(settings, executor, run_db, job_id, {JobStatus.CANCELLED})
    assert job.cancel_requested_at is not None


def test_global_kill_switch_cancels_waiting_jobs(client, active, settings, run_db):
    job_id = run_command_via_api(client, active, PY, "-c", "print(1)")
    tick(settings)
    client.put("/kill-switch", json={"engaged": True, "reason": "incident"})
    tick(settings)
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.CANCELLED and job.reason == "kill switch engaged"
    assert [r.status for r in approvals(run_db, job_id)] == ["expired"]


def test_scope_removal_stops_a_job_that_is_now_out_of_scope(
    client, active, settings, executor, run_db
):
    job_id = start_sleeper(settings, executor, run_db, active)
    [entry] = [
        e
        for e in client.get(f"/engagements/{active['id']}/scope").json()
        if e["value"] == "203.0.113.0/24"
    ]
    client.request(
        "DELETE",
        f"/engagements/{active['id']}/scope/{entry['id']}",
        json={"reason": "client withdrew the range"},
    )
    drive(settings, executor, run_db, job_id, {JobStatus.CANCELLED})
    [reason] = [r for kind, r in job_events(run_db, job_id) if kind == "job.cancel_requested"]
    assert reason.startswith("scope changed:") and "203.0.113.5" in reason


def test_scope_change_that_still_allows_the_job_leaves_it_running(
    client, active, settings, executor, run_db
):
    job_id = start_sleeper(settings, executor, run_db, active)
    client.post(
        f"/engagements/{active['id']}/scope", json={"value": "198.51.100.0/24", "reason": "added"}
    )
    tick(settings)
    tick(settings)
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.RUNNING and job.cancel_requested_at is None


def test_operator_cancel_of_running_job(client, active, settings, executor, run_db):
    job_id = start_sleeper(settings, executor, run_db, active)
    resp = client.post(f"/engagements/{active['id']}/jobs/{job_id}/cancel")
    assert resp.json()["cancel_requested_at"]
    assert drive(settings, executor, run_db, job_id, {JobStatus.CANCELLED})


# --- limits and the watchdog ----------------------------------------------------------------


def test_concurrency_limit_defers_the_second_job(client, active, settings, executor, run_db):
    client.patch(f"/engagements/{active['id']}", json={"limits": {"max_concurrent_jobs": 1}})
    first = start_sleeper(settings, executor, run_db, active, target="203.0.113.5")
    second = submit(run_db, active, target="203.0.113.6")
    tick(settings)
    job = get_job(run_db, second)
    assert job.status is JobStatus.DEFERRED and "jobs already running" in job.reason
    assert get_job(run_db, first).status is JobStatus.RUNNING


def test_per_target_limit(active, settings, executor, run_db):
    start_sleeper(settings, executor, run_db, active, target="203.0.113.5")
    same = submit(run_db, active, target="203.0.113.5")
    other = submit(run_db, active, target="203.0.113.6")
    tick(settings)
    assert get_job(run_db, same).status is JobStatus.DEFERRED
    assert get_job(run_db, other).status is JobStatus.DISPATCHED


def test_watchdog_marks_jobs_the_executor_never_starts_lost(active, settings, run_db):
    job_id = submit(run_db, active, target="203.0.113.5")
    tick(settings)  # dispatched, but no executor is running
    later = datetime.now(UTC) + timedelta(seconds=30)
    tick(settings, clock=lambda: later)
    job = get_job(run_db, job_id)
    assert job.status is JobStatus.LOST and "never started" in job.reason
    assert p.cancel_path(settings.job_spec_dir, str(job_id)).exists()


def test_two_schedulers_never_claim_the_same_job(active, settings, run_db, migrated_db):
    for _ in range(3):
        submit(run_db, active, target="203.0.113.5")

    async def go():
        engine = make_engine(settings)
        sessions = make_sessionmaker(engine)
        try:
            async with sessions() as a, sessions() as b:
                now = datetime.now(UTC)
                first = await queue.claim_due(a, now)
                second = await queue.claim_due(b, now)  # a still holds its locks
                return len(first), len(second)
        finally:
            await engine.dispose()

    assert asyncio.run(go()) == (3, 0)


# --- API ------------------------------------------------------------------------------------


def test_submit_validates_params(client, active):
    resp = client.post(
        f"/engagements/{active['id']}/jobs", json={"tool": "run_command", "params": {"argv": "ls"}}
    )
    assert resp.status_code == 422


def test_unknown_tool_is_recorded_and_denied(client, active, settings, run_db):
    resp = client.post(f"/engagements/{active['id']}/jobs", json={"tool": "sqlmap"})
    assert resp.status_code == 202
    tick(settings)
    job = get_job(run_db, uuid.UUID(resp.json()["id"]))
    assert job.status is JobStatus.DENIED and "unknown tool" in job.reason


def test_list_get_and_cancel_waiting_job(client, active, run_db):
    job_id = run_command_via_api(client, active, "true")
    jobs = client.get(f"/engagements/{active['id']}/jobs").json()
    assert [j["id"] for j in jobs] == [str(job_id)]
    assert jobs[0]["requester"] == "operator:operator"
    assert client.get(f"/engagements/{active['id']}/jobs", params={"status": "denied"}).json() == []
    resp = client.post(f"/engagements/{active['id']}/jobs/{job_id}/cancel")
    assert resp.json()["status"] == "cancelled"
    assert client.post(f"/engagements/{active['id']}/jobs/{job_id}/cancel").status_code == 409


def test_archived_engagement_takes_no_jobs(client, active):
    client.patch(f"/engagements/{active['id']}", json={"status": "archived"})
    resp = client.post(
        f"/engagements/{active['id']}/jobs",
        json={"tool": "run_command", "params": {"argv": ["true"]}},
    )
    assert resp.status_code == 409


def test_limits_are_validated(client, active):
    e = f"/engagements/{active['id']}"
    assert client.patch(e, json={"limits": {"max_concurrent_jobs": 0}}).status_code == 422
    assert client.patch(e, json={"limits": {"bogus": 2}}).status_code == 422
    out = client.patch(e, json={"limits": {"max_jobs_per_minute": 5}}).json()
    assert out["limits"] == {
        "max_concurrent_jobs": 3,
        "max_concurrent_per_target": 1,
        "max_jobs_per_minute": 5,
    }
