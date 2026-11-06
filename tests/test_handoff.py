"""Worker side of the job file protocol. Files from the executor are written where tools run,
so they are untrusted: anything malformed or mismatched is ignored."""

import json
import uuid

import pytest

from quiver.executor import protocol as p
from quiver.worker import handoff


@pytest.fixture
def job(tmp_path):
    job_id = str(uuid.uuid4())
    (tmp_path / job_id).mkdir()
    return tmp_path, job_id


def write(path, data):
    path.write_text(data if isinstance(data, str) else json.dumps(data))


def good_result(job_id, **extra):
    return {
        "job_id": job_id,
        "status": "succeeded",
        "reason": "exited 0",
        "exit_code": 0,
        "output_bytes": 12,
        "truncated": False,
        "started_at": "2026-11-06T10:00:00+00:00",
        "finished_at": "2026-11-06T10:00:01+00:00",
    } | extra


def test_running_then_finished(job):
    out, job_id = job
    assert handoff.read_state(out, job_id) == handoff.ExecutorState(None, None)
    write(out / job_id / p.STARTED, {"started_at": "2026-11-06T10:00:00+00:00"})
    state = handoff.read_state(out, job_id)
    assert state.started_at.isoformat() == "2026-11-06T10:00:00+00:00" and state.result is None
    write(out / job_id / p.RESULT, good_result(job_id))
    assert handoff.read_state(out, job_id).result["status"] == "succeeded"


@pytest.mark.parametrize(
    "case", ["not json", "a list", "no job id", "another job's result", "unknown status"]
)
def test_malformed_or_foreign_results_are_ignored(job, case):
    out, job_id = job
    bad = {
        "not json": "not json",
        "a list": [],
        "no job id": {"status": "succeeded"},
        "another job's result": good_result(str(uuid.uuid4())),
        "unknown status": good_result(job_id, status="pwned"),
    }[case]
    write(out / job_id / p.RESULT, bad)
    assert handoff.read_state(out, job_id).result is None


def test_result_fields_are_sanitized(job):
    out, job_id = job
    write(
        out / job_id / p.RESULT,
        good_result(
            job_id,
            exit_code=True,
            output_bytes=-5,
            truncated="yes",
            reason="x" * 5000,
            started_at="yesterday",
            finished_at="2026-11-06T10:00:01",  # no time zone
        ),
    )
    r = handoff.read_state(out, job_id).result
    assert r["exit_code"] is None and r["output_bytes"] == 0 and r["truncated"] is False
    assert len(r["reason"]) == 1000
    assert r["started_at"] is None and r["finished_at"] is None


def test_unparseable_started_file_falls_back_to_its_mtime(job):
    out, job_id = job
    write(out / job_id / p.STARTED, "garbage")
    assert handoff.read_state(out, job_id).started_at is not None


def test_spec_cancel_and_cleanup(tmp_path):
    job_id = str(uuid.uuid4())
    handoff.write_spec(
        tmp_path, job_id, ["echo", "hi"], idle_timeout=5, hard_timeout=10, output_cap=1000
    )
    spec = json.loads(p.spec_path(tmp_path, job_id).read_text())
    assert spec == {
        "job_id": job_id,
        "argv": ["echo", "hi"],
        "timeouts": {"idle": 5, "hard": 10},
        "output_cap": 1000,
    }
    handoff.request_cancel(tmp_path, job_id)
    handoff.request_cancel(tmp_path, job_id)  # idempotent
    assert p.cancel_path(tmp_path, job_id).exists()
    handoff.cleanup(tmp_path, job_id)
    assert list(tmp_path.iterdir()) == []
