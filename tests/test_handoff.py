"""Worker side of the job file protocol. Files from the executor are written where tools run,
so they are untrusted: anything malformed or mismatched is ignored."""

import json
import os
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


def test_spec_stdin_is_joined_lines(tmp_path):
    job_id = str(uuid.uuid4())
    handoff.write_spec(
        tmp_path, job_id, ["dnsx"], idle_timeout=1, hard_timeout=2, output_cap=3, stdin=["a", "b"]
    )
    assert json.loads(p.spec_path(tmp_path, job_id).read_text())["stdin"] == "a\nb\n"
    handoff.write_spec(tmp_path, job_id, ["x"], idle_timeout=1, hard_timeout=2, output_cap=3)
    assert "stdin" not in json.loads(p.spec_path(tmp_path, job_id).read_text())


# --- reading output: never follow what a tool could have planted --------------------------------


def test_read_output_with_cap(job):
    out, job_id = job
    (out / job_id / p.OUTPUT).write_bytes(b"0123456789")
    assert handoff.read_output(out, job_id, 100) == handoff.Output(b"0123456789", False)
    assert handoff.read_output(out, job_id, 4) == handoff.Output(b"0123", True)
    assert handoff.read_output(out, job_id, 10) == handoff.Output(b"0123456789", False)


def test_read_output_missing(job):
    out, job_id = job
    assert handoff.read_output(out, job_id, 100) is None
    assert handoff.read_output(out, str(uuid.uuid4()), 100) is None
    assert handoff.read_output(out, "../etc", 100) is None


def test_symlinked_output_file_is_not_followed(job, tmp_path_factory):
    out, job_id = job
    secret = tmp_path_factory.mktemp("secrets") / "postgres_password"
    secret.write_text("hunter2")
    (out / job_id / p.OUTPUT).symlink_to(secret)
    assert handoff.read_output(out, job_id, 100) is None
    # The status files get the same treatment.
    write(secret, good_result(job_id))
    (out / job_id / p.RESULT).symlink_to(secret)
    (out / job_id / p.STARTED).symlink_to(secret)
    assert handoff.read_state(out, job_id) == handoff.ExecutorState(None, None)


def test_symlinked_job_directory_is_not_followed(tmp_path, tmp_path_factory):
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    (elsewhere / p.OUTPUT).write_text("not yours")
    job_id = str(uuid.uuid4())
    (tmp_path / job_id).symlink_to(elsewhere, target_is_directory=True)
    assert handoff.read_output(tmp_path, job_id, 100) is None


def test_fifo_output_does_not_block(job):
    out, job_id = job
    os.mkfifo(out / job_id / p.OUTPUT)
    assert handoff.read_output(out, job_id, 100) is None


def test_directory_in_place_of_output_is_ignored(job):
    out, job_id = job
    (out / job_id / p.OUTPUT).mkdir()
    assert handoff.read_output(out, job_id, 100) is None
