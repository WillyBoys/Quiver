"""Executor: real processes, no shell, limits, cancellation, process-group cleanup, and the
file protocol. Commands are the test interpreter itself, so these run on any OS CI uses."""

import json
import os
import sys
import time
import uuid
from pathlib import Path

import pytest

from quiver.executor import protocol as p
from quiver.executor.runner import Executor, Spec, SpecError, load_spec, run_job

PY = sys.executable
PATH_ENV = f"{Path(PY).parent}:/usr/bin:/bin"


def spec(*argv, idle=30, hard=30, cap=p.DEFAULT_OUTPUT_CAP):
    return Spec(str(uuid.uuid4()), tuple(argv), float(idle), float(hard), cap)


def run(tmp_path, s, cancelled=lambda: False):
    out = tmp_path / s.job_id
    out.mkdir()
    return run_job(s, out, cancelled, path_env=PATH_ENV), out


def py(code):
    return (PY, "-c", code)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers kill(0); treat it as dead.
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split()[2] != "Z"
    except OSError:
        return True


# --- run_job --------------------------------------------------------------------------------


def test_success_writes_output_and_result(tmp_path):
    result, out = run(tmp_path, spec(*py("print('hello')")))
    assert result["status"] == p.SUCCEEDED and result["exit_code"] == 0
    assert (out / p.OUTPUT).read_text() == "hello\n"
    assert json.loads((out / p.RESULT).read_text()) == result
    assert result["started_at"] <= result["finished_at"]


def test_nonzero_exit_fails(tmp_path):
    result, _ = run(tmp_path, spec(*py("import sys; sys.exit(3)")))
    assert (result["status"], result["exit_code"], result["reason"]) == (p.FAILED, 3, "exited 3")


def test_stderr_is_captured(tmp_path):
    _, out = run(tmp_path, spec(*py("import sys; sys.stderr.write('oops\\n')")))
    assert (out / p.OUTPUT).read_text() == "oops\n"


def test_no_shell_metacharacters_are_literal(tmp_path):
    marker = tmp_path / "pwned"
    argv = (*py("import sys; print(sys.argv[1:])"), f"; touch {marker}", "$(id)", "`id`", "|x")
    _, out = run(tmp_path, spec(*argv))
    assert (out / p.OUTPUT).read_text().strip() == repr(
        [f"; touch {marker}", "$(id)", "`id`", "|x"]
    )
    assert not marker.exists()


def test_environment_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("QUIVER_DB_PASSWORD", "hunter2-do-not-leak")
    _, out = run(tmp_path, spec(*py("import os, json; print(json.dumps(dict(os.environ)))")))
    env = json.loads((out / p.OUTPUT).read_text())
    assert "hunter2-do-not-leak" not in json.dumps(env)
    assert set(env) <= {"PATH", "LANG", "LC_ALL", "HOME", "PWD", "__CF_USER_TEXT_ENCODING"}
    assert env["HOME"] == str(out)


def test_working_directory_is_the_job_directory(tmp_path):
    _, out = run(tmp_path, spec(*py("import os; print(os.getcwd())")))
    assert Path((out / p.OUTPUT).read_text().strip()).resolve() == out.resolve()


def test_output_cap_truncates_and_kills(tmp_path):
    result, out = run(
        tmp_path,
        spec(*py("import sys, time\nwhile True: sys.stdout.write('x' * 4096)"), cap=10_000),
    )
    assert result["status"] == p.FAILED and result["truncated"] is True
    assert "output cap" in result["reason"]
    assert (out / p.OUTPUT).stat().st_size == result["output_bytes"] == 10_000


def test_one_huge_line_is_fine(tmp_path):
    """v1 read by line with a 1 MB limit, so one long line without a newline broke it."""
    result, out = run(tmp_path, spec(*py("import sys; sys.stdout.write('y' * 3_000_000)")))
    assert result["status"] == p.SUCCEEDED
    assert (out / p.OUTPUT).stat().st_size == 3_000_000


def test_idle_timeout(tmp_path):
    t = time.monotonic()
    result, _ = run(tmp_path, spec(*py("import time; time.sleep(30)"), idle=1))
    assert result["status"] == p.TIMED_OUT and "no output" in result["reason"]
    assert time.monotonic() - t < 5


def test_hard_timeout_despite_steady_output(tmp_path):
    code = "import time\nwhile True:\n    print('tick', flush=True)\n    time.sleep(0.1)"
    t = time.monotonic()
    result, _ = run(tmp_path, spec(*py(code), idle=30, hard=1))
    assert result["status"] == p.TIMED_OUT and "hard timeout" in result["reason"]
    assert time.monotonic() - t < 5


def test_cancel_stops_the_job(tmp_path):
    t0 = time.monotonic()
    result, _ = run(
        tmp_path, spec(*py("import time; time.sleep(30)")), lambda: time.monotonic() - t0 > 0.5
    )
    assert result["status"] == p.CANCELLED
    assert time.monotonic() - t0 < 5


@pytest.mark.parametrize("stop", ["exits", "timeout"])
def test_whole_process_group_is_killed(tmp_path, stop):
    """A child left behind (backgrounded, still holding the pipe) never outlives its job."""
    pidfile = tmp_path / "child.pid"
    code = (
        "import subprocess, sys, time\n"
        f"c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(c.pid))\n"
        + ("" if stop == "exits" else "time.sleep(60)\n")
    )
    result, _ = run(tmp_path, spec(*py(code), idle=1, hard=30))
    child = int(pidfile.read_text())
    deadline = time.monotonic() + 3
    while alive(child) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not alive(child), f"child {child} survived ({result['status']})"


def test_missing_executable_fails_without_crashing(tmp_path):
    result, _ = run(tmp_path, spec("definitely-not-a-real-tool-xyz"))
    assert result["status"] == p.FAILED and "could not start" in result["reason"]


# --- specs ----------------------------------------------------------------------------------


def write_spec(spec_dir: Path, job_id=None, **data):
    job_id = job_id or str(uuid.uuid4())
    body = {"job_id": job_id, "argv": list(py("print('ok')"))} | data
    p.write_json_atomic(p.spec_path(spec_dir, job_id), body)
    return job_id


def test_load_spec_clamps_limits(tmp_path):
    job = write_spec(tmp_path, timeouts={"idle": 10**9, "hard": 0}, output_cap=10**12)
    s = load_spec(p.spec_path(tmp_path, job))
    assert s.idle_timeout == p.MAX_IDLE_TIMEOUT
    assert s.hard_timeout == 1
    assert s.output_cap == p.MAX_OUTPUT_CAP


@pytest.mark.parametrize(
    "data",
    [
        {"argv": "echo hi"},  # a string is not an argv list
        {"argv": []},
        {"argv": ["echo", 3]},
        {"argv": [""]},
        {"argv": ["echo", "a\0b"]},
        {"timeouts": {"idle": True}},
        {"timeouts": "fast"},
    ],
)
def test_invalid_specs_are_rejected(tmp_path, data):
    job = write_spec(tmp_path, **data)
    with pytest.raises(SpecError):
        load_spec(p.spec_path(tmp_path, job))


def test_spec_for_another_job_is_rejected(tmp_path):
    job = str(uuid.uuid4())
    p.write_json_atomic(p.spec_path(tmp_path, job), {"job_id": str(uuid.uuid4()), "argv": ["true"]})
    with pytest.raises(SpecError, match="does not belong"):
        load_spec(p.spec_path(tmp_path, job))


def test_spec_must_be_named_after_a_job_id(tmp_path):
    path = tmp_path / "../../etc.json"
    with pytest.raises(SpecError):
        load_spec(path)


# --- Executor -------------------------------------------------------------------------------


@pytest.fixture
def dirs(tmp_path):
    specs, output = tmp_path / "specs", tmp_path / "output"
    specs.mkdir()
    output.mkdir()
    return specs, output


def executor(dirs, **kwargs):
    return Executor(*dirs, path_env=PATH_ENV, **kwargs)


def result_of(output: Path, job_id: str) -> dict:
    return json.loads((output / job_id / p.RESULT).read_text())


def test_executor_runs_a_spec_without_touching_the_spec_dir(dirs):
    specs, output = dirs
    job = write_spec(specs)
    before = sorted(x.name for x in specs.iterdir())
    ex = executor(dirs)
    assert ex.poll_once() == [job]
    ex.wait(10)
    assert result_of(output, job)["status"] == p.SUCCEEDED
    assert (output / job / p.OUTPUT).read_text() == "ok\n"
    assert sorted(x.name for x in specs.iterdir()) == before
    assert ex.poll_once() == []  # never run twice


def test_invalid_spec_fails_without_a_process(dirs):
    specs, output = dirs
    job = write_spec(specs, argv="rm -rf /")
    ex = executor(dirs)
    ex.poll_once()
    ex.wait(10)
    r = result_of(output, job)
    assert r["status"] == p.FAILED and "invalid spec" in r["reason"]
    assert not (output / job / p.OUTPUT).exists()


def test_files_not_named_after_jobs_are_ignored(dirs):
    specs, output = dirs
    (specs / "evil.json").write_text(json.dumps({"job_id": "evil", "argv": ["true"]}))
    assert executor(dirs).poll_once() == []
    assert list(output.iterdir()) == []


def test_only_one_executor_claims_a_job(dirs):
    specs, _ = dirs
    write_spec(specs)
    a, b = executor(dirs), executor(dirs)
    started = a.poll_once() + b.poll_once()
    a.wait(10)
    b.wait(10)
    assert len(started) == 1


def test_cancel_file_cancels_a_running_job(dirs):
    specs, output = dirs
    job = write_spec(specs, argv=list(py("import time; time.sleep(30)")))
    ex = executor(dirs)
    ex.poll_once()
    time.sleep(0.3)
    p.cancel_path(specs, job).write_text("")
    ex.wait(10)
    assert result_of(output, job)["status"] == p.CANCELLED


def test_parallel_limit(dirs):
    specs, output = dirs
    jobs = [write_spec(specs, argv=list(py("import time; time.sleep(0.5)"))) for _ in range(3)]
    ex = executor(dirs, max_parallel=2)
    assert len(ex.poll_once()) == 2
    ex.wait(10)
    assert len(ex.poll_once()) == 1
    ex.wait(10)
    assert all(result_of(output, j)["status"] == p.SUCCEEDED for j in jobs)


def test_recover_marks_interrupted_jobs_lost(dirs):
    _, output = dirs
    job = str(uuid.uuid4())
    (output / job).mkdir()
    (output / job / p.STARTED).write_text('{"started_at": "2026-11-06T10:00:00+00:00"}')
    (output / job / p.OUTPUT).write_text("partial")
    done = str(uuid.uuid4())
    (output / done).mkdir()
    (output / done / p.STARTED).write_text("{}")
    p.write_json_atomic(output / done / p.RESULT, {"status": p.SUCCEEDED})

    assert executor(dirs).recover() == [job]
    r = result_of(output, job)
    assert r["status"] == p.LOST and r["output_bytes"] == 7
    assert result_of(output, done)["status"] == p.SUCCEEDED


def test_shutdown_cancels_running_jobs(dirs):
    specs, output = dirs
    job = write_spec(specs, argv=list(py("import time; time.sleep(30)")))
    ex = executor(dirs)
    ex.poll_once()
    time.sleep(0.3)
    t = time.monotonic()
    ex.shutdown()
    assert time.monotonic() - t < 5
    assert result_of(output, job)["status"] == p.CANCELLED
    late = write_spec(specs)
    assert ex.poll_once() == []  # no new work once stopping
    assert not (output / late).exists()
