"""Worker side of the job file protocol (`quiver.executor.protocol`).

The worker writes a spec only after the gate allowed the job, and reads back what the executor
reports. Everything under the output directory is written in the container where tools run,
so it is untrusted: it is read without following symlinks, validated here, and only ever
updates the job's bookkeeping or feeds a parser, never a policy decision.
"""

import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from quiver.executor import protocol as p


@dataclass(frozen=True)
class ExecutorState:
    started_at: datetime | None
    result: dict | None  # validated result.json, or None while the job is still running


def write_spec(
    spec_dir: Path,
    job_id: str,
    argv: list[str],
    *,
    idle_timeout: int,
    hard_timeout: int,
    output_cap: int,
    stdin: list[str] | None = None,
) -> None:
    spec = {
        "job_id": job_id,
        "argv": argv,
        "timeouts": {"idle": idle_timeout, "hard": hard_timeout},
        "output_cap": output_cap,
    }
    if stdin:
        spec["stdin"] = "".join(f"{line}\n" for line in stdin)
    p.write_json_atomic(p.spec_path(spec_dir, job_id), spec)


def request_cancel(spec_dir: Path, job_id: str) -> None:
    path = p.cancel_path(spec_dir, job_id)
    if not path.exists():
        p.write_json_atomic(path, {"job_id": job_id})


def cleanup(spec_dir: Path, job_id: str) -> None:
    """Remove a finished job's spec and cancel files (its output stays)."""
    p.spec_path(spec_dir, job_id).unlink(missing_ok=True)
    p.cancel_path(spec_dir, job_id).unlink(missing_ok=True)


# Status files are tiny; anything larger is not ours.
MAX_STATUS_FILE = 64 * 1024


def read_state(output_dir: Path, job_id: str) -> ExecutorState:
    started_raw = _read_bytes(output_dir, job_id, p.STARTED, MAX_STATUS_FILE)
    started = _json(started_raw)
    result = _json(_read_bytes(output_dir, job_id, p.RESULT, MAX_STATUS_FILE))
    started_at = _timestamp(started.get("started_at")) if isinstance(started, dict) else None
    if started_raw is not None and started_at is None:
        started_at = _file_time(p.job_output_dir(output_dir, job_id) / p.STARTED)
    return ExecutorState(started_at, _valid_result(result, job_id))


@dataclass(frozen=True)
class Output:
    data: bytes  # at most the cap; untrusted, target-controlled
    truncated: bool  # the file held more than the cap


def read_output(output_dir: Path, job_id: str, cap: int) -> Output | None:
    """A finished job's output, or None when there is no readable regular file."""
    data = _read_bytes(output_dir, job_id, p.OUTPUT, cap + 1)
    if data is None:
        return None
    return Output(data[:cap], len(data) > cap)


def _read_bytes(output_dir: Path, job_id: str, name: str, limit: int) -> bytes | None:
    """Read up to `limit` bytes of a file in a job's output directory, or None.

    Tools run as the same user on the volume these files live on, so any job could replace
    another job's directory or files with a symlink to something in *this* container (such
    as a secret). Neither the job directory nor the file may be a symlink, and the file must
    be a regular file (a FIFO would block)."""
    if not p.valid_job_id(job_id):
        return None
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        root = os.open(output_dir, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return None
    try:
        job_dir = os.open(job_id, flags | os.O_DIRECTORY, dir_fd=root)
    except OSError:
        return None
    finally:
        os.close(root)
    try:
        fd = os.open(name, flags | os.O_NONBLOCK, dir_fd=job_dir)
    except OSError:
        return None
    finally:
        os.close(job_dir)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, remaining = [], limit
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def _json(data: bytes | None):
    if data is None:
        return None
    try:
        return json.loads(data)
    except ValueError:
        return None


def _valid_result(result, job_id: str) -> dict | None:
    if not isinstance(result, dict) or result.get("job_id") != job_id:
        return None
    if result.get("status") not in p.RESULT_STATUSES:
        return None
    exit_code = result.get("exit_code")
    size = result.get("output_bytes")
    return {
        "status": result["status"],
        "reason": str(result.get("reason", ""))[:1000],
        "exit_code": exit_code
        if isinstance(exit_code, int) and not isinstance(exit_code, bool)
        else None,
        "output_bytes": size if isinstance(size, int) and size >= 0 else 0,
        "truncated": result.get("truncated") is True,
        "started_at": _timestamp(result.get("started_at")),
        "finished_at": _timestamp(result.get("finished_at")),
    }


def _timestamp(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _file_time(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.lstat().st_mtime, UTC)
    except OSError:
        return None
