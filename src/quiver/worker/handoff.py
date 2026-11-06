"""Worker side of the job file protocol (`quiver.executor.protocol`).

The worker writes a spec only after the gate allowed the job, and reads back what the executor
reports. Everything under the output directory is written in the container where tools run,
so it is untrusted: it is validated here and only ever updates the job's bookkeeping, never a
policy decision.
"""

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
) -> None:
    p.write_json_atomic(
        p.spec_path(spec_dir, job_id),
        {
            "job_id": job_id,
            "argv": argv,
            "timeouts": {"idle": idle_timeout, "hard": hard_timeout},
            "output_cap": output_cap,
        },
    )


def request_cancel(spec_dir: Path, job_id: str) -> None:
    path = p.cancel_path(spec_dir, job_id)
    if not path.exists():
        p.write_json_atomic(path, {"job_id": job_id})


def cleanup(spec_dir: Path, job_id: str) -> None:
    """Remove a finished job's spec and cancel files (its output stays)."""
    p.spec_path(spec_dir, job_id).unlink(missing_ok=True)
    p.cancel_path(spec_dir, job_id).unlink(missing_ok=True)


def read_state(output_dir: Path, job_id: str) -> ExecutorState:
    job_dir = p.job_output_dir(output_dir, job_id)
    started = _read(job_dir / p.STARTED)
    result = _read(job_dir / p.RESULT)
    started_at = _timestamp(started.get("started_at")) if isinstance(started, dict) else None
    if (job_dir / p.STARTED).exists() and started_at is None:
        started_at = _file_time(job_dir / p.STARTED)
    return ExecutorState(started_at, _valid_result(result, job_id))


def _read(path: Path):
    try:
        return p.read_json(path)
    except (OSError, ValueError):
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
        return datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError:
        return None
