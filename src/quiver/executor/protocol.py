"""The file protocol between the worker and the executor (Blueprint §6). Stdlib only.

Two directories, each writable by one side only:

    <spec_dir>/<job_id>.json      worker writes (after the gate allowed the job)
    <spec_dir>/<job_id>.cancel    worker writes to cancel a job
    <output_dir>/<job_id>/started     executor creates (O_EXCL) when it claims the job
    <output_dir>/<job_id>/output.log  stdout and stderr, merged, up to the output cap
    <output_dir>/<job_id>/result.json executor writes when the process is gone

The executor mounts the spec directory read-only, so neither it nor the tools it runs can
create jobs. Every JSON file is written to a temporary name and renamed into place.
"""

import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

SPEC_SUFFIX = ".json"
CANCEL_SUFFIX = ".cancel"
STARTED = "started"
OUTPUT = "output.log"
RESULT = "result.json"

DEFAULT_IDLE_TIMEOUT = 600  # seconds without output (v1: 10 minutes)
DEFAULT_HARD_TIMEOUT = 2700  # seconds in total (v1: 45 minutes)
MAX_IDLE_TIMEOUT = 3600
MAX_HARD_TIMEOUT = 4 * 3600
DEFAULT_OUTPUT_CAP = 10 * 1024 * 1024  # bytes (v1: 10 MB)
MAX_OUTPUT_CAP = 50 * 1024 * 1024

# Final statuses reported in result.json.
SUCCEEDED = "succeeded"
FAILED = "failed"
TIMED_OUT = "timed_out"
CANCELLED = "cancelled"
LOST = "lost"
RESULT_STATUSES = frozenset({SUCCEEDED, FAILED, TIMED_OUT, CANCELLED, LOST})


def valid_job_id(name: str) -> bool:
    """Job IDs are canonical UUIDs, so a file name can never point outside its directory."""
    try:
        return str(uuid.UUID(name)) == name
    except ValueError:
        return False


def spec_path(spec_dir: Path, job_id: str) -> Path:
    return spec_dir / f"{job_id}{SPEC_SUFFIX}"


def cancel_path(spec_dir: Path, job_id: str) -> Path:
    return spec_dir / f"{job_id}{CANCEL_SUFFIX}"


def job_output_dir(output_dir: Path, job_id: str) -> Path:
    return output_dir / job_id


def write_json_atomic(path: Path, data: Any) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())
