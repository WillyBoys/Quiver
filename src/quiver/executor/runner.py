"""The executor: the only place Quiver starts processes (Blueprint §6). Stdlib only.

It runs in its own container with no secrets and no database access. It runs exactly what a
job spec says, as an argv list and never through a shell, and it cannot create specs: only the
worker can, after the policy gate allowed the job.

Each process gets a fresh session (so the whole process group can be killed), stdin from
/dev/null (or the spec's input lines, for tools that read a target list), its job's output
directory as working directory and HOME, and an environment that inherits nothing. Output is
read in chunks (not lines, so one huge line cannot stall or break the reader) and capped. Idle
timeout, hard timeout, the output cap, and cancellation all kill the whole process group, and
so does the parent exiting, so no child outlives its job.
"""

import contextlib
import logging
import os
import selectors
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from quiver.executor import protocol as p

log = logging.getLogger("quiver.executor")

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
CHUNK = 64 * 1024
TICK = 0.2  # seconds between timeout and cancel checks
EXIT_GRACE = 1.0  # after the main process exits, how long to drain output from its children


class SpecError(ValueError):
    pass


@dataclass(frozen=True)
class Spec:
    job_id: str
    argv: tuple[str, ...]
    idle_timeout: float
    hard_timeout: float
    output_cap: int
    stdin: bytes | None = None  # fed to the process, then closed; None: /dev/null


def _bounded(value, default: float, maximum: float) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise SpecError(f"limit {value!r} is not a number")
    return float(min(max(value, 1), maximum))


def load_spec(path: Path) -> Spec:
    job_id = path.name.removesuffix(p.SPEC_SUFFIX)
    if not p.valid_job_id(job_id):
        raise SpecError(f"{path.name} is not named after a job ID")
    try:
        data = p.read_json(path)
    except (OSError, ValueError) as exc:
        raise SpecError(f"unreadable spec: {exc}") from exc
    if not isinstance(data, dict) or data.get("job_id") != job_id:
        raise SpecError("spec does not belong to this job")
    argv = data.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(a, str) and "\0" not in a for a in argv)
        or not argv[0]
    ):
        raise SpecError("argv must be a non-empty list of strings")
    timeouts = data.get("timeouts") or {}
    if not isinstance(timeouts, dict):
        raise SpecError("timeouts must be an object")
    stdin = data.get("stdin")
    if stdin is not None:
        if not isinstance(stdin, str) or "\0" in stdin:
            raise SpecError("stdin must be text")
        stdin = stdin.encode()
        if len(stdin) > p.MAX_STDIN:
            raise SpecError(f"stdin exceeds {p.MAX_STDIN} bytes")
    return Spec(
        job_id=job_id,
        argv=tuple(argv),
        idle_timeout=_bounded(timeouts.get("idle"), p.DEFAULT_IDLE_TIMEOUT, p.MAX_IDLE_TIMEOUT),
        hard_timeout=_bounded(timeouts.get("hard"), p.DEFAULT_HARD_TIMEOUT, p.MAX_HARD_TIMEOUT),
        output_cap=int(_bounded(data.get("output_cap"), p.DEFAULT_OUTPUT_CAP, p.MAX_OUTPUT_CAP)),
        stdin=stdin,
    )


def _now() -> str:
    return datetime.now(UTC).isoformat()


KILL_WAIT = 5.0  # seconds to wait for the main process after a kill


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the job's whole process group and reap the main process. Never blocks for long:
    if the group kill somehow failed, the main process is killed directly."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)  # the session leader's pid is the group id
    try:
        proc.wait(timeout=KILL_WAIT)
    except subprocess.TimeoutExpired:
        log.error("job process %s survived its group kill; killing it directly", proc.pid)
        with contextlib.suppress(OSError):
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=KILL_WAIT)


def run_job(
    spec: Spec,
    out_dir: Path,
    cancelled: Callable[[], bool],
    *,
    path_env: str = DEFAULT_PATH,
    started_at: str | None = None,
) -> dict:
    """Run one job to completion and return its result (also written to result.json)."""
    started_at = started_at or _now()
    result = {
        "job_id": spec.job_id,
        "started_at": started_at,
        "exit_code": None,
        "output_bytes": 0,
        "truncated": False,
    }
    env = {"PATH": path_env, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": str(out_dir)}

    with open(out_dir / p.OUTPUT, "wb") as out:
        try:
            proc = subprocess.Popen(  # noqa: S603 (argv list from a gate-allowed spec; no shell)
                list(spec.argv),
                stdin=subprocess.DEVNULL if spec.stdin is None else subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=out_dir,
                env=env,
                start_new_session=True,
                close_fds=True,
                shell=False,
            )
        except (OSError, ValueError) as exc:
            result.update(status=p.FAILED, reason=f"could not start {spec.argv[0]!r}: {exc}")
            return _finish(out_dir, result)

        if spec.stdin is not None:
            # A thread, so a tool that never reads its input cannot block supervision.
            threading.Thread(target=_feed, args=(proc.stdin, spec.stdin), daemon=True).start()
        status, reason = _supervise(proc, spec, out, cancelled, result)
        _kill_group(proc)  # whatever is left of the group goes with the job
        if proc.stdout:
            proc.stdout.close()

    code = proc.returncode
    result["exit_code"] = code
    if status is None:
        if code == 0:
            status, reason = p.SUCCEEDED, "exited 0"
        elif code < 0:
            status, reason = p.FAILED, f"killed by signal {-code}"
        else:
            status, reason = p.FAILED, f"exited {code}"
    result.update(status=status, reason=reason)
    return _finish(out_dir, result)


def _feed(pipe, data: bytes) -> None:
    try:
        pipe.write(data)
    except OSError:  # includes BrokenPipeError: the tool exited or closed its input
        pass
    finally:
        with contextlib.suppress(OSError):
            pipe.close()


def _supervise(proc, spec: Spec, out, cancelled, result) -> tuple[str | None, str]:
    """Copy output until the process group is done or a limit is hit. Returns (status,
    reason) when the job was stopped, (None, "") when it ended on its own."""
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    sel = selectors.DefaultSelector()
    sel.register(fd, selectors.EVENT_READ)
    start = last_output = time.monotonic()
    exited_at = None
    try:
        while True:
            now = time.monotonic()
            if cancelled():
                return p.CANCELLED, "cancelled"
            if now - start >= spec.hard_timeout:
                return p.TIMED_OUT, f"hard timeout ({spec.hard_timeout:g} s)"
            if now - last_output >= spec.idle_timeout:
                return p.TIMED_OUT, f"no output for {spec.idle_timeout:g} s"
            if exited_at is None and proc.poll() is not None:
                exited_at = now
            if exited_at is not None and now - exited_at >= EXIT_GRACE:
                return None, ""  # children still holding the pipe are killed by the caller

            if not sel.select(TICK):
                continue
            try:
                chunk = os.read(fd, CHUNK)
            except BlockingIOError:
                continue
            if not chunk:
                proc.wait()
                return None, ""
            last_output = time.monotonic()
            room = spec.output_cap - result["output_bytes"]
            out.write(chunk[:room])
            result["output_bytes"] += min(len(chunk), room)
            if len(chunk) > room:
                result["truncated"] = True
                return p.FAILED, f"output cap reached ({spec.output_cap} bytes)"
    finally:
        sel.close()
        out.flush()


def _finish(out_dir: Path, result: dict) -> dict:
    result["finished_at"] = _now()
    p.write_json_atomic(out_dir / p.RESULT, result)
    return result


class Executor:
    """Polls the spec directory and runs each new job in its own thread."""

    def __init__(
        self,
        spec_dir: Path,
        output_dir: Path,
        *,
        poll_interval: float = 0.5,
        max_parallel: int = 16,
        path_env: str = DEFAULT_PATH,
    ):
        self.spec_dir = spec_dir
        self.output_dir = output_dir
        self.poll_interval = poll_interval
        self.path_env = path_env
        self._slots = threading.BoundedSemaphore(max_parallel)
        self._threads: dict[str, threading.Thread] = {}
        self._stopping = threading.Event()  # set by shutdown(): every running job is cancelled

    def recover(self) -> list[str]:
        """Jobs that were running when the executor stopped can't be resumed: mark them lost."""
        lost = []
        for job_dir in sorted(self.output_dir.iterdir()) if self.output_dir.exists() else []:
            if (
                p.valid_job_id(job_dir.name)
                and (job_dir / p.STARTED).exists()
                and not (job_dir / p.RESULT).exists()
            ):
                started = p.read_json(job_dir / p.STARTED).get("started_at")
                _finish(
                    job_dir,
                    {
                        "job_id": job_dir.name,
                        "status": p.LOST,
                        "reason": "the executor stopped while the job was running",
                        "started_at": started,
                        "exit_code": None,
                        "output_bytes": _size(job_dir / p.OUTPUT),
                        "truncated": False,
                    },
                )
                lost.append(job_dir.name)
        return lost

    def poll_once(self) -> list[str]:
        """Claim and start every new job whose spec is present. Returns the started IDs."""
        if self._stopping.is_set():
            return []
        started = []
        specs = sorted(self.spec_dir.glob(f"*{p.SPEC_SUFFIX}"), key=_mtime)
        for path in specs:
            job_id = path.name.removesuffix(p.SPEC_SUFFIX)
            if not p.valid_job_id(job_id) or job_id in self._threads:
                continue
            job_dir = p.job_output_dir(self.output_dir, job_id)
            if (job_dir / p.STARTED).exists():
                continue
            if not self._slots.acquire(blocking=False):
                break  # at capacity; the rest wait for the next poll
            claimed_at = self._claim(job_dir)
            if claimed_at is None:
                self._slots.release()
                continue
            thread = threading.Thread(
                target=self._run, args=(path, job_dir, claimed_at), name=f"job-{job_id}"
            )
            self._threads[job_id] = thread
            thread.start()
            started.append(job_id)
        self._threads = {k: t for k, t in self._threads.items() if t.is_alive()}
        return started

    def _claim(self, job_dir: Path) -> str | None:
        job_dir.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(job_dir / p.STARTED, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            return None
        started_at = _now()
        with os.fdopen(fd, "w") as f:
            f.write(f'{{"started_at": "{started_at}"}}')
        return started_at

    def _run(self, path: Path, job_dir: Path, started_at: str) -> None:
        job_id = job_dir.name
        try:
            try:
                spec = load_spec(path)
            except SpecError as exc:
                log.warning("job %s: invalid spec: %s", job_id, exc)
                _finish(
                    job_dir,
                    {
                        "job_id": job_id,
                        "status": p.FAILED,
                        "reason": f"invalid spec: {exc}",
                        "started_at": started_at,
                        "exit_code": None,
                        "output_bytes": 0,
                        "truncated": False,
                    },
                )
                return
            cancel = p.cancel_path(self.spec_dir, job_id)
            log.info("job %s: starting %s", job_id, spec.argv[0])
            result = run_job(
                spec,
                job_dir,
                lambda: self._stopping.is_set() or cancel.exists(),
                path_env=self.path_env,
                started_at=started_at,
            )
            log.info("job %s: %s (%s)", job_id, result["status"], result["reason"])
        finally:
            self._slots.release()

    def wait(self, timeout: float | None = None) -> None:
        """Wait for running jobs (tests and shutdown)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        for thread in list(self._threads.values()):
            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            thread.join(remaining)

    def shutdown(self, timeout: float = 10) -> None:
        """Stop taking jobs and cancel every running one (whole process groups are killed)."""
        self._stopping.set()
        self.wait(timeout)

    def serve(self, stop: threading.Event) -> None:
        self.recover()
        while not stop.is_set() and not self._stopping.is_set():
            try:
                self.poll_once()
            except OSError as exc:  # e.g. a volume briefly unavailable
                log.error("poll failed: %s", exc)
            stop.wait(self.poll_interval)


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0
