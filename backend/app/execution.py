import logging
import time as _time
import asyncio
import os
import signal
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Shared state — runs.py (WebSocket) and agent/engine.py both reference these dicts.
# Since Python modules are singletons, both modules see the same objects.
_running_processes: dict = {}
_run_buffers: dict[str, list[str]] = {}
_run_done_events: dict[str, asyncio.Event] = {}


def build_command(tool, param_values: dict, extra_flags: str = "") -> str:
    parts = [tool.binary]
    if tool.default_flags:
        parts.append(tool.default_flags)
    for param in tool.parameters:
        name = param.get("name")
        flag = param.get("flag", "")
        value = param_values.get(name, "")
        if value:
            if flag:
                parts.append(f"{flag} {value}")
            else:
                parts.append(value)
    if extra_flags:
        parts.append(extra_flags)
    return " ".join(parts)


def kill_process(run_id: str) -> None:
    process = _running_processes.get(run_id)
    if process is not None:
        logger.info("RUN KILL  | run_id=%s", run_id)
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                process.terminate()
            except Exception:
                pass


async def execute_run_background(
    run_id: str,
    command: str,
    session_id: str = "",
    tool_name: str = "",
) -> None:
    """Run a shell command as a subprocess, stream output into the shared buffer,
    and persist the final result to the Run DB record.

    Survives WebSocket disconnects — the WebSocket handler just stops reading from
    the buffer, but this task keeps the process alive and writing.
    """
    from app.db.database import AsyncSessionLocal
    from app.models.run import Run
    from sqlalchemy import select

    _run_buffers.setdefault(run_id, [])
    _run_done_events.setdefault(run_id, asyncio.Event())
    buf = _run_buffers[run_id]

    exit_code = -1
    run_status = "error"
    t_start = _time.monotonic()

    logger.info(
        "RUN START | run_id=%s session_id=%s tool=%s | %s",
        run_id, session_id, tool_name, command[:300],
    )

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            limit=1024 * 1024,
            start_new_session=True,
        )
        _running_processes[run_id] = process

        async for line_bytes in process.stdout:
            line = line_bytes.decode("utf-8", errors="replace")
            buf.append(line)

        await process.wait()
        exit_code = process.returncode
        run_status = "complete" if exit_code == 0 else "error"

    except Exception as e:
        buf.append(f"\n[ERROR] {str(e)}\n")
        logger.error("RUN ERROR | run_id=%s | %s", run_id, str(e))
    finally:
        _running_processes.pop(run_id, None)

    duration = _time.monotonic() - t_start
    logger.info(
        "RUN END   | run_id=%s session_id=%s tool=%s | status=%s exit_code=%s duration=%.1fs",
        run_id, session_id, tool_name, run_status, exit_code, duration,
    )

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Run).where(Run.id == run_id))
        run = result.scalar_one_or_none()
        if run:
            run.output = "".join(buf)
            run.status = run_status
            run.exit_code = exit_code
            run.finished_at = datetime.now(timezone.utc)
            await db.commit()

    _run_done_events[run_id].set()

    # Keep buffer alive briefly so a reconnect just after completion can replay
    await asyncio.sleep(60)
    _run_buffers.pop(run_id, None)
    _run_done_events.pop(run_id, None)
