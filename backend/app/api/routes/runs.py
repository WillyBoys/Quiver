from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db, AsyncSessionLocal
from app.models.run import Run
from app.models.tool import Tool
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import asyncio
import os
import signal

router = APIRouter()

# run_id → asyncio Process (for kill endpoint)
_running_processes: dict = {}
# run_id → accumulated output lines (survives WebSocket disconnects)
_run_buffers: dict[str, list[str]] = {}
# run_id → Event set when the background task has finished its DB write
_run_done_events: dict[str, asyncio.Event] = {}


class RunCreate(BaseModel):
    session_id: str
    tool_id: str
    param_values: dict = {}
    extra_flags: Optional[str] = ""


def build_command(tool: Tool, param_values: dict, extra_flags: str = "") -> str:
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


async def _execute_tool(run_id: str, command: str) -> None:
    """Background task: runs the subprocess and accumulates output.

    Survives WebSocket disconnects — the caller just stops reading from the
    buffer, but this task keeps the process alive and writing.
    """
    # Buffer and event may already exist (initialized by the WS handler before
    # this task was scheduled). Use setdefault so we don't clobber them.
    _run_buffers.setdefault(run_id, [])
    _run_done_events.setdefault(run_id, asyncio.Event())
    buf = _run_buffers[run_id]

    exit_code = -1
    run_status = "error"

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            limit=1024 * 1024,
            start_new_session=True,  # own process group so killpg reaches all children
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
    finally:
        _running_processes.pop(run_id, None)

    # Persist final output and status
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Run).where(Run.id == run_id))
        run = result.scalar_one_or_none()
        if run:
            run.output = "".join(buf)
            run.status = run_status
            run.exit_code = exit_code
            run.finished_at = datetime.now(timezone.utc)
            await db.commit()

    # Signal any waiting WebSocket handlers that the DB write is done
    _run_done_events[run_id].set()

    # Keep buffer alive briefly so a reconnect that arrives just after
    # completion can still get a replay without hitting the DB
    await asyncio.sleep(60)
    _run_buffers.pop(run_id, None)
    _run_done_events.pop(run_id, None)


@router.get("/session/{session_id}")
async def list_runs(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Run).where(Run.session_id == session_id).order_by(Run.created_at.desc())
    )
    runs = result.scalars().all()
    return [_run_dict(r) for r in runs]


@router.get("/{run_id}")
async def get_run(run_id: str, db: AsyncSession = Depends(get_db)):
    run = await _get_or_404(run_id, db)
    return _run_dict(run)


@router.post("/", status_code=201)
async def create_run(body: RunCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Tool).where(Tool.id == body.tool_id))
    tool = result.scalar_one_or_none()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    command = build_command(tool, body.param_values, body.extra_flags or "")

    run = Run(
        session_id=body.session_id,
        tool_id=tool.id,
        tool_name=tool.name,
        command=command,
        param_values=body.param_values,
        status="pending",
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return _run_dict(run)


@router.post("/{run_id}/kill", status_code=204)
async def kill_run(run_id: str, db: AsyncSession = Depends(get_db)):
    """Send SIGTERM to a running tool process and its entire process group."""
    process = _running_processes.get(run_id)
    if process is not None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                process.terminate()
            except Exception:
                pass


@router.delete("/{run_id}", status_code=204)
async def delete_run(run_id: str, db: AsyncSession = Depends(get_db)):
    run = await _get_or_404(run_id, db)
    await db.delete(run)
    await db.commit()


@router.websocket("/ws/{run_id}/execute")
async def execute_run(websocket: WebSocket, run_id: str):
    await websocket.accept()

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Run).where(Run.id == run_id))
        run = result.scalar_one_or_none()

        if not run:
            await websocket.send_json({"type": "error", "data": "Run not found"})
            await websocket.close()
            return

        # Already finished — replay stored output from DB and exit
        if run.status in ("complete", "error"):
            await websocket.send_json({"type": "command", "data": run.command})
            if run.output:
                await websocket.send_json({"type": "output", "data": run.output})
            await websocket.send_json({
                "type": "done",
                "data": f"\n[Replay] Finished with exit code {run.exit_code}\n",
                "exit_code": run.exit_code,
                "status": run.status,
            })
            await websocket.close()
            return

        # Pending — mark running, start the background task.
        # Initialize buffer and done event HERE (before create_task) so the
        # streaming loop below never sees buf=None for a brand-new run.
        if run.status == "pending":
            run.status = "running"
            run.started_at = datetime.now(timezone.utc)
            run.output = ""
            await db.commit()
            _run_buffers[run_id] = []
            _run_done_events[run_id] = asyncio.Event()
            asyncio.create_task(_execute_tool(run_id, run.command))
            await websocket.send_json({"type": "command", "data": run.command})
            await websocket.send_json({
                "type": "start",
                "data": f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Executing: {run.command}\n",
            })

        # Running (fresh start or reconnect) — stream from the shared buffer.
        # For a reconnect the buffer may already have output; replay it first.
        elif run.status == "running":
            await websocket.send_json({"type": "command", "data": run.command})
            buf = _run_buffers.get(run_id)
            if buf is None:
                # Buffer is gone (task finished and cleaned up after 60 s).
                # Re-read output from DB.
                await db.refresh(run)
                if run.output:
                    await websocket.send_json({"type": "output", "data": run.output})
                await websocket.send_json({
                    "type": "done",
                    "data": f"\n[Replay] Finished with exit code {run.exit_code}\n",
                    "exit_code": run.exit_code,
                    "status": run.status,
                })
                await websocket.close()
                return

    # ── Streaming loop ──────────────────────────────────────────────────────
    # Replay whatever is already in the buffer, then tail new lines.
    cursor = 0
    buf = _run_buffers.get(run_id, [])
    if buf:
        replay = "".join(buf)
        try:
            await websocket.send_json({"type": "output", "data": replay})
        except WebSocketDisconnect:
            return
        cursor = len(buf)

    try:
        while True:
            buf = _run_buffers.get(run_id)

            if buf is None:
                # Buffer cleaned up after 60s grace period — task long finished
                break

            if len(buf) > cursor:
                chunk = "".join(buf[cursor:])
                await websocket.send_json({"type": "output", "data": chunk})
                cursor = len(buf)

            # Done event fires only after subprocess exits AND DB write completes.
            # Safe to use as the exit signal — can never fire before the process starts.
            event = _run_done_events.get(run_id)
            if event and event.is_set():
                # Drain any lines that arrived between the last poll and the event
                buf = _run_buffers.get(run_id, [])
                if len(buf) > cursor:
                    chunk = "".join(buf[cursor:])
                    await websocket.send_json({"type": "output", "data": chunk})
                break

            await asyncio.sleep(0.05)

    except WebSocketDisconnect:
        # Client navigated away — background task keeps running
        return

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Run).where(Run.id == run_id))
        final_run = result.scalar_one_or_none()

    if final_run and final_run.status != "running":
        try:
            await websocket.send_json({
                "type": "done",
                "data": f"\n[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Finished with exit code {final_run.exit_code}\n",
                "exit_code": final_run.exit_code,
                "status": final_run.status,
            })
        except WebSocketDisconnect:
            pass

    try:
        await websocket.close()
    except Exception:
        pass


async def _get_or_404(run_id: str, db: AsyncSession) -> Run:
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


def _run_dict(r: Run) -> dict:
    return {
        "id": r.id,
        "session_id": r.session_id,
        "tool_id": r.tool_id,
        "tool_name": r.tool_name,
        "command": r.command,
        "output": r.output,
        "status": r.status,
        "exit_code": r.exit_code,
        "param_values": r.param_values,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "created_at": r.created_at.isoformat(),
    }
