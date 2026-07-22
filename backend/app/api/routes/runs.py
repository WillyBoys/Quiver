import logging
import shlex
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db, AsyncSessionLocal
from app.models.run import Run
from app.models.tool import Tool
from app.models.session import Session as EngagementSession
from app.execution import (
    _running_processes,
    _run_buffers,
    _run_done_events,
    build_command,
    kill_process,
    execute_run_background,
)
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import asyncio

logger = logging.getLogger(__name__)

router = APIRouter()


class RunCreate(BaseModel):
    session_id: str
    tool_id: Optional[str] = None
    command: Optional[str] = None   # free-form shell run (no tool lookup)
    param_values: dict = {}
    extra_flags: Optional[str] = ""


@router.get("/session/{session_id}")
async def list_runs(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Run).where(Run.session_id == session_id).order_by(Run.created_at.desc())
    )
    runs = result.scalars().all()
    return [_run_dict(r) for r in runs]


@router.get("/all")
async def list_all_runs(limit: int = Query(default=500, ge=1, le=10000), db: AsyncSession = Depends(get_db)):
    """All runs across every session, newest first, with session name included."""
    stmt = (
        select(Run, EngagementSession.name.label("session_name"))
        .outerjoin(EngagementSession, Run.session_id == EngagementSession.id)
        .order_by(Run.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    rows = result.all()
    return [
        {**_run_dict(run), "session_name": session_name or "Unknown"}
        for run, session_name in rows
    ]


@router.get("/{run_id}")
async def get_run(run_id: str, db: AsyncSession = Depends(get_db)):
    run = await _get_or_404(run_id, db)
    return _run_dict(run)


@router.post("/", status_code=201)
async def create_run(body: RunCreate, db: AsyncSession = Depends(get_db)):
    session_check = await db.execute(select(EngagementSession).where(EngagementSession.id == body.session_id))
    if not session_check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Session not found")
    if body.tool_id:
        result = await db.execute(select(Tool).where(Tool.id == body.tool_id))
        tool = result.scalar_one_or_none()
        if not tool:
            raise HTTPException(status_code=404, detail="Tool not found")
        cmd_list = build_command(tool, body.param_values, body.extra_flags or "")
        command = " ".join(cmd_list)
        tool_id = tool.id
        tool_name = tool.name
    elif body.command:
        command = body.command.strip()
        if not command:
            raise HTTPException(status_code=400, detail="command is required")
        tool_id = "shell"
        tool_name = command.split()[0]  # first token for tab label
    else:
        raise HTTPException(status_code=400, detail="Either tool_id or command is required")

    run = Run(
        session_id=body.session_id,
        tool_id=tool_id,
        tool_name=tool_name,
        command=command,
        param_values=body.param_values,
        status="pending",
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    logger.info("RUN QUEUED | run_id=%s session_id=%s tool=%s | %s", run.id, run.session_id, run.tool_name, command[:300])
    return _run_dict(run)


@router.post("/{run_id}/kill", status_code=204)
async def kill_run(run_id: str, db: AsyncSession = Depends(get_db)):
    kill_process(run_id)


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
            # Reconstruct a safe argument list. Shell/manual runs wrap in bash -c to
            # preserve pipes/redirects; tool runs re-split the stored command string.
            if run.tool_id == "shell":
                run_cmd_list = ["bash", "-c", run.command]
            else:
                try:
                    run_cmd_list = shlex.split(run.command)
                except ValueError:
                    run_cmd_list = run.command.split()
            asyncio.create_task(execute_run_background(run_id, run_cmd_list, run.session_id, run.tool_name))
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
        "reasoning": r.reasoning or "",
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "created_at": r.created_at.isoformat(),
    }
