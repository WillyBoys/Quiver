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

# Maps run_id -> running asyncio Process so the kill endpoint can reach it.
_running_processes: dict = {}


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
        tool_id=body.tool_id,
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

        if run.status == "running":
            await websocket.send_json({"type": "error", "data": "Run already in progress"})
            await websocket.close()
            return

        run.status = "running"
        run.started_at = datetime.now(timezone.utc)
        run.output = ""
        await db.commit()

        await websocket.send_json({"type": "command", "data": run.command})
        await websocket.send_json({"type": "start", "data": f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Executing: {run.command}\n"})

        full_output = []
        exit_code = -1

        try:
            process = await asyncio.create_subprocess_shell(
                run.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                limit=1024 * 1024,
                start_new_session=True,  # own process group so killpg reaches all children
            )
            _running_processes[run_id] = process

            async for line_bytes in process.stdout:
                line = line_bytes.decode("utf-8", errors="replace")
                full_output.append(line)
                await websocket.send_json({"type": "output", "data": line})

            await process.wait()
            exit_code = process.returncode

        except WebSocketDisconnect:
            run.status = "error"
        except Exception as e:
            error_line = f"\n[ERROR] {str(e)}\n"
            full_output.append(error_line)
            try:
                await websocket.send_json({"type": "output", "data": error_line})
            except Exception:
                pass
            run.status = "error"
        else:
            run.status = "complete" if exit_code == 0 else "error"
        finally:
            _running_processes.pop(run_id, None)

        run.output = "".join(full_output)
        run.exit_code = exit_code
        run.finished_at = datetime.now(timezone.utc)
        await db.commit()

        try:
            await websocket.send_json({
                "type": "done",
                "data": f"\n[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Finished with exit code {exit_code}\n",
                "exit_code": exit_code,
                "status": run.status,
            })
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
