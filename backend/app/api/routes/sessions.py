from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db
from app.models.session import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter()


class Finding(BaseModel):
    id: str
    title: str
    severity: str  # critical / high / medium / low / info
    notes: str = ""
    tool_run_id: Optional[str] = None


class SessionCreate(BaseModel):
    name: str
    target: str
    scope: Optional[str] = ""
    engagement_type: str = "external"  # external / internal / web
    notes: Optional[str] = ""


class SessionUpdate(SessionCreate):
    status: Optional[str] = "active"
    findings: Optional[list[Finding]] = []


class ChecklistUpdate(BaseModel):
    phase_checks: dict = {}
    custom_items: list = []


@router.get("/")
async def list_sessions(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Session).order_by(Session.created_at.desc()))
    sessions = result.scalars().all()
    return [_session_dict(s) for s in sessions]


@router.get("/{session_id}")
async def get_session(session_id: str, db: AsyncSession = Depends(get_db)):
    session = await _get_or_404(session_id, db)
    return _session_dict(session)


@router.post("/", status_code=201)
async def create_session(body: SessionCreate, db: AsyncSession = Depends(get_db)):
    session = Session(
        name=body.name,
        target=body.target,
        scope=body.scope,
        engagement_type=body.engagement_type,
        notes=body.notes,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return _session_dict(session)


@router.put("/{session_id}")
async def update_session(session_id: str, body: SessionUpdate, db: AsyncSession = Depends(get_db)):
    session = await _get_or_404(session_id, db)
    session.name = body.name
    session.target = body.target
    session.scope = body.scope
    session.engagement_type = body.engagement_type
    session.notes = body.notes
    session.status = body.status
    if body.findings is not None:
        session.findings = [f.model_dump() for f in body.findings]
    await db.commit()
    return _session_dict(session)


@router.patch("/{session_id}/checklist")
async def update_checklist(session_id: str, body: ChecklistUpdate, db: AsyncSession = Depends(get_db)):
    session = await _get_or_404(session_id, db)
    session.checklist_state = {"phase_checks": body.phase_checks, "custom_items": body.custom_items}
    await db.commit()
    return {"checklist_state": session.checklist_state}


@router.delete("/{session_id}", status_code=204)
async def delete_session(session_id: str, db: AsyncSession = Depends(get_db)):
    session = await _get_or_404(session_id, db)
    await db.delete(session)
    await db.commit()


async def _get_or_404(session_id: str, db: AsyncSession) -> Session:
    result = await db.execute(select(Session).where(Session.id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


def _session_dict(s: Session) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "target": s.target,
        "scope": s.scope,
        "engagement_type": s.engagement_type,
        "notes": s.notes,
        "status": s.status,
        "findings": s.findings or [],
        "checklist_state": s.checklist_state or {},
        "created_at": s.created_at.isoformat(),
        "updated_at": s.updated_at.isoformat(),
    }
