import re
import uuid
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db
from app.models.session import Session
from app.models.run import Run
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

router = APIRouter()


class Finding(BaseModel):
    id: str
    title: str
    severity: str  # critical / high / medium / low / info
    notes: str = ""
    tool_run_id: Optional[str] = None          # legacy — kept for backwards compat
    evidence_run_ids: Optional[list] = None    # [{run_id, ...}] multi-evidence


class SessionCreate(BaseModel):
    name: str
    target: str
    scope: Optional[str] = ""
    engagement_type: str = "external"  # external / internal / web
    notes: Optional[str] = ""
    targets: Optional[list] = None  # [{id, value}]; initialized from target if omitted


class SessionUpdate(SessionCreate):
    status: Optional[str] = "active"
    findings: Optional[list[Finding]] = []
    targets: Optional[list] = None


class ChecklistUpdate(BaseModel):
    phase_checks: dict = {}
    custom_items: list = []


class TargetsUpdate(BaseModel):
    targets: list


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
    targets = body.targets
    if targets is None:
        targets = [{"id": str(uuid.uuid4()), "value": body.target}] if body.target else []
    session = Session(
        name=body.name,
        target=body.target,
        scope=body.scope,
        engagement_type=body.engagement_type,
        notes=body.notes,
        targets=targets,
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
    if body.targets is not None:
        session.targets = body.targets
    await db.commit()
    return _session_dict(session)


@router.patch("/{session_id}/targets")
async def update_targets(session_id: str, body: TargetsUpdate, db: AsyncSession = Depends(get_db)):
    session = await _get_or_404(session_id, db)
    session.targets = body.targets
    await db.commit()
    return {"targets": session.targets}


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


@router.get("/{session_id}/report.md")
async def export_report(session_id: str, db: AsyncSession = Depends(get_db)):
    session = await _get_or_404(session_id, db)
    result = await db.execute(
        select(Run).where(Run.session_id == session_id).order_by(Run.created_at)
    )
    runs = result.scalars().all()
    md = _build_report(session, runs)
    filename = _safe_filename(session.name)
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Report helpers ────────────────────────────────────────────────────────────

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_ANSI_RE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)


def _safe_filename(name: str) -> str:
    slug = re.sub(r'[^\w\s-]', '', name.lower())
    slug = re.sub(r'[\s_]+', '-', slug).strip('-')
    return f"quiver-report-{slug}.md"


def _build_report(session, runs) -> str:
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    created = session.created_at.strftime('%Y-%m-%d')

    lines = [
        f"# Pentest Report — {session.name}",
        "",
        "| | |",
        "|---|---|",
        f"| **Target** | `{session.target}` |",
        f"| **Scope** | {session.scope or '—'} |",
        f"| **Type** | {session.engagement_type.title()} |",
        f"| **Status** | {session.status.title()} |",
        f"| **Created** | {created} |",
        f"| **Generated** | {now} |",
        "",
        "---",
        "",
    ]

    # Findings
    lines += ["## Findings", ""]
    findings = sorted(
        session.findings or [],
        key=lambda f: _SEVERITY_ORDER.index(f.get("severity", "info"))
        if f.get("severity") in _SEVERITY_ORDER else 99,
    )

    if not findings:
        lines += ["*No findings logged.*", ""]
    else:
        for sev in _SEVERITY_ORDER:
            sev_group = [f for f in findings if f.get("severity") == sev]
            if not sev_group:
                continue
            lines += [f"### {sev.upper()} ({len(sev_group)})", ""]
            for f in sev_group:
                lines += [f"#### {f.get('title', 'Untitled')}", ""]
                if f.get("notes"):
                    lines += [f["notes"].strip(), ""]
                lines += ["---", ""]

    # Engagement notes
    if session.notes and session.notes.strip():
        lines += ["## Notes", "", session.notes.strip(), "", "---", ""]

    # Tool runs
    lines += ["## Tool Output", ""]
    completed = [r for r in runs if r.status in ("complete", "error")]

    if not completed:
        lines += ["*No tool runs recorded.*", ""]
    else:
        for run in completed:
            ts = run.finished_at or run.created_at
            ts_str = ts.strftime('%Y-%m-%d %H:%M UTC') if ts else "—"
            status_str = f"exit {run.exit_code}" if run.exit_code is not None else run.status

            lines += [
                f"### {run.tool_name}",
                "",
                f"**Time:** {ts_str}  ",
                f"**Status:** {status_str}  ",
                "",
                "**Command:**",
                "",
                "```",
                run.command,
                "```",
                "",
                "**Output:**",
                "",
                "```",
                _strip_ansi(run.output or "*(no output)*").rstrip(),
                "```",
                "",
                "---",
                "",
            ]

    return "\n".join(lines)


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
        "targets": s.targets or [],
        "campaign_id": s.campaign_id or None,
        "created_at": s.created_at.isoformat(),
        "updated_at": s.updated_at.isoformat(),
    }
