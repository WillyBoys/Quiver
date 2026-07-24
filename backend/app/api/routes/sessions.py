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
from typing import Optional, Literal
from datetime import datetime, timezone

router = APIRouter()


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    notes: str = ""
    tool_run_id: Optional[str] = None          # legacy — kept for backwards compat
    evidence_run_ids: Optional[list] = None    # [{run_id, ...}] multi-evidence
    chains_from_id: Optional[str] = ""


class SessionCreate(BaseModel):
    name: str
    target: str
    scope: Optional[str] = ""
    engagement_type: str = "external"  # external / internal / web
    notes: Optional[str] = ""
    targets: Optional[list] = None  # [{id, value}]; initialized from target if omitted


class SessionUpdate(SessionCreate):
    status: Optional[str] = "active"
    findings: Optional[list[Finding]] = None
    targets: Optional[list] = None
    campaign_id: Optional[str] = None


class NotesUpdate(BaseModel):
    notes: str


class ChecklistUpdate(BaseModel):
    phase_checks: dict = {}
    custom_items: list = []


class ReportGenerateRequest(BaseModel):
    provider: Optional[str] = "claude"
    name: Optional[str] = "Draft Report"


class ReportRenameRequest(BaseModel):
    name: str


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
    if body.campaign_id is not None:
        session.campaign_id = body.campaign_id
    if body.findings is not None:
        session.findings = [f.model_dump() for f in body.findings]
    if body.targets is not None:
        session.targets = body.targets
    await db.commit()
    return _session_dict(session)


@router.patch("/{session_id}/notes")
async def update_notes(session_id: str, body: NotesUpdate, db: AsyncSession = Depends(get_db)):
    session = await _get_or_404(session_id, db)
    session.notes = body.notes
    await db.commit()
    return {"notes": session.notes}


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


@router.post("/{session_id}/report/generate")
async def generate_ai_report(session_id: str, body: ReportGenerateRequest, db: AsyncSession = Depends(get_db)):
    from app.agent.llm import generate_report as llm_generate_report, AuthError
    from app.models.report import Report
    session = await _get_or_404(session_id, db)
    result = await db.execute(
        select(Run).where(Run.session_id == session_id).order_by(Run.created_at)
    )
    runs = result.scalars().all()
    prompt = _build_ai_report_prompt(session, runs)
    try:
        markdown = await llm_generate_report(prompt, provider=body.provider or "claude")
        report = Report(
            session_id=session_id,
            name=body.name or "Draft Report",
            provider=body.provider or "claude",
            content=markdown,
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)
        return _report_dict(report)
    except AuthError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Report generation failed: {e}")


@router.get("/{session_id}/reports")
async def list_reports(session_id: str, db: AsyncSession = Depends(get_db)):
    from app.models.report import Report
    await _get_or_404(session_id, db)
    result = await db.execute(
        select(Report).where(Report.session_id == session_id).order_by(Report.generated_at.desc())
    )
    return [_report_dict(r, include_content=False) for r in result.scalars().all()]


@router.get("/{session_id}/reports/{report_id}")
async def get_report(session_id: str, report_id: str, db: AsyncSession = Depends(get_db)):
    return _report_dict(await _get_report_or_404(session_id, report_id, db))


@router.patch("/{session_id}/reports/{report_id}")
async def rename_report(session_id: str, report_id: str, body: ReportRenameRequest, db: AsyncSession = Depends(get_db)):
    report = await _get_report_or_404(session_id, report_id, db)
    report.name = body.name.strip() or report.name
    await db.commit()
    return _report_dict(report, include_content=False)


@router.delete("/{session_id}/reports/{report_id}", status_code=204)
async def delete_report(session_id: str, report_id: str, db: AsyncSession = Depends(get_db)):
    report = await _get_report_or_404(session_id, report_id, db)
    await db.delete(report)
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

_SEVERITY_CVSS = {
    "critical": "9.0–10.0 (Critical)",
    "high": "7.0–8.9 (High)",
    "medium": "4.0–6.9 (Medium)",
    "low": "0.1–3.9 (Low)",
    "info": "0.0 (Informational)",
}


def _build_ai_report_prompt(session, runs) -> str:
    findings = session.findings or []
    findings_sorted = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.index(f.get("severity", "info"))
        if f.get("severity") in _SEVERITY_ORDER else 99,
    )
    findings_by_id = {f.get("id"): f for f in findings}

    # Build per-finding evidence snippets from linked run IDs
    runs_by_id = {r.id: r for r in runs}
    findings_text = ""
    if findings_sorted:
        for f in findings_sorted:
            sev = f.get("severity", "info")
            ev_ids = f.get("evidence_run_ids") or []
            ev_snippets = []
            for rid in ev_ids[:3]:
                r = runs_by_id.get(rid)
                if r:
                    out = _strip_ansi(r.output or "")[:400]
                    ev_snippets.append(f"  [{r.tool_name}] {r.command}\n  {out[:400]}")
            ev_text = "\n".join(ev_snippets) if ev_snippets else "  (no linked evidence runs)"
            parent = findings_by_id.get(f.get("chains_from_id", ""))
            chain_line = f"  Chains from: {parent['title']}\n" if parent else ""
            findings_text += (
                f"---\n"
                f"Title: {f.get('title', 'Untitled')}\n"
                f"Severity: {sev.upper()} | CVSS: {_SEVERITY_CVSS.get(sev, '')}\n"
                f"{chain_line}"
                f"Notes: {f.get('notes', '').strip() or '(no notes)'}\n"
                f"Evidence runs:\n{ev_text}\n\n"
            )
    else:
        findings_text = "(no findings logged)\n"

    # Tool run summary for coverage section
    completed = [r for r in runs if r.status in ("complete", "error", "timeout") and r.tool_name != "_summary"]
    timed_out = [r for r in completed if r.status == "timeout"]
    tools_used = sorted({r.tool_name for r in completed})
    coverage_text = f"Tools used: {', '.join(tools_used) or 'none'}\nTotal runs: {len(completed)}"
    if timed_out:
        coverage_text += f"\nTimed-out runs ({len(timed_out)} — may need manual follow-up):\n"
        for r in timed_out:
            coverage_text += f"  - {r.tool_name}: {r.command[:120]}\n"

    sev_counts = {}
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1
    count_str = ", ".join(f"{sev_counts[s]} {s}" for s in _SEVERITY_ORDER if s in sev_counts) or "0 findings"

    return f"""You are a senior penetration tester writing an internal technical brief for a colleague who will review these findings and write the final client report.

This is NOT a client deliverable. Write for a technical reviewer, not an executive. Be terse and precise.

ENGAGEMENT DETAILS:
- Session: {session.name}
- Target: {session.target}
- Type: {session.engagement_type.title()} Assessment
- Scope: {session.scope or 'Not specified'}
- Notes: {(session.notes or '').strip() or '(none)'}
- Finding count: {count_str}

CONFIRMED FINDINGS (sorted critical → info):
{findings_text}
COVERAGE SUMMARY:
{coverage_text}

Write a technical brief in Markdown using EXACTLY this structure. Do not add sections, do not write for executives, do not include remediation advice (the reviewer will add that):

# Technical Brief — {session.target}
> **Reviewer:** _______________  **Date reviewed:** _______________

## Engagement Summary
- **Type:** {session.engagement_type.title()}
- **Target:** {session.target}
- **Scope:** [one line from scope notes]
- **Tools run:** [count and tool names]
- **Finding count:** {count_str}
- **Overall risk:** [one word: Critical / High / Medium / Low / Informational — based on highest confirmed severity]

## Attack Surface
[Bullet list of what was discovered: open ports, exposed services, interesting endpoints. Pull from tool outputs. Be specific — include port numbers, versions, URLs.]

## Findings

[For EACH finding, use this exact format:]

### [SEVERITY] Finding Title
| Field | Value |
|-------|-------|
| **Severity** | SEVERITY — CVSS range |
| **Location** | specific URL, port, or service |
| **Chains from** | prior finding title OR — |

**Reproduction steps:**
1. [Exact step with specific values — commands, payloads, credentials]
2. [Continue until exploited]

**Key evidence:**
```
[paste the most relevant snippet from the evidence runs — the line(s) that prove it works]
```

**Reviewer notes:** [Flag anything the reviewer should manually verify or that needs more context. Be honest about uncertainty.]

---

## Attack Chains
[If any findings chain together, describe the kill chain in 2-3 sentences per chain. E.g. "SQLi (Finding 1) yielded admin JWT → used to access /api/Users (Finding 2) → mass assignment on POST /api/Users escalated to admin role (Finding 3)."]
[If no chains: write "No multi-step chains identified."]

## Coverage Gaps
[Bullet list of: what wasn't tested, what timed out, what was blocked by scope, what needs manual follow-up. Be specific about what a reviewer should check by hand.]

RULES:
- Write only what the evidence supports. Do not invent findings.
- No executive summary, no remediation steps, no client-facing language.
- Reproduction steps must use exact values from the evidence (real payloads, real endpoints, real commands).
- Flag uncertainty explicitly in Reviewer notes rather than stating something confidently if unsure.
- Reply with Markdown only — no preamble."""

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


async def _get_report_or_404(session_id: str, report_id: str, db: AsyncSession):
    from app.models.report import Report
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.session_id == session_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def _report_dict(r, include_content: bool = True) -> dict:
    d = {
        "id": r.id,
        "session_id": r.session_id,
        "name": r.name,
        "provider": r.provider,
        "generated_at": r.generated_at.isoformat(),
    }
    if include_content:
        d["content"] = r.content
    return d


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
