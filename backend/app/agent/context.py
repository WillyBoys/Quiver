import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.run import Run
from app.models.tool import Tool
from app.models.campaign import Campaign

logger = logging.getLogger(__name__)

MAX_OUTPUT_PER_RUN = 600
MAX_RUNS = 10


async def build_agent_prompt(campaign: Campaign, db: AsyncSession) -> str:
    """Assemble the ReAct prompt from live campaign + session state."""

    runs = []
    if campaign.session_id:
        result = await db.execute(
            select(Run)
            .where(Run.session_id == campaign.session_id)
            .where(Run.status.in_(["complete", "error"]))
            .order_by(Run.created_at.desc())
            .limit(MAX_RUNS)
        )
        runs = list(reversed(result.scalars().all()))

    result = await db.execute(select(Tool).where(Tool.enabled == True))
    tools = result.scalars().all()

    scope_str = "\n".join(f"  - {s}" for s in (campaign.target_scope or []))

    tool_lines = []
    for t in tools:
        params = ", ".join(
            f"{p['name']} ({'required' if p.get('required') else 'optional'})"
            for p in (t.parameters or [])
        )
        tool_lines.append(
            f"  - {t.name}: {t.description or t.category} "
            f"| binary: {t.binary} | params: {params or 'none'}"
        )
    tools_str = "\n".join(tool_lines) or "  (no tools configured)"

    action_lines = []
    for run in runs:
        out = (run.output or "")[:MAX_OUTPUT_PER_RUN]
        if len(run.output or "") > MAX_OUTPUT_PER_RUN:
            out += "..."
        action_lines.append(
            f"  [{run.tool_name}] {run.command}\n"
            f"  Status: {run.status}\n"
            f"  Output: {out or '(no output)'}\n"
        )
    actions_str = "\n".join(action_lines) or "  (none yet — this is the first action)"

    return f"""You are a professional penetration tester AI conducting a systematic security assessment.

TARGET SCOPE (only test these targets):
{scope_str}

AVAILABLE TOOLS:
{tools_str}

ACTIONS TAKEN SO FAR (oldest first):
{actions_str}

Decide the single best NEXT action. Build logically on previous results:
if ports are open, enumerate those services; if services are found, check for vulnerabilities.

Respond with ONLY valid JSON (no text before or after the JSON):
{{
  "reasoning": "Brief explanation of why this is the next logical step",
  "tool_name": "exact tool name from available tools",
  "target": "specific IP, domain, or URL",
  "parameters": {{"param_name": "value"}}
}}

If the assessment is complete or no further productive actions remain, respond:
{{
  "reasoning": "Why the assessment is complete",
  "done": true
}}

Rules:
- Only target systems within TARGET SCOPE or subdomains/IPs discovered from them
- Use exact tool names from AVAILABLE TOOLS
- Be specific — exact IPs or hostnames, not ranges
- Never repeat an action that was already taken with the same target and parameters"""
