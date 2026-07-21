import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
from app.db.database import get_db
from app.models.run import Run
from app.agent.llm import generate as llm_generate

logger = logging.getLogger(__name__)
router = APIRouter()

MAX_OUTPUT_CHARS = 8000


def _build_prompt(tool_name: str, command: str, output: str) -> str:
    truncated = output[:MAX_OUTPUT_CHARS]
    if len(output) > MAX_OUTPUT_CHARS:
        truncated += f"\n[... output truncated at {MAX_OUTPUT_CHARS} chars ...]"
    return f"""Analyze this penetration testing tool output. Be concise and technical.

Tool: {tool_name}
Command: {command}

--- OUTPUT ---
{truncated}
--- END OUTPUT ---

Respond in exactly this format (no extra text before or after):

SUMMARY
[2-3 sentences on what this output shows overall]

FINDINGS
[Bullet list of notable items: open ports, services, versions, vulnerabilities, credentials, misconfigurations. Include specific values.]

NEXT STEPS
[Bullet list of specific follow-up commands or actions a penetration tester should take based on these results]"""


class AnalyzeRequest(BaseModel):
    run_id: str
    provider: Optional[str] = "local"  # "local" or "claude"


@router.post("/analyze")
async def analyze_run(body: AnalyzeRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == body.run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status not in ("complete", "error"):
        raise HTTPException(status_code=400, detail="Run has not finished yet")
    if not run.output or not run.output.strip():
        raise HTTPException(status_code=400, detail="Run produced no output to analyze")

    prompt = _build_prompt(run.tool_name or "unknown", run.command or "", run.output)
    provider = body.provider or "local"

    logger.info("AI ANALYZE | run_id=%s tool=%s provider=%s", run.id, run.tool_name, provider)

    try:
        analysis, model_used = await llm_generate(prompt, provider=provider)
        logger.info("AI DONE   | run_id=%s model=%s chars=%d", run.id, model_used, len(analysis))
        return {"analysis": analysis, "model": model_used, "run_id": body.run_id}
    except RuntimeError as e:
        if "ANTHROPIC_API_KEY" in str(e):
            raise HTTPException(status_code=503, detail=str(e))
        raise HTTPException(status_code=503, detail=f"AI service unavailable: {e}")
    except Exception as e:
        logger.error("AI analyze unexpected error: %s", str(e))
        raise HTTPException(status_code=500, detail="Analysis failed")
