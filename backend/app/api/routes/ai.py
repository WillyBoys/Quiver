import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.db.database import get_db
from app.models.run import Run

logger = logging.getLogger(__name__)
router = APIRouter()

OLLAMA_URL = "http://ai:11434"
MODEL = "phi3:mini"
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

    logger.info("AI ANALYZE | run_id=%s tool=%s model=%s", run.id, run.tool_name, MODEL)

    try:
        async with httpx.AsyncClient(timeout=360.0) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "num_ctx": 4096,
                    },
                },
            )

        if resp.status_code != 200:
            logger.error("Ollama returned %s: %s", resp.status_code, resp.text[:500])
            raise HTTPException(status_code=502, detail="AI service returned an error")

        data = resp.json()
        analysis = data.get("response", "").strip()
        logger.info("AI DONE   | run_id=%s chars=%d", run.id, len(analysis))
        return {"analysis": analysis, "model": MODEL, "run_id": body.run_id}

    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail="AI service unavailable. Make sure Ollama is running (docker compose up ai).",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Analysis timed out. The model may still be loading — try again in a moment.",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("AI analyze unexpected error: %s", str(e))
        raise HTTPException(status_code=500, detail="Analysis failed")
