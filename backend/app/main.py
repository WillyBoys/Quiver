import logging
import sys
import time
import asyncio
from logging.handlers import RotatingFileHandler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

import httpx

from app.db.database import init_db
from app.api.routes import tools, sessions, wordlists, runs, ai, campaigns, approvals, shannon, pipelines
from app.db.seed import seed_default_tools
from app.config import OLLAMA_URL, OLLAMA_MODEL
from app.agent.scheduler import start_scheduler, stop_scheduler


def _setup_logging() -> None:
    fmt = logging.Formatter(
        fmt="%(asctime)s UTC | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fmt.converter = time.gmtime  # force UTC regardless of server timezone

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        fh = RotatingFileHandler(
            "/data/quiver.log",
            maxBytes=10 * 1024 * 1024,  # 10 MB per file
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        logging.getLogger(__name__).warning("Could not open /data/quiver.log — file logging disabled")


_setup_logging()
logger = logging.getLogger(__name__)


async def _warmup_ai() -> None:
    """Send a tiny inference request so the configured model is loaded into RAM before first use."""
    await asyncio.sleep(5)  # give Ollama a moment after compose start
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": "hi", "stream": False,
                      "options": {"num_predict": 1}},
            )
        if resp.status_code == 200:
            logger.info("AI warmup complete — %s is loaded and ready", OLLAMA_MODEL)
        else:
            logger.warning("AI warmup got status %s — model may load on first use", resp.status_code)
    except Exception as e:
        logger.warning("AI warmup skipped (%s) — model will load on first analyze", e)


async def _reset_stale_campaigns():
    """On startup, reset interrupted campaigns so operators can restart deliberately.

    - "active" → "paused": loop was mid-run when the process died
    - "awaiting_approval" → "paused": the background resume task is gone; the
      approval (if still pending) will re-surface immediately when the user
      re-triggers the campaign, and will go through the fixed approval path
    """
    from app.models.campaign import Campaign
    from app.db.database import AsyncSessionLocal
    from sqlalchemy import select, or_
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Campaign).where(
                or_(Campaign.status == "active", Campaign.status == "awaiting_approval")
            )
        )
        stale = result.scalars().all()
        for c in stale:
            c.status = "paused"
        if stale:
            await db.commit()
            logger.warning("Startup: reset %d interrupted campaign(s) to paused", len(stale))


async def _reset_stale_pipeline_runs():
    """On startup, reset any PipelineRun still in 'running' status to 'paused'.
    These were interrupted when the process died and are resumable."""
    from app.models.pipeline import PipelineRun
    from app.db.database import AsyncSessionLocal
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(PipelineRun).where(PipelineRun.status == "running"))
        stale = result.scalars().all()
        for r in stale:
            r.status = "paused"
        if stale:
            await db.commit()
            logger.warning("Startup: reset %d interrupted pipeline run(s) to paused", len(stale))


async def _reset_stale_runs():
    """On startup, mark any run still in 'running' status as 'error'.
    These are runs whose subprocess died when the backend process did."""
    from app.models.run import Run
    from app.db.database import AsyncSessionLocal
    from sqlalchemy import select
    from datetime import datetime, timezone
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Run).where(Run.status == "running"))
        stale = result.scalars().all()
        for r in stale:
            r.status = "error"
            r.output = (r.output or "") + "\n[run interrupted by backend restart]"
            r.finished_at = datetime.now(timezone.utc)
        if stale:
            await db.commit()
            logger.warning("Startup: marked %d interrupted run(s) as error", len(stale))


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Quiver API starting up")
    await init_db()
    await _reset_stale_pipeline_runs()
    await _reset_stale_runs()
    await _reset_stale_campaigns()
    await seed_default_tools()
    asyncio.create_task(_warmup_ai())
    await start_scheduler()
    logger.info("Quiver API ready")
    yield
    stop_scheduler()
    logger.info("Quiver API shutting down")


app = FastAPI(
    title="Quiver API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
app.include_router(wordlists.router, prefix="/api/wordlists", tags=["wordlists"])
app.include_router(runs.router, prefix="/api/runs", tags=["runs"])
app.include_router(ai.router, prefix="/api/ai", tags=["ai"])
app.include_router(campaigns.router, prefix="/api/campaigns", tags=["campaigns"])
app.include_router(approvals.router, prefix="/api/approvals", tags=["approvals"])
app.include_router(shannon.router, prefix="/api/shannon", tags=["shannon"])
app.include_router(pipelines.router, prefix="/api/pipelines", tags=["pipelines"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}
