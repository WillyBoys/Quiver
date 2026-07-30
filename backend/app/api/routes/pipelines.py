import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db
from app.models.pipeline import PipelineRun

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/")
async def list_pipeline_runs(campaign_id: str | None = None, db: AsyncSession = Depends(get_db)):
    query = select(PipelineRun).order_by(PipelineRun.created_at.desc())
    if campaign_id:
        query = query.where(PipelineRun.campaign_id == campaign_id)
    result = await db.execute(query)
    return [_dict(r) for r in result.scalars().all()]


@router.get("/{run_id}")
async def get_pipeline_run(run_id: str, db: AsyncSession = Depends(get_db)):
    return _dict(await _get_or_404(run_id, db))


async def _get_or_404(run_id: str, db: AsyncSession) -> PipelineRun:
    result = await db.execute(select(PipelineRun).where(PipelineRun.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return run


def _dict(r: PipelineRun) -> dict:
    return {
        "id": r.id,
        "campaign_id": r.campaign_id,
        "phase": r.phase,
        "status": r.status,
        "specialist_results": r.specialist_results or {},
        "synthesis_directives": r.synthesis_directives or [],
        "error": r.error or "",
        "created_at": r.created_at.isoformat(),
        "updated_at": r.updated_at.isoformat(),
    }
