import logging
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from app.db.database import get_db
from app.models.campaign import Campaign
from app.models.session import Session as EngagementSession
from app.agent.scheduler import add_campaign_job, remove_campaign_job
from app.agent.engine import run_campaign_loop

logger = logging.getLogger(__name__)
router = APIRouter()


class CampaignCreate(BaseModel):
    name: str
    description: str = ""
    target_scope: list[str] = []
    schedule: Optional[str] = None
    risk_level: str = "notify"
    ai_provider: str = "local"


class CampaignUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target_scope: Optional[list[str]] = None
    schedule: Optional[str] = None
    risk_level: Optional[str] = None
    ai_provider: Optional[str] = None
    status: Optional[str] = None


@router.get("/")
async def list_campaigns(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Campaign).order_by(Campaign.created_at.desc()))
    return [_dict(c) for c in result.scalars().all()]


@router.get("/{campaign_id}")
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    return _dict(await _get_or_404(campaign_id, db))


@router.post("/", status_code=201)
async def create_campaign(body: CampaignCreate, db: AsyncSession = Depends(get_db)):
    campaign = Campaign(
        name=body.name,
        description=body.description,
        target_scope=[t.strip() for t in body.target_scope if t.strip()],
        schedule=body.schedule or None,
        risk_level=body.risk_level,
        ai_provider=body.ai_provider,
    )
    db.add(campaign)
    await db.commit()
    await db.refresh(campaign)
    if campaign.schedule:
        add_campaign_job(campaign.id, campaign.schedule)
    logger.info("CAMPAIGN CREATE | id=%s name=%s schedule=%s", campaign.id, campaign.name, campaign.schedule)
    return _dict(campaign)


@router.put("/{campaign_id}")
async def update_campaign(campaign_id: str, body: CampaignUpdate, db: AsyncSession = Depends(get_db)):
    campaign = await _get_or_404(campaign_id, db)
    old_schedule = campaign.schedule

    if body.name is not None:
        campaign.name = body.name
    if body.description is not None:
        campaign.description = body.description
    if body.target_scope is not None:
        campaign.target_scope = [t.strip() for t in body.target_scope if t.strip()]
    if body.schedule is not None:
        campaign.schedule = body.schedule or None
    if body.risk_level is not None:
        campaign.risk_level = body.risk_level
    if body.ai_provider is not None:
        campaign.ai_provider = body.ai_provider
    if body.status is not None:
        campaign.status = body.status
        if body.status == "paused":
            remove_campaign_job(campaign_id)
        elif body.status == "active" and campaign.schedule:
            add_campaign_job(campaign_id, campaign.schedule)

    if campaign.schedule and campaign.schedule != old_schedule:
        add_campaign_job(campaign_id, campaign.schedule)

    campaign.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return _dict(campaign)


@router.delete("/{campaign_id}", status_code=204)
async def delete_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    campaign = await _get_or_404(campaign_id, db)
    remove_campaign_job(campaign_id)
    await db.delete(campaign)
    await db.commit()


@router.post("/{campaign_id}/run")
async def trigger_campaign(
    campaign_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    campaign = await _get_or_404(campaign_id, db)
    if campaign.status != "active":
        raise HTTPException(status_code=400, detail="Campaign must be active to run")
    background_tasks.add_task(run_campaign_loop, campaign_id)
    logger.info("CAMPAIGN RUN | id=%s triggered manually", campaign_id)
    return {"message": "Agent loop triggered", "campaign_id": campaign_id}


@router.get("/{campaign_id}/session")
async def get_campaign_session(campaign_id: str, db: AsyncSession = Depends(get_db)):
    campaign = await _get_or_404(campaign_id, db)
    if not campaign.session_id:
        return None
    result = await db.execute(
        select(EngagementSession).where(EngagementSession.id == campaign.session_id)
    )
    session = result.scalar_one_or_none()
    return {"id": session.id, "name": session.name} if session else None


async def _get_or_404(campaign_id: str, db: AsyncSession) -> Campaign:
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


def _dict(c: Campaign) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "description": c.description,
        "target_scope": c.target_scope,
        "schedule": c.schedule,
        "status": c.status,
        "risk_level": c.risk_level,
        "ai_provider": c.ai_provider or "local",
        "session_id": c.session_id,
        "last_agent_reasoning": c.last_agent_reasoning or "",
        "created_at": c.created_at.isoformat(),
        "updated_at": c.updated_at.isoformat(),
        "last_run_at": c.last_run_at.isoformat() if c.last_run_at else None,
    }
