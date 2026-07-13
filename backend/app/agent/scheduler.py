import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select
from app.db.database import AsyncSessionLocal
from app.models.campaign import Campaign

logger = logging.getLogger(__name__)

_scheduler = AsyncIOScheduler()


async def _run_job(campaign_id: str) -> None:
    from app.agent.engine import run_campaign_agent  # late import avoids circular at module load
    logger.info("SCHEDULER | firing campaign %s", campaign_id)
    try:
        status = await run_campaign_agent(campaign_id)
        logger.info("SCHEDULER | campaign %s result: %s", campaign_id, status)
    except Exception as e:
        logger.error("SCHEDULER | campaign %s error: %s", campaign_id, e)


async def start_scheduler() -> None:
    """Load all active scheduled campaigns from DB and start the APScheduler."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Campaign)
            .where(Campaign.status == "active")
            .where(Campaign.schedule.isnot(None))
        )
        campaigns = result.scalars().all()

    for campaign in campaigns:
        _add_job(campaign.id, campaign.schedule)

    _scheduler.start()
    logger.info("SCHEDULER | started with %d scheduled campaign(s)", len(campaigns))


def _add_job(campaign_id: str, cron_str: str) -> None:
    try:
        trigger = CronTrigger.from_crontab(cron_str)
        _scheduler.add_job(
            _run_job,
            trigger=trigger,
            args=[campaign_id],
            id=f"campaign_{campaign_id}",
            replace_existing=True,
            misfire_grace_time=120,
        )
        logger.info("SCHEDULER | job added for campaign %s: %s", campaign_id, cron_str)
    except Exception as e:
        logger.error("SCHEDULER | failed to add job for campaign %s: %s", campaign_id, e)


def add_campaign_job(campaign_id: str, cron_str: str) -> None:
    _add_job(campaign_id, cron_str)


def remove_campaign_job(campaign_id: str) -> None:
    job_id = f"campaign_{campaign_id}"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)
        logger.info("SCHEDULER | job removed for campaign %s", campaign_id)


def stop_scheduler() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
