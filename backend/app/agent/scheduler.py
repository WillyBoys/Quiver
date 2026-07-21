import logging
from datetime import datetime, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from sqlalchemy import select
from app.db.database import AsyncSessionLocal
from app.models.campaign import Campaign

logger = logging.getLogger(__name__)

_scheduler = AsyncIOScheduler()


async def _run_job(campaign_id: str) -> None:
    from app.agent.engine import run_campaign_loop  # late import avoids circular at module load
    logger.info("SCHEDULER | firing campaign %s", campaign_id)
    try:
        await run_campaign_loop(campaign_id)
        logger.info("SCHEDULER | campaign %s loop complete", campaign_id)
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


def _is_datetime_schedule(s: str) -> bool:
    """True when s looks like an ISO 8601 datetime rather than a cron expression."""
    # A cron expression has exactly 5 space-separated tokens
    if len(s.strip().split()) == 5:
        return False
    # ISO 8601 datetimes contain "T" and multiple dashes
    return "T" in s or (s.count("-") >= 2 and s.count(" ") < 4)


def _add_job(campaign_id: str, schedule: str) -> None:
    try:
        if _is_datetime_schedule(schedule):
            run_date = datetime.fromisoformat(schedule.replace("Z", "+00:00"))
            # If the time has already passed, skip rather than fire instantly
            if run_date < datetime.now(timezone.utc):
                logger.warning("SCHEDULER | scheduled time already passed for campaign %s — skipping", campaign_id)
                return
            trigger = DateTrigger(run_date=run_date, timezone=timezone.utc)
            logger.info("SCHEDULER | one-shot job added for campaign %s at %s", campaign_id, run_date.isoformat())
        else:
            trigger = CronTrigger.from_crontab(schedule)
            logger.info("SCHEDULER | cron job added for campaign %s: %s", campaign_id, schedule)

        _scheduler.add_job(
            _run_job,
            trigger=trigger,
            args=[campaign_id],
            id=f"campaign_{campaign_id}",
            replace_existing=True,
            misfire_grace_time=120,
        )
    except Exception as e:
        logger.error("SCHEDULER | failed to add job for campaign %s: %s", campaign_id, e)


def add_campaign_job(campaign_id: str, schedule: str) -> None:
    _add_job(campaign_id, schedule)


def remove_campaign_job(campaign_id: str) -> None:
    job_id = f"campaign_{campaign_id}"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)
        logger.info("SCHEDULER | job removed for campaign %s", campaign_id)


def stop_scheduler() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
