import logging

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
import os

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:////data/pentest.db")
# Convert sqlite:// to sqlite+aiosqlite://
if DATABASE_URL.startswith("sqlite:///"):
    DATABASE_URL = DATABASE_URL.replace("sqlite:///", "sqlite+aiosqlite:///", 1)

# NullPool: each async session gets its own SQLite connection, preventing pool exhaustion
# when the agent loop holds connections across long awaits.
engine = create_async_engine(DATABASE_URL, echo=False, poolclass=NullPool)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db():
    from app.models import tool, session, run, campaign, report, pipeline  # noqa: import all models
    async with engine.begin() as conn:
        # Enable WAL mode so reads never block writes (persists in the DB file)
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.execute(text("PRAGMA busy_timeout=5000"))
        await conn.run_sync(Base.metadata.create_all)
        # Migrate: add checklist_state to existing sessions tables that pre-date this column
        try:
            await conn.execute(text("ALTER TABLE sessions ADD COLUMN checklist_state JSON DEFAULT '{}'"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE sessions ADD COLUMN targets JSON DEFAULT '[]'"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE runs ADD COLUMN reasoning TEXT DEFAULT ''"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE campaigns ADD COLUMN last_agent_reasoning TEXT DEFAULT ''"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE campaigns ADD COLUMN ai_provider TEXT DEFAULT 'local'"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE sessions ADD COLUMN campaign_id TEXT DEFAULT NULL"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE campaigns ADD COLUMN max_iterations INTEGER DEFAULT NULL"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE campaigns ADD COLUMN iteration_count INTEGER NOT NULL DEFAULT 0"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE campaigns ADD COLUMN engagement_type TEXT DEFAULT 'external'"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE sessions ADD COLUMN artifacts JSON DEFAULT '{}'"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE sessions ADD COLUMN initial_context JSON DEFAULT '{}'"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE campaigns ADD COLUMN pipeline_mode TEXT DEFAULT 'single'"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        # pipeline_runs columns — table may have been created by P1 with fewer columns
        for col_sql in [
            "ALTER TABLE pipeline_runs ADD COLUMN session_id TEXT DEFAULT NULL",
            "ALTER TABLE pipeline_runs ADD COLUMN engagement_type TEXT DEFAULT 'external'",
            "ALTER TABLE pipeline_runs ADD COLUMN current_phase INTEGER DEFAULT 1",
            "ALTER TABLE pipeline_runs ADD COLUMN phase_count INTEGER DEFAULT 0",
            "ALTER TABLE pipeline_runs ADD COLUMN specialist_results JSON DEFAULT '{}'",
            "ALTER TABLE pipeline_runs ADD COLUMN synthesis_outputs JSON DEFAULT '[]'",
            "ALTER TABLE pipeline_runs ADD COLUMN skipped_phases JSON DEFAULT '[]'",
            "ALTER TABLE pipeline_runs ADD COLUMN started_at DATETIME DEFAULT NULL",
            "ALTER TABLE pipeline_runs ADD COLUMN completed_at DATETIME DEFAULT NULL",
        ]:
            try:
                await conn.execute(text(col_sql))
            except OperationalError as e:
                if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                    logger.warning("Migration warning: %s", e)
        # Ensure indexes exist on pre-index DBs
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_runs_session_id ON runs (session_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_campaigns_status ON campaigns (status)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_campaigns_session_id ON campaigns (session_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_approval_requests_campaign_id ON approval_requests (campaign_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_approval_requests_status ON approval_requests (status)"
        ))


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
