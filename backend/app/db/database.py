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
        # Migrate pipeline_runs off the old NOT NULL 'phase' column (renamed to
        # 'current_phase' in this model) by rebuilding the table instead of dropping
        # it outright — this preserves existing pipeline run history rather than
        # silently deleting it. SQLite can't rename/relax a NOT NULL column in place,
        # so the old table is renamed aside, a fresh one is created with the current
        # schema, and matching columns are copied across.
        old_pipeline_columns: list[str] = []
        needs_pipeline_runs_migration = False
        try:
            result = await conn.execute(text("PRAGMA table_info(pipeline_runs)"))
            old_pipeline_columns = [row[1] for row in result.fetchall()]
            needs_pipeline_runs_migration = bool(
                old_pipeline_columns and "phase" in old_pipeline_columns
                and "current_phase" not in old_pipeline_columns
            )
            if needs_pipeline_runs_migration:
                await conn.execute(text("ALTER TABLE pipeline_runs RENAME TO pipeline_runs_old"))
        except Exception as e:
            logger.warning("pipeline_runs schema check failed: %s", e)
            needs_pipeline_runs_migration = False

        await conn.run_sync(Base.metadata.create_all)

        if needs_pipeline_runs_migration:
            # Columns the current model requires (NOT NULL, no SQL-level server_default)
            # that a genuinely old "P1" table (per the comment further down) may not have
            # had at all. A plain INSERT...SELECT would omit these entirely and hit a
            # NOT NULL constraint failure, so fall back to each column's Python-side
            # default value when the old table doesn't have it.
            _FALLBACKS = {
                "engagement_type": "'external'",
                "status": "'running'",
                "phase_count": "0",
                "specialist_results": "'{}'",
                "synthesis_outputs": "'[]'",
                "skipped_phases": "'[]'",
                "error": "''",
                "started_at": "CURRENT_TIMESTAMP",
                "created_at": "CURRENT_TIMESTAMP",
                "updated_at": "CURRENT_TIMESTAMP",
                "session_id": "NULL",
                "completed_at": "NULL",
            }
            try:
                from app.models.pipeline import PipelineRun
                new_columns = [c.name for c in PipelineRun.__table__.columns]
                insert_cols = []
                select_exprs = []
                for col in new_columns:
                    insert_cols.append(col)
                    if col == "current_phase":
                        # Old rows may predate even the 'phase' column having a value.
                        select_exprs.append("COALESCE(phase, 1)")
                    elif col in old_pipeline_columns:
                        fallback = _FALLBACKS.get(col)
                        # The column can exist in the old table yet still hold NULL
                        # for a row — guard against that, not just the column's absence.
                        select_exprs.append(f"COALESCE({col}, {fallback})" if fallback else col)
                    else:
                        select_exprs.append(_FALLBACKS.get(col, "NULL"))
                await conn.execute(text(
                    f"INSERT INTO pipeline_runs ({', '.join(insert_cols)}) "
                    f"SELECT {', '.join(select_exprs)} FROM pipeline_runs_old"
                ))
                moved = (await conn.execute(text("SELECT COUNT(*) FROM pipeline_runs_old"))).scalar()
                await conn.execute(text("DROP TABLE pipeline_runs_old"))
                logger.info("Migrated pipeline_runs.phase -> current_phase, preserved %d row(s)", moved)
            except Exception as e:
                logger.warning(
                    "pipeline_runs data migration failed — old data preserved in "
                    "pipeline_runs_old for manual recovery: %s", e
                )
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
        try:
            await conn.execute(text("ALTER TABLE campaigns ADD COLUMN role_prompt TEXT DEFAULT ''"))
        except OperationalError as e:
            if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                logger.warning("Migration warning: %s", e)
        try:
            await conn.execute(text("ALTER TABLE campaigns ADD COLUMN exit_report TEXT DEFAULT ''"))
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
        try:
            await conn.execute(text("ALTER TABLE runs ADD COLUMN campaign_id TEXT DEFAULT NULL"))
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
