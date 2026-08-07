"""Regression test for the pipeline_runs schema migration in init_db().

The old schema had a NOT NULL 'phase' column later renamed to 'current_phase'.
init_db() used to handle this by dropping pipeline_runs outright — silently
destroying any existing pipeline run history. It now rebuilds the table and
copies rows across instead; this test pins that behavior.
"""
import uuid

from sqlalchemy import text

from app.db.database import engine, init_db


async def test_pipeline_runs_migration_preserves_existing_rows():
    old_run_id = str(uuid.uuid4())
    campaign_id = str(uuid.uuid4())

    async with engine.begin() as conn:
        # Recreate the pre-migration schema on top of whatever conftest already set up.
        await conn.execute(text("DROP TABLE IF EXISTS pipeline_runs"))
        await conn.execute(text(
            "CREATE TABLE pipeline_runs ("
            "id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, phase INTEGER NOT NULL, "
            "status TEXT, created_at DATETIME, updated_at DATETIME)"
        ))
        await conn.execute(
            text(
                "INSERT INTO pipeline_runs (id, campaign_id, phase, status) "
                "VALUES (:id, :campaign_id, :phase, :status)"
            ),
            {"id": old_run_id, "campaign_id": campaign_id, "phase": 2, "status": "paused"},
        )

    await init_db()

    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT campaign_id, current_phase, status FROM pipeline_runs WHERE id = :id"),
            {"id": old_run_id},
        )
        row = result.fetchone()
        assert row is not None, "existing pipeline_runs row was lost during migration"
        assert row[0] == campaign_id
        assert row[1] == 2  # migrated from the old 'phase' column
        assert row[2] == "paused"

        leftover = await conn.execute(text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='pipeline_runs_old'"
        ))
        assert leftover.fetchone() is None, "pipeline_runs_old should be dropped after a successful migration"
