"""Shared fixtures.

Database tests run against a real Postgres. Set QUIVER_TEST_DATABASE_URL to use an existing
server (CI does this); otherwise a throwaway container is started via testcontainers.
Settings are always passed explicitly; tests never mutate QUIVER_* environment variables.
"""

import asyncio
import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from quiver.core.config import Settings


@pytest.fixture(scope="session")
def database_url():
    url = os.environ.get("QUIVER_TEST_DATABASE_URL")
    if url:
        yield url
        return
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:16-alpine", driver="asyncpg") as pg:
        yield pg.get_connection_url()


@pytest.fixture(scope="session")
def migrated_db(database_url):
    """Apply migrations once per session, exercising downgrade along the way."""
    from alembic import command

    from quiver.core.migrate import alembic_config

    cfg = alembic_config(Settings(database_url=database_url))
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    return database_url


@pytest.fixture
def secret_key_file(tmp_path):
    path = tmp_path / "api_secret_key"
    path.write_text("test-secret-key-0123456789abcdef")
    return path


@pytest.fixture
def offline_settings(secret_key_file):
    """Settings for app tests that never reach the database (the engine connects lazily)."""
    return Settings(
        database_url="postgresql+asyncpg://unused:unused@127.0.0.1:1/unused",
        secret_key_file=secret_key_file,
    )


@pytest.fixture
def settings(migrated_db, secret_key_file):
    return Settings(database_url=migrated_db, secret_key_file=secret_key_file)


@pytest.fixture
def clean_db(migrated_db):
    yield

    async def _truncate():
        engine = create_async_engine(migrated_db)
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE auth_sessions, users, organizations CASCADE"))
        await engine.dispose()

    asyncio.run(_truncate())


@pytest.fixture
def run_db(migrated_db):
    """Run an async callable against the test database: run_db(async_fn_taking_session)."""

    def _run(fn):
        async def _inner():
            from quiver.core.db import make_sessionmaker

            engine = create_async_engine(migrated_db)
            try:
                async with make_sessionmaker(engine)() as session:
                    return await fn(session)
            finally:
                await engine.dispose()

        return asyncio.run(_inner())

    return _run
