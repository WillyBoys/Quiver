"""Points the app at a throwaway temp-file SQLite DB before any app module is
imported, so tests never touch the real /data/pentest.db mounted in the container.
"""
import os
import tempfile

_tmp_db_fd, _tmp_db_path = tempfile.mkstemp(suffix=".db")
os.close(_tmp_db_fd)
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp_db_path}"

import pytest
import pytest_asyncio

from app.db.database import Base, engine
from app.models import tool, session, run, campaign, report, pipeline  # noqa: register models with Base


@pytest_asyncio.fixture(autouse=True)
async def _fresh_schema():
    """Give every test a clean set of tables — cheap enough at this test count
    and avoids state leaking between tests that share the same temp DB file."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


def pytest_sessionfinish(session, exitstatus):
    try:
        os.remove(_tmp_db_path)
    except OSError:
        pass
