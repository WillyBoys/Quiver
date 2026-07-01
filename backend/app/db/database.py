from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:////data/pentest.db")
# Convert sqlite:// to sqlite+aiosqlite://
if DATABASE_URL.startswith("sqlite:///"):
    DATABASE_URL = DATABASE_URL.replace("sqlite:///", "sqlite+aiosqlite:///", 1)

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db():
    from app.models import tool, session, run  # noqa: import all models
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Migrate: add checklist_state to existing sessions tables that pre-date this column
        try:
            await conn.execute(text("ALTER TABLE sessions ADD COLUMN checklist_state JSON DEFAULT '{}'"))
        except Exception:
            pass  # column already exists


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
