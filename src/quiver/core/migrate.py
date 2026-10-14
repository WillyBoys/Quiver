"""Run Alembic migrations programmatically (no alembic.ini needed in containers)."""

from alembic import command
from alembic.config import Config

from quiver.core.config import Settings


def alembic_config(settings: Settings | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", "quiver:migrations")
    if settings is not None:
        cfg.attributes["settings"] = settings
    return cfg


def upgrade_to_head(settings: Settings | None = None) -> None:
    command.upgrade(alembic_config(settings), "head")
