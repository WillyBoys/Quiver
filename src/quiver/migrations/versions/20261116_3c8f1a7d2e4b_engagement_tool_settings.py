"""engagement tool settings

Revision ID: 3c8f1a7d2e4b
Revises: b90be32c3bbb
Create Date: 2026-11-16 10:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "3c8f1a7d2e4b"
down_revision: str | None = "b90be32c3bbb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "engagements",
        sa.Column(
            "tool_settings",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("engagements", "tool_settings")
