"""What can be tuned per engagement, per tool (Blueprint §4 check 3a): the schema the
settings page renders. Values are set with PATCH /engagements/{id} `tool_settings`."""

from typing import Any

from fastapi import APIRouter, Depends

from quiver.api.auth import require_operator
from quiver.worker.registry import default_registry

router = APIRouter(
    prefix="/tool-settings", tags=["tool settings"], dependencies=[Depends(require_operator)]
)


@router.get("")
async def tool_settings_schema() -> dict[str, dict[str, dict[str, Any]]]:
    """Each configurable tool's settings: the parameter each governs, how (default, ceiling,
    allow), the values it takes, its default, and what it does."""
    return {
        name: spec.settings.describe()
        for name, spec in default_registry().items()
        if spec.settings.specs
    }
