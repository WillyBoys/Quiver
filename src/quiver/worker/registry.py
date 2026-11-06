"""The tools Quiver knows. Pure metadata (tier, target parameters, argv builder), so the API
can validate and build a job's argv without importing anything that runs processes.

Tracks add their tools here from step 10 on; until then only `run_command` exists.
"""

from functools import cache

from quiver.core.policy import RUN_COMMAND, ToolRegistry


@cache
def default_registry() -> ToolRegistry:
    return ToolRegistry([RUN_COMMAND])
