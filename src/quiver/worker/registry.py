"""The tools Quiver knows, and the parsers for their output. Pure metadata (tier, target
parameters, argv builder) and pure functions, so the API can validate and build a job's argv
without importing anything that runs processes."""

from collections.abc import Mapping
from functools import cache

from quiver.core.policy import RUN_COMMAND, ToolRegistry
from quiver.worker.tracks import external
from quiver.worker.tracks.external.parsers import Parser


@cache
def default_registry() -> ToolRegistry:
    return ToolRegistry([RUN_COMMAND, *external.TOOLS])


def default_parsers() -> Mapping[str, Parser]:
    """Tool name -> parser. Tools without one (run_command) are never parsed."""
    return external.PARSERS
