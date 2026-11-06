"""What the gate knows about tools: risk tier and which parameters are targets.

Tracks register their tools in a `ToolRegistry` (step 10); the gate is given the registry,
so an unregistered tool is denied rather than guessed at. A tool's risk tier comes only from
its spec, never from the requester.
"""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from quiver.core.policy.types import TIER_ORDER, Autonomy, RiskTier


@dataclass(frozen=True)
class TargetParam:
    # The action reaches everything below a URL (crawlers, content discovery), not one request.
    url_subtree: bool = False


@dataclass(frozen=True)
class ToolSpec:
    name: str
    tier: RiskTier
    target_params: Mapping[str, TargetParam] = field(default_factory=dict)
    enabled: bool = True
    # Optional per-call classification (e.g. nuclei with exploit templates). It can only raise
    # the tier above `tier`, never lower it.
    tier_for: Callable[[Mapping[str, Any]], RiskTier] | None = None
    # Builds the final argv from structured parameters. The worker calls it; the gate then
    # checks the result like any argv. Raises ValueError for parameters it cannot use.
    build_argv: Callable[[Mapping[str, Any]], list[str]] | None = None

    def argv_for(self, params: Mapping[str, Any]) -> list[str]:
        if self.build_argv is None:
            raise ValueError(f"tool {self.name!r} cannot build a command line")
        argv = self.build_argv(params)
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(a, str) and "\0" not in a for a in argv)
            or not argv[0]
        ):
            raise ValueError(f"tool {self.name!r} did not build a usable command line")
        return list(argv)

    def tier_of(self, params: Mapping[str, Any]) -> RiskTier:
        if self.tier_for is None:
            return self.tier
        return max(self.tier, self.tier_for(params), key=TIER_ORDER.index)


def _run_command_argv(params: Mapping[str, Any]) -> list[str]:
    argv = params.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("run_command needs 'argv': a non-empty list of strings")
    return list(argv)


# The escape hatch: a free-form argv, always approval-gated, scope-checked from the argv alone.
RUN_COMMAND = ToolSpec("run_command", RiskTier.ARBITRARY, build_argv=_run_command_argv)


class ToolRegistry:
    def __init__(self, specs: Iterable[ToolSpec] = (RUN_COMMAND,)):
        self._specs: dict[str, ToolSpec] = {}
        for spec in specs:
            if spec.name in self._specs:
                raise ValueError(f"tool {spec.name!r} registered twice")
            self._specs[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._specs


# --- autonomy -------------------------------------------------------------------------------

DEFAULT_AUTONOMY: Mapping[RiskTier, Autonomy] = MappingProxyType(
    {
        RiskTier.PASSIVE: Autonomy.AUTO,
        RiskTier.DISCOVERY: Autonomy.AUTO,
        RiskTier.INTRUSIVE: Autonomy.APPROVAL,
        RiskTier.ARBITRARY: Autonomy.APPROVAL,
    }
)


def validate_autonomy(overrides: Mapping[str, str]) -> dict[str, str]:
    """Check an engagement's autonomy overrides; returns them with canonical values.

    Raises ValueError for unknown tiers or values, or for run_command (arbitrary) set to auto.
    """
    clean = {}
    for tier, value in overrides.items():
        tier, value = RiskTier(tier), Autonomy(value)
        if tier is RiskTier.ARBITRARY and value is Autonomy.AUTO:
            raise ValueError("arbitrary commands (run_command) always need approval")
        clean[tier.value] = value.value
    return clean


def effective_autonomy(overrides: Mapping[str, str] | None) -> dict[RiskTier, Autonomy]:
    """Defaults merged with an engagement's overrides. Invalid stored overrides (including
    arbitrary set to auto) are ignored, so the default applies."""
    result = dict(DEFAULT_AUTONOMY)
    for tier, value in (overrides or {}).items():
        try:
            tier, value = RiskTier(tier), Autonomy(value)
        except ValueError:
            continue
        if tier is RiskTier.ARBITRARY and value is Autonomy.AUTO:
            continue
        result[tier] = value
    return result


# --- job limits (gate check 6) ---------------------------------------------------------------

DEFAULT_LIMITS: Mapping[str, int] = MappingProxyType(
    {
        "max_concurrent_jobs": 3,  # running at once in the engagement
        "max_concurrent_per_target": 1,  # running at once against the same host or network
        "max_jobs_per_minute": 30,  # started in the engagement in any 60 seconds
    }
)
MAX_LIMIT = 1000


def validate_limits(overrides: Mapping[str, Any]) -> dict[str, int]:
    """Check an engagement's limit overrides. Raises ValueError for unknown names or values
    outside 1..1000."""
    clean = {}
    for name, value in overrides.items():
        if name not in DEFAULT_LIMITS:
            raise ValueError(f"unknown limit {name!r}; known: {sorted(DEFAULT_LIMITS)}")
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_LIMIT:
            raise ValueError(f"{name} must be a whole number from 1 to {MAX_LIMIT}")
        clean[name] = value
    return clean


def effective_limits(overrides: Mapping[str, Any] | None) -> dict[str, int]:
    """Defaults merged with valid overrides; invalid stored values fall back to the default."""
    result = dict(DEFAULT_LIMITS)
    for name, value in (overrides or {}).items():
        try:
            result.update(validate_limits({name: value}))
        except ValueError:
            continue
    return result
