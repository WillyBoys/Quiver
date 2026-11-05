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

    def tier_of(self, params: Mapping[str, Any]) -> RiskTier:
        if self.tier_for is None:
            return self.tier
        return max(self.tier, self.tier_for(params), key=TIER_ORDER.index)


RUN_COMMAND = ToolSpec("run_command", RiskTier.ARBITRARY)


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
