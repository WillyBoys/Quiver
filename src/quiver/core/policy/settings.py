"""Per-engagement tool settings (Blueprint §4, check 3a).

A tool declares, in code, which of its behaviours an operator may tune per engagement. Each
setting governs one job parameter:

- `default`  fills the parameter when a job leaves it out (e.g. which ports to probe);
- `ceiling`  bounds an integer parameter: a job asking for more needs approval;
- `allow`    gates a true/false feature: a job asking for it while the engagement turns it
             off needs approval;
- `choices`  lists which values of a choice parameter the engagement allows (e.g. nuclei
             template profiles): any other value needs approval.

Settings move only within the bounds the code allows, and safety invariants (name
resolution off, pinned addresses, no off-host redirects, no shell, no out-of-band callbacks,
keyless sources) are never settings. Missing parameters are filled at submission, so the
job's parameters and argv show exactly what runs; the gate re-checks every job against the
engagement's current settings, so tightening a setting makes queued jobs that exceed it ask.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class SettingMode(StrEnum):
    DEFAULT = "default"
    CEILING = "ceiling"
    ALLOW = "allow"
    CHOICES = "choices"


class SettingKind(StrEnum):
    INT = "int"
    BOOL = "bool"
    PORTS = "ports"  # a list of TCP ports, deduplicated in order
    CHOICES = "choices"  # a non-empty subset of the spec's choices


@dataclass(frozen=True)
class SettingSpec:
    param: str  # the job parameter this setting governs
    mode: SettingMode
    kind: SettingKind
    default: Any  # the setting's value when the engagement does not override it
    help: str
    minimum: int | None = None  # INT bounds (inclusive)
    maximum: int | None = None
    max_items: int = 20  # PORTS
    choices: tuple[str, ...] = ()  # CHOICES: the values the parameter can take
    # CEILING / ALLOW: the parameter's own default, used to fill a job that leaves it out
    # (capped by the ceiling, or switched off when the feature is not allowed).
    param_default: Any = None
    # Do not fill the parameter when the job gives any of these (e.g. explicit ports
    # instead of a top-N count).
    unless: tuple[str, ...] = ()

    def __post_init__(self):
        if self.mode is SettingMode.CEILING and self.kind is not SettingKind.INT:
            raise ValueError(f"{self.param}: a ceiling must be a whole number")
        if self.mode is SettingMode.ALLOW and self.kind is not SettingKind.BOOL:
            raise ValueError(f"{self.param}: an allow setting must be true or false")
        if (self.mode is SettingMode.CHOICES) != (self.kind is SettingKind.CHOICES):
            raise ValueError(f"{self.param}: a choices setting is a list of choices")
        if self.mode is SettingMode.CHOICES and self.param_default not in self.choices:
            raise ValueError(f"{self.param}: the parameter's default must be a choice")
        self.validate(self.default)  # the code's own default must be valid

    def validate(self, value: Any) -> Any:
        """The value in canonical form; ValueError if the code does not allow it."""
        if self.kind is SettingKind.BOOL:
            if not isinstance(value, bool):
                raise ValueError("must be true or false")
            return value
        if self.kind is SettingKind.INT:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("must be a whole number")
            if not self.minimum <= value <= self.maximum:
                raise ValueError(f"must be from {self.minimum} to {self.maximum}")
            return value
        if self.kind is SettingKind.CHOICES:
            if (
                not isinstance(value, list)
                or not value
                or not all(isinstance(v, str) and v in self.choices for v in value)
            ):
                raise ValueError(f"must be a non-empty list of: {', '.join(self.choices)}")
            return [c for c in self.choices if c in value]  # canonical order
        if not isinstance(value, list) or not 1 <= len(value) <= self.max_items:
            raise ValueError(f"must be a list of 1 to {self.max_items} ports")
        ports = []
        for port in value:
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("ports must be whole numbers from 1 to 65535")
            ports.append(port)
        return list(dict.fromkeys(ports))

    def describe(self) -> dict[str, Any]:
        """For the settings page: what the setting is and what values it takes."""
        out = {
            "param": self.param,
            "mode": self.mode.value,
            "kind": self.kind.value,
            "default": self.default,
            "help": self.help,
        }
        if self.kind is SettingKind.INT:
            out |= {"minimum": self.minimum, "maximum": self.maximum}
        if self.kind is SettingKind.PORTS:
            out["max_items"] = self.max_items
        if self.kind is SettingKind.CHOICES:
            out["choices"] = list(self.choices)
        return out


@dataclass(frozen=True)
class ToolSettings:
    """A tool's settings schema: name -> SettingSpec."""

    specs: Mapping[str, SettingSpec] = field(default_factory=dict)

    def validate(self, overrides: Mapping[str, Any]) -> dict[str, Any]:
        """Canonical overrides; ValueError naming the first bad one."""
        if not isinstance(overrides, Mapping):
            raise ValueError("settings must be an object")
        clean = {}
        for name, value in overrides.items():
            spec = self.specs.get(name)
            if spec is None:
                raise ValueError(f"unknown setting {name!r}; known: {sorted(self.specs)}")
            try:
                clean[name] = spec.validate(value)
            except ValueError as exc:
                raise ValueError(f"{name} {exc}") from exc
        return clean

    def effective(self, overrides: Mapping[str, Any] | None) -> dict[str, Any]:
        """Defaults merged with valid overrides; an invalid stored value falls back to the
        default (stored values are validated on write, so this only guards corruption)."""
        result = {name: spec.default for name, spec in self.specs.items()}
        if isinstance(overrides, Mapping):
            for name, value in overrides.items():
                spec = self.specs.get(name)
                if spec is None:
                    continue
                try:
                    result[name] = spec.validate(value)
                except ValueError:
                    continue
        return result

    def with_defaults(
        self, params: Mapping[str, Any], settings: Mapping[str, Any]
    ) -> dict[str, Any]:
        """The job's parameters with every parameter it left out filled from the settings."""
        filled = dict(params)
        for name, spec in self.specs.items():
            if spec.param in filled or any(other in filled for other in spec.unless):
                continue
            value = settings[name]
            if spec.mode is SettingMode.DEFAULT:
                filled[spec.param] = list(value) if isinstance(value, list) else value
            elif spec.mode is SettingMode.CEILING and spec.param_default is not None:
                filled[spec.param] = min(spec.param_default, value)
            elif spec.mode is SettingMode.ALLOW and spec.param_default is not None:
                filled[spec.param] = bool(spec.param_default and value)
            elif spec.mode is SettingMode.CHOICES:
                filled[spec.param] = spec.param_default if spec.param_default in value else value[0]
        return filled

    def problems(self, params: Mapping[str, Any], settings: Mapping[str, Any]) -> list[str]:
        """Why this job goes beyond the engagement's settings (empty when it does not)."""
        reasons = []
        for name, spec in self.specs.items():
            value = params.get(spec.param)
            limit = settings[name]
            if spec.mode is SettingMode.CEILING:
                if isinstance(value, int) and not isinstance(value, bool) and value > limit:
                    reasons.append(
                        f"{spec.param} {value} is above this engagement's limit ({limit})"
                    )
            elif spec.mode is SettingMode.ALLOW and value is True and limit is not True:
                reasons.append(f"{spec.param} is turned off for this engagement")
            elif spec.mode is SettingMode.CHOICES and isinstance(value, str) and value not in limit:
                reasons.append(
                    f"{spec.param} {value} is not allowed for this engagement "
                    f"(allowed: {', '.join(limit)})"
                )
        return reasons

    def describe(self) -> dict[str, dict[str, Any]]:
        return {name: spec.describe() for name, spec in self.specs.items()}


NO_SETTINGS = ToolSettings()
