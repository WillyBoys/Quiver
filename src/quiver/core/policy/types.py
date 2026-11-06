"""Policy gate vocabulary: requests, verdicts, and decisions (Blueprint §4)."""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from quiver.core.scope import NormalizedScope
from quiver.core.scope_match import ScopeDecision


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"  # definitely wrong; the operator cannot approve it
    NEEDS_APPROVAL = "needs_approval"  # in scope but risky or uncertain
    DEFER = "defer"  # allowed, but not now (window, paused engagement)


# Final verdict precedence: the most severe check wins. NEEDS_APPROVAL outranks DEFER so the
# approval can be collected while the action waits; it is gated again before it runs.
SEVERITY = {Verdict.ALLOW: 0, Verdict.DEFER: 1, Verdict.NEEDS_APPROVAL: 2, Verdict.DENY: 3}


class RiskTier(StrEnum):
    PASSIVE = "passive"  # third-party lookups only (DNS, certificate transparency, OSINT)
    DISCOVERY = "discovery"  # in-scope scans (port scan, HTTP probe, fingerprinting)
    INTRUSIVE = "intrusive"  # validation, attack payloads, credential attempts
    ARBITRARY = "arbitrary"  # run_command: free-form argv


TIER_ORDER = [RiskTier.PASSIVE, RiskTier.DISCOVERY, RiskTier.INTRUSIVE, RiskTier.ARBITRARY]


class Autonomy(StrEnum):
    AUTO = "auto"
    APPROVAL = "approval"
    OFF = "off"  # the tier is disabled for this engagement (DENY)


@dataclass(frozen=True)
class ActionRequest:
    """One action an agent or the playbook wants to run.

    params: the tool's structured parameters (target parameters are declared by the tool).
    argv: the final command line the runner would execute.
    requester: agent run ID or schedule, for the audit trail.
    """

    engagement_id: uuid.UUID
    tool: str
    params: Mapping[str, Any]
    argv: tuple[str, ...]
    requester: str


@dataclass(frozen=True)
class Check:
    name: str
    verdict: Verdict
    reason: str
    until: datetime | None = None  # DEFER only: when the condition clears (None = unknown)


@dataclass(frozen=True)
class TargetCheck:
    target: str
    source: str  # "param:<name>" or "argv"
    decision: ScopeDecision


@dataclass(frozen=True)
class GateDecision:
    verdict: Verdict
    reason: str
    checks: tuple[Check, ...]
    tier: RiskTier | None = None
    defer_until: datetime | None = None  # None with DEFER: until the operator changes something
    targets: tuple[TargetCheck, ...] = ()
    # Out-of-scope targets to record as scope suggestions, already normalized.
    suggest: tuple[NormalizedScope, ...] = ()
    # (hostname, addresses) the action may contact: the runner pins jobs to these.
    resolutions: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # Hostnames seen for the first time, whose addresses the store should pin.
    new_pins: tuple[tuple[str, tuple[str, ...]], ...] = ()
