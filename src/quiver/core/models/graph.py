"""Knowledge graph and runs (Blueprint §5.2, §5.3, §5.4).

Entities and relationships are stored generically: the type registry (`quiver.core.graph.types`)
validates attributes and derives identity keys, so tracks add types without migrations.
Attributes are reported by tools and agents and are therefore target-controlled data.
"""

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from quiver.core.models.base import Base, IdMixin
from quiver.core.models.engagement import _enum


class RunTrigger(StrEnum):
    ON_DEMAND = "on_demand"
    SCHEDULED = "scheduled"
    TRIGGERED = "triggered"  # by a change (new host, new service, ...)


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScopeStatus(StrEnum):
    """An entity's scope at its latest sighting. Informational: the gate decides actions."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    EXCLUDED = "excluded"
    UNCERTAIN = "uncertain"
    NOT_APPLICABLE = "not_applicable"  # e.g. certificates, which are not targets


class EntityStatus(StrEnum):
    ACTIVE = "active"  # reconciliation (step 13) adds more


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """The full lifecycle (Blueprint §5.4). Until step 24 only candidates are created."""

    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    REGRESSED = "regressed"
    ACCEPTED_RISK = "accepted_risk"
    STALE = "stale"


class EvidenceKind(StrEnum):
    OUTPUT_EXCERPT = "output_excerpt"
    OBSERVATION = "observation"
    NOTE = "note"


class _Seen:
    """First and last sighting, by time and by run."""

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    first_seen_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"))
    last_seen_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"))


class Run(IdMixin, Base):
    """One execution of an engagement. Minimal until the playbook (step 13) fills it in."""

    __tablename__ = "runs"

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), index=True)
    trigger: Mapped[RunTrigger] = mapped_column(_enum(RunTrigger, "run_trigger"))
    status: Mapped[RunStatus] = mapped_column(
        _enum(RunStatus, "run_status"), default=RunStatus.RUNNING
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    summary: Mapped[dict] = mapped_column(JSONB, default=dict)


class Entity(_Seen, IdMixin, Base):
    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint("engagement_id", "key_hash", name="uq_entities_engagement_id"),
        Index("ix_entities_engagement_id_type", "engagement_id", "type"),
    )

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"))
    type: Mapped[str] = mapped_column(String(50))
    key: Mapped[str] = mapped_column(Text)
    key_hash: Mapped[str] = mapped_column(String(64))
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict)
    scope_status: Mapped[ScopeStatus] = mapped_column(_enum(ScopeStatus, "scope_status"))
    status: Mapped[EntityStatus] = mapped_column(
        _enum(EntityStatus, "entity_status"), default=EntityStatus.ACTIVE
    )


class Relationship(_Seen, IdMixin, Base):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "type", name="uq_relationships_source_id"),
    )

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), index=True)
    type: Mapped[str] = mapped_column(String(50))
    source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("entities.id"))
    target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("entities.id"), index=True)


class Finding(_Seen, IdMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("engagement_id", "key_hash", name="uq_findings_engagement_id"),
    )

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), index=True)
    key: Mapped[str] = mapped_column(Text)
    key_hash: Mapped[str] = mapped_column(String(64))
    issue_type: Mapped[str] = mapped_column(String(200))
    entity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("entities.id"), index=True)
    location: Mapped[str] = mapped_column(Text, default="")
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "finding_severity"))
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"), default=FindingStatus.CANDIDATE
    )
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    scope_status: Mapped[ScopeStatus] = mapped_column(_enum(ScopeStatus, "finding_scope_status"))


class Observation(IdMixin, Base):
    """One sighting of an entity, relationship, or finding: who reported it, from which job and
    run, and what it said. Reconciliation (step 13) reads these."""

    __tablename__ = "observations"
    __table_args__ = (
        CheckConstraint(
            "num_nonnulls(entity_id, relationship_id, finding_id) = 1",
            name="exactly_one_subject",
        ),
    )

    engagement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("engagements.id"), index=True)
    entity_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("entities.id"), index=True)
    relationship_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("relationships.id"))
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id"), index=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("jobs.id"), index=True)
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), index=True)
    source: Mapped[str] = mapped_column(String(200))  # e.g. "parser:nmap", "agent:<run id>"
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict)


class Evidence(IdMixin, Base):
    """What supports a finding. Excerpts are tool output: untrusted, target-controlled data."""

    __tablename__ = "evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), index=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("jobs.id"))
    kind: Mapped[EvidenceKind] = mapped_column(_enum(EvidenceKind, "evidence_kind"))
    excerpt: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
