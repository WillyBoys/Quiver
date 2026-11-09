"""Knowledge graph, read-only: entities, findings, and runs (Blueprint §5.3, §10).

Nothing is written over HTTP: parsers and agents record through `quiver.core.graph.record`
in the worker. Attributes, details, and evidence come from tool output and are target-
controlled; responses label them so the dashboard shows them as untrusted data.
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import aliased

from quiver.api.auth import DbDep, OperatorDep, require_operator
from quiver.api.engagements import OrmOut, get_engagement_or_404
from quiver.core.models import (
    Entity,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Observation,
    Relationship,
    Run,
    RunStatus,
    RunTrigger,
    ScopeStatus,
    Severity,
)

router = APIRouter(
    prefix="/engagements/{engagement_id}",
    tags=["graph"],
    dependencies=[Depends(require_operator)],
)

Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0)]
UNTRUSTED = "reported by tools or agents; target-controlled data"


class EntityOut(OrmOut):
    id: uuid.UUID
    type: str
    key: str
    attributes: dict
    attributes_trust: str = UNTRUSTED
    scope_status: ScopeStatus
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    first_seen_run_id: uuid.UUID | None
    last_seen_run_id: uuid.UUID | None


class EntityPage(BaseModel):
    total: int
    items: list[EntityOut]


class RelationOut(BaseModel):
    id: uuid.UUID
    type: str
    direction: str  # "out" (this entity is the source) or "in"
    other_id: uuid.UUID
    other_key: str
    last_seen_at: datetime


class ObservationOut(OrmOut):
    id: uuid.UUID
    source: str
    job_id: uuid.UUID | None
    run_id: uuid.UUID | None
    observed_at: datetime
    attributes: dict


class EntityDetail(EntityOut):
    relationships: list[RelationOut]
    observations: list[ObservationOut]


class FindingOut(OrmOut):
    id: uuid.UUID
    key: str
    issue_type: str
    entity_id: uuid.UUID
    location: str
    title: str
    severity: Severity
    status: FindingStatus
    scope_status: ScopeStatus
    details: dict
    details_trust: str = UNTRUSTED
    first_seen_at: datetime
    last_seen_at: datetime


class EvidenceOut(OrmOut):
    id: uuid.UUID
    job_id: uuid.UUID | None
    kind: EvidenceKind
    excerpt: str
    source: str
    created_at: datetime


class FindingDetail(FindingOut):
    entity_key: str
    evidence: list[EvidenceOut]
    evidence_trust: str = UNTRUSTED


class RunOut(OrmOut):
    id: uuid.UUID
    trigger: RunTrigger
    status: RunStatus
    started_at: datetime
    finished_at: datetime | None
    summary: dict


@router.get("/entities", response_model=EntityPage)
async def list_entities(
    engagement_id: uuid.UUID,
    db: DbDep,
    user: OperatorDep,
    type: Annotated[str | None, Query(max_length=50)] = None,
    scope_status: ScopeStatus | None = None,
    q: Annotated[str | None, Query(max_length=200, description="substring of the key")] = None,
    limit: Limit = 100,
    offset: Offset = 0,
):
    eng = await get_engagement_or_404(db, user, engagement_id)
    where = [Entity.engagement_id == eng.id]
    if type:
        where.append(Entity.type == type)
    if scope_status:
        where.append(Entity.scope_status == scope_status)
    if q:
        where.append(Entity.key.icontains(q, autoescape=True))
    total = await db.scalar(select(func.count(Entity.id)).where(*where))
    rows = await db.scalars(
        select(Entity).where(*where).order_by(Entity.type, Entity.key).limit(limit).offset(offset)
    )
    return EntityPage(total=total or 0, items=list(rows))


@router.get("/entities/{entity_id}", response_model=EntityDetail)
async def get_entity(engagement_id: uuid.UUID, entity_id: uuid.UUID, db: DbDep, user: OperatorDep):
    eng = await get_engagement_or_404(db, user, engagement_id)
    entity = await db.scalar(
        select(Entity).where(Entity.id == entity_id, Entity.engagement_id == eng.id)
    )
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")
    other = aliased(Entity)
    rels = await db.execute(
        select(Relationship, other.key)
        .join(
            other,
            other.id
            == func.coalesce(
                func.nullif(Relationship.target_id, entity.id),
                Relationship.source_id,
            ),
        )
        .where(or_(Relationship.source_id == entity.id, Relationship.target_id == entity.id))
        .order_by(Relationship.type, other.key)
    )
    relationships = [
        RelationOut(
            id=rel.id,
            type=rel.type,
            direction="out" if rel.source_id == entity.id else "in",
            other_id=rel.target_id if rel.source_id == entity.id else rel.source_id,
            other_key=other_key,
            last_seen_at=rel.last_seen_at,
        )
        for rel, other_key in rels
    ]
    observations = await db.scalars(
        select(Observation)
        .where(Observation.entity_id == entity.id)
        .order_by(Observation.observed_at.desc(), Observation.id)
        .limit(20)
    )
    return EntityDetail(
        **EntityOut.model_validate(entity).model_dump(),
        relationships=relationships,
        observations=[ObservationOut.model_validate(o) for o in observations],
    )


@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    engagement_id: uuid.UUID,
    db: DbDep,
    user: OperatorDep,
    status_filter: Annotated[FindingStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
):
    eng = await get_engagement_or_404(db, user, engagement_id)
    stmt = select(Finding).where(Finding.engagement_id == eng.id)
    if status_filter:
        stmt = stmt.where(Finding.status == status_filter)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = await db.scalars(
        stmt.order_by(Finding.last_seen_at.desc(), Finding.id).limit(limit).offset(offset)
    )
    return list(rows)


@router.get("/findings/{finding_id}", response_model=FindingDetail)
async def get_finding(
    engagement_id: uuid.UUID, finding_id: uuid.UUID, db: DbDep, user: OperatorDep
):
    eng = await get_engagement_or_404(db, user, engagement_id)
    row = await db.execute(
        select(Finding, Entity.key)
        .join(Entity, Entity.id == Finding.entity_id)
        .where(Finding.id == finding_id, Finding.engagement_id == eng.id)
    )
    found = row.first()
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    finding, entity_key = found
    evidence = await db.scalars(
        select(Evidence)
        .where(Evidence.finding_id == finding.id)
        .order_by(Evidence.created_at, Evidence.id)
    )
    return FindingDetail(
        **FindingOut.model_validate(finding).model_dump(),
        entity_key=entity_key,
        evidence=[EvidenceOut.model_validate(e) for e in evidence],
    )


@router.get("/runs", response_model=list[RunOut])
async def list_runs(engagement_id: uuid.UUID, db: DbDep, user: OperatorDep, limit: Limit = 50):
    eng = await get_engagement_or_404(db, user, engagement_id)
    rows = await db.scalars(
        select(Run).where(Run.engagement_id == eng.id).order_by(Run.started_at.desc()).limit(limit)
    )
    return list(rows)
