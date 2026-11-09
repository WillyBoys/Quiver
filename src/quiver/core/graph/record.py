"""Recording into the knowledge graph (Blueprint §5.3). Parsers (step 10 on) and agents
(step 15) call `record()`; nothing else writes entities.

- Identity comes only from `quiver.core.graph.keys` (through the type registry).
- Everything is validated before anything is written: one bad item rejects the whole call.
- Every sighting writes an `Observation` (who, which job and run, what was seen).
- Each entity's scope status is computed at record time; out-of-scope discoveries create a
  `ScopeSuggestion` (excluded ones don't). Scope status is information only: the gate decides
  what may be touched.
- Concurrent writers are safe: inserts use ON CONFLICT on the identity key.
"""

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from quiver.core.graph import keys
from quiver.core.graph.types import MAX_ATTRIBUTES, GraphRegistry, default_graph
from quiver.core.models import (
    Engagement,
    Entity,
    Event,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Observation,
    Relationship,
    Run,
    RunStatus,
    RunTrigger,
    ScopeEntry,
    ScopeStatus,
    Severity,
)
from quiver.core.policy.gate import suggestion_for
from quiver.core.policy.suggestions import upsert_suggestion
from quiver.core.scope_match import Scope, ScopeResult

MAX_EXCERPT = 8 * 1024  # bytes per evidence excerpt; longer excerpts are truncated
MAX_TITLE = 500
MAX_EVENT_KEYS = 50
_TRUNCATED = "\n[… truncated]"

_SCOPE_STATUS = {
    ScopeResult.IN_SCOPE: ScopeStatus.IN_SCOPE,
    ScopeResult.OUT_OF_SCOPE: ScopeStatus.OUT_OF_SCOPE,
    ScopeResult.EXCLUDED: ScopeStatus.EXCLUDED,
    ScopeResult.UNCERTAIN: ScopeStatus.UNCERTAIN,
}


# --- inputs ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Observed:
    """An entity as a parser or agent saw it."""

    type: str
    attributes: Mapping[str, Any]


# An entity reference: one observed in the same call, or the key of one already recorded.
EntityRef = Observed | str


@dataclass(frozen=True)
class Link:
    type: str
    source: EntityRef
    target: EntityRef


@dataclass(frozen=True)
class EvidenceIn:
    excerpt: str
    kind: EvidenceKind = EvidenceKind.OUTPUT_EXCERPT


@dataclass(frozen=True)
class FindingIn:
    issue_type: str
    entity: EntityRef
    title: str
    severity: Severity | str
    location: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)
    evidence: Sequence[EvidenceIn] = ()


@dataclass
class RecordResult:
    entities_created: list[str] = field(default_factory=list)  # keys
    entities_updated: list[str] = field(default_factory=list)
    relationships_created: int = 0
    relationships_updated: int = 0
    findings_created: list[str] = field(default_factory=list)
    findings_updated: list[str] = field(default_factory=list)
    suggestions: int = 0


# --- validated plan (nothing written yet) ---------------------------------------------------


@dataclass
class _Ent:
    key: str
    type: str
    attributes: dict
    scope_target: str | None


@dataclass
class _Plan:
    entities: dict[str, _Ent] = field(default_factory=dict)  # key -> observed in this call
    refs: set[str] = field(default_factory=set)  # keys referred to but not observed
    links: list[tuple[str, str, str]] = field(default_factory=list)  # (type, source, target)
    findings: list[dict] = field(default_factory=list)


def _plan(registry: GraphRegistry, entities, links, findings, errors: list[str]) -> _Plan:
    plan = _Plan()

    def observe(item: Observed, where: str) -> str | None:
        try:
            etype = registry.entity(item.type)
            attrs = etype.clean(item.attributes)
            key = etype.make_key(attrs)
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
            return None
        if key in plan.entities:  # the same entity twice in one call: merge what was seen
            ent = plan.entities[key]
            ent.attributes = etype.merge(ent.attributes, attrs)
        else:
            plan.entities[key] = _Ent(key, item.type, attrs, etype.scope_target(attrs))
        return key

    def ref(item: EntityRef, where: str) -> str | None:
        if isinstance(item, Observed):
            return observe(item, where)
        if not isinstance(item, str) or ":" not in item:
            errors.append(f"{where}: an entity reference must be an observed entity or a key")
            return None
        if item not in plan.entities:
            plan.refs.add(item)
        return item

    for i, item in enumerate(entities):
        if not isinstance(item, Observed):
            errors.append(f"entity {i}: not an observed entity")
            continue
        observe(item, f"entity {i} ({item.type})")

    for i, link in enumerate(links):
        where = f"link {i} ({link.type})"
        try:
            rel = registry.relation(link.type)
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
            continue
        src, dst = ref(link.source, f"{where} source"), ref(link.target, f"{where} target")
        if src is None or dst is None:
            continue
        for end, key, expected in (("source", src, rel.source), ("target", dst, rel.target)):
            if key.split(":", 1)[0] != expected:
                errors.append(f"{where}: {end} must be a {expected}, not {key.split(':', 1)[0]}")
        plan.links.append((link.type, src, dst))

    for i, f in enumerate(findings):
        where = f"finding {i} ({f.issue_type})"
        entity_key = ref(f.entity, f"{where} entity")
        try:
            if entity_key is None:
                continue
            key = keys.finding_key(f.issue_type, entity_key, f.location)
            title = " ".join(str(f.title).split())
            if not title or len(title) > MAX_TITLE:
                raise ValueError(f"title must be 1-{MAX_TITLE} characters")
            severity = Severity(f.severity)
            details = json.loads(json.dumps(dict(f.details), allow_nan=False))
            if len(json.dumps(details).encode()) > MAX_ATTRIBUTES:
                raise ValueError(f"details are larger than {MAX_ATTRIBUTES} bytes")
            evidence = [(EvidenceKind(e.kind), _cap(str(e.excerpt))) for e in f.evidence]
        except (ValueError, TypeError) as exc:
            errors.append(f"{where}: {exc}")
            continue
        plan.findings.append(
            {
                "key": key,
                "issue_type": keys.canonical_issue(f.issue_type),
                "entity_key": entity_key,
                "location": keys.canonical_location(f.location),
                "title": title,
                "severity": severity,
                "details": details,
                "evidence": evidence,
            }
        )
    return plan


def _cap(text: str) -> str:
    raw = text.encode()
    if len(raw) <= MAX_EXCERPT:
        return text
    return raw[: MAX_EXCERPT - len(_TRUNCATED.encode())].decode(errors="ignore") + _TRUNCATED


# --- recording ------------------------------------------------------------------------------


async def record(
    db: AsyncSession,
    engagement_id: uuid.UUID,
    *,
    source: str,
    entities: Sequence[Observed] = (),
    links: Sequence[Link] = (),
    findings: Sequence[FindingIn] = (),
    job_id: uuid.UUID | None = None,
    run_id: uuid.UUID | None = None,
    registry: GraphRegistry | None = None,
    now: datetime | None = None,
) -> RecordResult:
    """Record what a parser or agent saw. Raises ValueError (listing every problem) and writes
    nothing if any item is invalid. Flushes; the caller commits."""
    registry = registry or default_graph()
    now = now or datetime.now(UTC)
    source = " ".join(str(source).split())
    errors: list[str] = []
    if not source or len(source) > 200:
        errors.append("source must be 1-200 characters")
    plan = _plan(registry, entities, links, findings, errors)

    eng = await db.get(Engagement, engagement_id)
    if eng is None:
        errors.append(f"engagement {engagement_id} not found")
    existing = await _existing(db, engagement_id, plan.refs)
    missing = sorted(plan.refs - set(existing))
    if missing:
        errors.append(f"unknown entity keys: {', '.join(missing[:10])}")
    if errors:
        raise ValueError("nothing recorded: " + "; ".join(errors))

    scope = await _scope(db, engagement_id)
    result = RecordResult()
    seen = {"job_id": job_id, "run_id": run_id, "source": source, "observed_at": now}
    ids: dict[str, uuid.UUID] = dict(existing)
    statuses: dict[str, ScopeStatus] = {}

    for ent in plan.entities.values():
        status = _scope_status(scope, ent.scope_target)
        statuses[ent.key] = status
        merge = registry.entity(ent.type).merge
        entity_id, created = await _upsert_entity(
            db, engagement_id, ent, status, run_id, now, merge
        )
        ids[ent.key] = entity_id
        (result.entities_created if created else result.entities_updated).append(ent.key)
        db.add(
            Observation(
                engagement_id=engagement_id, entity_id=entity_id, attributes=ent.attributes, **seen
            )
        )
        if status is ScopeStatus.OUT_OF_SCOPE and ent.scope_target is not None:
            suggestion = suggestion_for(ent.scope_target)
            if suggestion is not None:
                await upsert_suggestion(
                    db,
                    engagement_id,
                    suggestion,
                    source=f"graph:{source}"[:50],
                    evidence={
                        "entity": ent.key,
                        "source": source,
                        "job_id": str(job_id) if job_id else None,
                    },
                )
                result.suggestions += 1

    for rel_type, src, dst in plan.links:
        rel_id, created = await _upsert_relationship(
            db, engagement_id, rel_type, ids[src], ids[dst], run_id, now
        )
        if created:
            result.relationships_created += 1
        else:
            result.relationships_updated += 1
        db.add(
            Observation(
                engagement_id=engagement_id,
                relationship_id=rel_id,
                attributes={"type": rel_type, "source": src, "target": dst},
                **seen,
            )
        )

    for f in plan.findings:
        entity_id = ids[f["entity_key"]]
        status = statuses.get(f["entity_key"]) or await _entity_status(db, entity_id)
        finding_id, created = await _upsert_finding(
            db, engagement_id, f, entity_id, status, run_id, now
        )
        (result.findings_created if created else result.findings_updated).append(f["key"])
        db.add(
            Observation(
                engagement_id=engagement_id,
                finding_id=finding_id,
                attributes={
                    "title": f["title"],
                    "severity": f["severity"],
                    "details": f["details"],
                },
                **seen,
            )
        )
        for kind, excerpt in f["evidence"]:
            db.add(
                Evidence(
                    finding_id=finding_id, job_id=job_id, kind=kind, excerpt=excerpt, source=source
                )
            )

    db.add(
        Event(
            org_id=eng.org_id,
            engagement_id=engagement_id,
            kind="graph.recorded",
            payload={
                "source": source,
                "job_id": str(job_id) if job_id else None,
                "run_id": str(run_id) if run_id else None,
                "entities_created": result.entities_created[:MAX_EVENT_KEYS],
                "entities_updated": len(result.entities_updated),
                "relationships_created": result.relationships_created,
                "findings_created": result.findings_created[:MAX_EVENT_KEYS],
                "findings_updated": len(result.findings_updated),
                "suggestions": result.suggestions,
            },
        )
    )
    await db.flush()
    return result


async def _existing(db, engagement_id, refs: set[str]) -> dict[str, uuid.UUID]:
    if not refs:
        return {}
    hashes = {keys.key_hash(k): k for k in refs}
    rows = await db.execute(
        select(Entity.key_hash, Entity.id).where(
            Entity.engagement_id == engagement_id, Entity.key_hash.in_(hashes)
        )
    )
    return {hashes[h]: entity_id for h, entity_id in rows}


async def _scope(db, engagement_id) -> Scope | None:
    entries = await db.scalars(
        select(ScopeEntry).where(
            ScopeEntry.engagement_id == engagement_id, ScopeEntry.removed_at.is_(None)
        )
    )
    try:
        return Scope.from_entries(entries)
    except ValueError:
        return None  # corrupted stored scope: every status is uncertain


def _scope_status(scope: Scope | None, target: str | None) -> ScopeStatus:
    if target is None:
        return ScopeStatus.NOT_APPLICABLE
    if scope is None:
        return ScopeStatus.UNCERTAIN
    return _SCOPE_STATUS[scope.check(target).result]


async def _entity_status(db, entity_id) -> ScopeStatus:
    return await db.scalar(select(Entity.scope_status).where(Entity.id == entity_id))


async def _upsert_entity(db, engagement_id, ent: _Ent, status, run_id, now, merge):
    stmt = (
        insert(Entity)
        .values(
            id=uuid.uuid4(),
            engagement_id=engagement_id,
            type=ent.type,
            key=ent.key,
            key_hash=keys.key_hash(ent.key),
            attributes=ent.attributes,
            scope_status=status,
            first_seen_at=now,
            last_seen_at=now,
            first_seen_run_id=run_id,
            last_seen_run_id=run_id,
        )
        .on_conflict_do_nothing(index_elements=["engagement_id", "key_hash"])
        .returning(Entity.id)
    )
    new_id = await db.scalar(stmt)
    if new_id is not None:
        return new_id, True
    row = await db.scalar(
        select(Entity)
        .where(Entity.engagement_id == engagement_id, Entity.key_hash == keys.key_hash(ent.key))
        .with_for_update()
    )
    row.attributes = merge(row.attributes, ent.attributes)
    row.scope_status = status
    row.last_seen_at = now
    row.last_seen_run_id = run_id or row.last_seen_run_id
    return row.id, False


async def _upsert_relationship(db, engagement_id, rel_type, src_id, dst_id, run_id, now):
    stmt = (
        insert(Relationship)
        .values(
            id=uuid.uuid4(),
            engagement_id=engagement_id,
            type=rel_type,
            source_id=src_id,
            target_id=dst_id,
            first_seen_at=now,
            last_seen_at=now,
            first_seen_run_id=run_id,
            last_seen_run_id=run_id,
        )
        .on_conflict_do_nothing(index_elements=["source_id", "target_id", "type"])
        .returning(Relationship.id)
    )
    new_id = await db.scalar(stmt)
    if new_id is not None:
        return new_id, True
    row = await db.scalar(
        select(Relationship)
        .where(
            Relationship.source_id == src_id,
            Relationship.target_id == dst_id,
            Relationship.type == rel_type,
        )
        .with_for_update()
    )
    row.last_seen_at = now
    row.last_seen_run_id = run_id or row.last_seen_run_id
    return row.id, False


async def _upsert_finding(db, engagement_id, f: dict, entity_id, status, run_id, now):
    stmt = (
        insert(Finding)
        .values(
            id=uuid.uuid4(),
            engagement_id=engagement_id,
            key=f["key"],
            key_hash=keys.key_hash(f["key"]),
            issue_type=f["issue_type"],
            entity_id=entity_id,
            location=f["location"],
            title=f["title"],
            severity=f["severity"],
            status=FindingStatus.CANDIDATE,
            details=f["details"],
            scope_status=status,
            first_seen_at=now,
            last_seen_at=now,
            first_seen_run_id=run_id,
            last_seen_run_id=run_id,
        )
        .on_conflict_do_nothing(index_elements=["engagement_id", "key_hash"])
        .returning(Finding.id)
    )
    new_id = await db.scalar(stmt)
    if new_id is not None:
        return new_id, True
    row = await db.scalar(
        select(Finding)
        .where(Finding.engagement_id == engagement_id, Finding.key_hash == keys.key_hash(f["key"]))
        .with_for_update()
    )
    # A new sighting refreshes what was reported; its lifecycle status is not touched.
    row.title = f["title"]
    row.severity = f["severity"]
    row.details = {**row.details, **f["details"]}
    row.scope_status = status
    row.last_seen_at = now
    row.last_seen_run_id = run_id or row.last_seen_run_id
    return row.id, False


# --- runs -----------------------------------------------------------------------------------


async def start_run(
    db: AsyncSession, engagement_id: uuid.UUID, trigger: RunTrigger = RunTrigger.ON_DEMAND
) -> Run:
    run = Run(engagement_id=engagement_id, trigger=trigger, status=RunStatus.RUNNING)
    db.add(run)
    await db.flush()
    return run


async def finish_run(
    db: AsyncSession, run: Run, status: RunStatus = RunStatus.COMPLETED, summary: dict | None = None
) -> Run:
    if status is RunStatus.RUNNING:
        raise ValueError("a finished run needs a final status")
    run.status = status
    run.finished_at = datetime.now(UTC)
    run.summary = summary or {}
    await db.flush()
    return run
