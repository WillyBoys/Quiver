"""Turning a finished job's output into graph records (Blueprint §6, parse stage).

The scheduler reads the output (without following symlinks: `handoff.read_output`), runs the
tool's parser (a pure function), and records the result here. Large results are recorded in
batches, within the caller's transaction, so one job's records still land together or not
at all.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from quiver.core.graph.record import FindingIn, Link, Observed, record
from quiver.core.graph.types import GraphRegistry, default_graph
from quiver.worker.tracks.external.parsers import Parsed

BATCH = 1000


@dataclass
class Recorded:
    entities_created: int = 0
    entities_updated: int = 0
    relationships: int = 0
    findings: int = 0
    suggestions: int = 0


async def record_parsed(
    db: AsyncSession,
    parsed: Parsed,
    *,
    engagement_id: uuid.UUID,
    source: str,
    job_id: uuid.UUID,
    run_id: uuid.UUID | None,
    now: datetime,
    registry: GraphRegistry | None = None,
) -> Recorded:
    """Record everything a parser returned. Entities go first; links and findings then refer
    to them by key, so each batch stands alone. Raises ValueError (from `record`) if any item
    is invalid; the caller rolls back."""
    registry = registry or default_graph()
    total = Recorded()

    async def write(entities=(), links=(), findings=()) -> None:
        result = await record(
            db,
            engagement_id,
            source=source,
            entities=entities,
            links=links,
            findings=findings,
            job_id=job_id,
            run_id=run_id,
            registry=registry,
            now=now,
        )
        total.entities_created += len(result.entities_created)
        total.entities_updated += len(result.entities_updated)
        total.relationships += result.relationships_created + result.relationships_updated
        total.findings += len(result.findings_created) + len(result.findings_updated)
        total.suggestions += result.suggestions

    def key(ref):
        if isinstance(ref, Observed):
            return registry.entity(ref.type).key(ref.attributes)
        return ref

    for chunk in _chunks(parsed.entities):
        await write(entities=chunk)
    links = [Link(link.type, key(link.source), key(link.target)) for link in parsed.links]
    for chunk in _chunks(links):
        await write(links=chunk)
    findings = [_with_key(f, key(f.entity)) for f in parsed.findings]
    for chunk in _chunks(findings):
        await write(findings=chunk)
    return total


def _with_key(finding: FindingIn, entity_key: str) -> FindingIn:
    return FindingIn(
        issue_type=finding.issue_type,
        entity=entity_key,
        title=finding.title,
        severity=finding.severity,
        location=finding.location,
        details=finding.details,
        evidence=finding.evidence,
    )


def _chunks(items):
    items = list(items)
    for i in range(0, len(items), BATCH):
        yield items[i : i + BATCH]
