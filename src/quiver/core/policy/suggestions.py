"""Recording scope suggestions (Blueprint §4.1). Used by the policy gate (out-of-scope action
targets) and the knowledge graph (out-of-scope discoveries).

One suggestion per engagement and normalized value. A repeat sighting refreshes the counters
and lookups; it never reopens a suggestion the operator already decided.
"""

import uuid
from typing import Any

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from quiver.core.models import ScopeSuggestion, SuggestionStatus
from quiver.core.scope import NormalizedScope


async def upsert_suggestion(
    db: AsyncSession,
    engagement_id: uuid.UUID,
    suggestion: NormalizedScope,
    *,
    source: str,
    evidence: dict[str, Any],
    lookup: dict[str, Any] | None = None,
) -> None:
    """`evidence` describes the first sighting (kept); `lookup` holds passive lookup results
    (`resolved_addresses`, `hosting`), refreshed on every sighting that has them."""
    found = dict(lookup or {})
    stmt = insert(ScopeSuggestion).values(
        id=uuid.uuid4(),
        engagement_id=engagement_id,
        kind=suggestion.kind,
        value=suggestion.value,
        status=SuggestionStatus.PENDING,
        source=source,
        evidence=evidence,
        seen_count=1,
        decision_note="",
        **{"resolved_addresses": [], "hosting": {}, **found},
    )
    await db.execute(
        stmt.on_conflict_do_update(
            index_elements=["engagement_id", "kind", "value"],
            set_={
                "last_seen_at": func.now(),
                "seen_count": ScopeSuggestion.seen_count + 1,
                **found,
            },
        )
    )
