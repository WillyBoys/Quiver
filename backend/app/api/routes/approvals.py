import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from app.db.database import get_db
from app.models.campaign import ApprovalRequest, Campaign
from app.agent.engine import execute_approval

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/")
async def list_approvals(status: str = "pending", db: AsyncSession = Depends(get_db)):
    stmt = (
        select(ApprovalRequest, Campaign.name.label("campaign_name"))
        .outerjoin(Campaign, ApprovalRequest.campaign_id == Campaign.id)
        .where(ApprovalRequest.status == status)
        .order_by(ApprovalRequest.created_at.desc())
    )
    rows = (await db.execute(stmt)).all()
    return [{**_dict(a), "campaign_name": name or "Unknown"} for a, name in rows]


@router.get("/pending-count")
async def pending_count(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ApprovalRequest).where(ApprovalRequest.status == "pending")
    )
    return {"count": len(result.scalars().all())}


@router.post("/{approval_id}/approve")
async def approve(approval_id: str, db: AsyncSession = Depends(get_db)):
    approval = await _get_or_404(approval_id, db)
    if approval.status != "pending":
        raise HTTPException(status_code=400, detail=f"Request is already {approval.status}")
    success = await execute_approval(approval_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to execute approved action")
    logger.info("APPROVAL APPROVE | id=%s", approval_id)
    return {"message": "Approved and executing"}


@router.post("/{approval_id}/reject")
async def reject(approval_id: str, db: AsyncSession = Depends(get_db)):
    approval = await _get_or_404(approval_id, db)
    if approval.status != "pending":
        raise HTTPException(status_code=400, detail=f"Request is already {approval.status}")
    approval.status = "rejected"
    approval.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info("APPROVAL REJECT | id=%s", approval_id)
    return {"message": "Rejected"}


async def _get_or_404(approval_id: str, db: AsyncSession) -> ApprovalRequest:
    result = await db.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
    a = result.scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return a


def _dict(a: ApprovalRequest) -> dict:
    return {
        "id": a.id,
        "campaign_id": a.campaign_id,
        "tool_name": a.tool_name,
        "command": a.command,
        "reasoning": a.reasoning,
        "target": a.target,
        "status": a.status,
        "created_at": a.created_at.isoformat(),
        "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
    }
