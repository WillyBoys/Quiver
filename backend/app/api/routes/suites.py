from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db
from app.models.suite import Suite
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter()


class SuiteStep(BaseModel):
    tool_id: str
    tool_name: str
    param_values: dict = {}
    extra_flags: str = ""


class SuiteCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    steps: list[SuiteStep] = []


class SuiteUpdate(SuiteCreate):
    pass


@router.get("/")
async def list_suites(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Suite).order_by(Suite.created_at.desc()))
    return [_suite_dict(s) for s in result.scalars().all()]


@router.get("/{suite_id}")
async def get_suite(suite_id: str, db: AsyncSession = Depends(get_db)):
    suite = await _get_or_404(suite_id, db)
    return _suite_dict(suite)


@router.post("/", status_code=201)
async def create_suite(body: SuiteCreate, db: AsyncSession = Depends(get_db)):
    suite = Suite(
        name=body.name,
        description=body.description or "",
        steps=[s.model_dump() for s in body.steps],
    )
    db.add(suite)
    await db.commit()
    await db.refresh(suite)
    return _suite_dict(suite)


@router.put("/{suite_id}")
async def update_suite(suite_id: str, body: SuiteUpdate, db: AsyncSession = Depends(get_db)):
    suite = await _get_or_404(suite_id, db)
    suite.name = body.name
    suite.description = body.description or ""
    suite.steps = [s.model_dump() for s in body.steps]
    await db.commit()
    return _suite_dict(suite)


@router.delete("/{suite_id}", status_code=204)
async def delete_suite(suite_id: str, db: AsyncSession = Depends(get_db)):
    suite = await _get_or_404(suite_id, db)
    await db.delete(suite)
    await db.commit()


async def _get_or_404(suite_id: str, db: AsyncSession) -> Suite:
    result = await db.execute(select(Suite).where(Suite.id == suite_id))
    suite = result.scalar_one_or_none()
    if not suite:
        raise HTTPException(status_code=404, detail="Suite not found")
    return suite


def _suite_dict(s: Suite) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "steps": s.steps or [],
        "created_at": s.created_at.isoformat(),
        "updated_at": s.updated_at.isoformat(),
    }
