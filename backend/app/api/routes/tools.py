from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.db.database import get_db
from app.models.tool import Tool
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class ToolParam(BaseModel):
    name: str
    flag: Optional[str] = ""
    placeholder: Optional[str] = ""
    required: bool = True
    description: Optional[str] = ""


class ToolCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    category: str
    binary: str
    default_flags: Optional[str] = ""
    parameters: list[ToolParam] = []
    workflow_tags: list[str] = []


class ToolUpdate(ToolCreate):
    enabled: Optional[bool] = True


@router.get("/")
async def list_tools(category: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    query = select(Tool)
    if category:
        query = query.where(Tool.category == category)
    result = await db.execute(query.order_by(Tool.category, Tool.name))
    tools = result.scalars().all()
    return [_tool_dict(t) for t in tools]


@router.get("/{tool_id}")
async def get_tool(tool_id: str, db: AsyncSession = Depends(get_db)):
    tool = await _get_or_404(tool_id, db)
    return _tool_dict(tool)


@router.post("/", status_code=201)
async def create_tool(body: ToolCreate, db: AsyncSession = Depends(get_db)):
    tool = Tool(
        name=body.name,
        description=body.description,
        category=body.category,
        binary=body.binary,
        default_flags=body.default_flags,
        parameters=[p.model_dump() for p in body.parameters],
        workflow_tags=body.workflow_tags,
        is_builtin=False,
    )
    db.add(tool)
    await db.commit()
    await db.refresh(tool)
    return _tool_dict(tool)


@router.put("/{tool_id}")
async def update_tool(tool_id: str, body: ToolUpdate, db: AsyncSession = Depends(get_db)):
    tool = await _get_or_404(tool_id, db)
    tool.name = body.name
    tool.description = body.description
    tool.category = body.category
    tool.binary = body.binary
    tool.default_flags = body.default_flags
    tool.parameters = [p.model_dump() for p in body.parameters]
    tool.workflow_tags = body.workflow_tags
    tool.enabled = body.enabled
    await db.commit()
    return _tool_dict(tool)


@router.delete("/{tool_id}", status_code=204)
async def delete_tool(tool_id: str, db: AsyncSession = Depends(get_db)):
    tool = await _get_or_404(tool_id, db)
    if tool.is_builtin:
        raise HTTPException(status_code=400, detail="Built-in tools cannot be deleted. Disable them instead.")
    await db.delete(tool)
    await db.commit()


async def _get_or_404(tool_id: str, db: AsyncSession) -> Tool:
    result = await db.execute(select(Tool).where(Tool.id == tool_id))
    tool = result.scalar_one_or_none()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    return tool


def _tool_dict(t: Tool) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "description": t.description,
        "category": t.category,
        "binary": t.binary,
        "default_flags": t.default_flags,
        "parameters": t.parameters,
        "workflow_tags": t.workflow_tags,
        "is_builtin": t.is_builtin,
        "enabled": t.enabled,
    }
