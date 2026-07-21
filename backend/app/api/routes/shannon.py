import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from typing import Optional
from app.integrations.shannon import shannon_client

logger = logging.getLogger(__name__)
router = APIRouter()


class ScanCreate(BaseModel):
    web_url: str
    workspace_name: Optional[str] = None
    config_yaml: Optional[str] = None
    claude_model: Optional[str] = None


async def _shannon_call(coro):
    try:
        return await coro
    except Exception as e:
        logger.warning("Shannon request failed: %s", e)
        raise HTTPException(status_code=502, detail=f"Shannon unavailable: {e}")


@router.get("/health")
async def shannon_health():
    return await shannon_client.health()


@router.get("/scans")
async def list_scans():
    return await _shannon_call(shannon_client.list_scans())


@router.post("/scans", status_code=201)
async def create_scan(body: ScanCreate):
    return await _shannon_call(
        shannon_client.create_scan(
            web_url=body.web_url,
            workspace_name=body.workspace_name,
            config_yaml=body.config_yaml,
            claude_model=body.claude_model,
        )
    )


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int):
    return await _shannon_call(shannon_client.get_scan(scan_id))


@router.get("/scans/{scan_id}/pipeline")
async def get_pipeline(scan_id: int):
    return await _shannon_call(shannon_client.get_pipeline_state(scan_id))


@router.get("/scans/{scan_id}/deliverables")
async def list_deliverables(scan_id: int):
    return await _shannon_call(shannon_client.list_deliverables(scan_id))


@router.get("/scans/{scan_id}/deliverables/{filename}", response_class=PlainTextResponse)
async def get_deliverable(scan_id: int, filename: str):
    return await _shannon_call(shannon_client.get_deliverable(scan_id, filename))


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: int):
    return await _shannon_call(shannon_client.cancel_scan(scan_id))
