import logging
import httpx
from app.config import SHANNON_URL, SHANNON_ADMIN_EMAIL, SHANNON_ADMIN_PASSWORD, CLAUDE_MODEL

logger = logging.getLogger(__name__)

# Models Shannon supports — anything else falls back to Shannon's internal default
SHANNON_MODELS = {
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-opus-4-7",
    "claude-opus-4-8",
}


class ShannonClient:
    def __init__(self):
        self._jwt: str | None = None
        self._base = SHANNON_URL

    def _available(self) -> bool:
        return bool(SHANNON_URL)

    async def _authenticate(self) -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self._base}/api/auth/login",
                json={"email": SHANNON_ADMIN_EMAIL, "password": SHANNON_ADMIN_PASSWORD},
            )
            resp.raise_for_status()
            self._jwt = resp.json()["token"]

    async def _headers(self) -> dict:
        if not self._jwt:
            await self._authenticate()
        return {"Authorization": f"Bearer {self._jwt}"}

    async def _get(self, path: str) -> object:
        headers = await self._headers()
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"{self._base}{path}", headers=headers)
            if resp.status_code == 401:
                self._jwt = None
                headers = await self._headers()
                resp = await client.get(f"{self._base}{path}", headers=headers)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "application/json" in content_type:
                return resp.json()
            return resp.text

    async def _post(self, path: str, body: dict) -> object:
        headers = await self._headers()
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{self._base}{path}", headers=headers, json=body)
            if resp.status_code == 401:
                self._jwt = None
                headers = await self._headers()
                resp = await client.post(f"{self._base}{path}", headers=headers, json=body)
            resp.raise_for_status()
            if resp.status_code == 204:
                return {}
            content_type = resp.headers.get("content-type", "")
            if "application/json" in content_type:
                return resp.json()
            return {"ok": True}

    # ── Public API ─────────────────────────────────────────────────────────────

    async def health(self) -> dict:
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.get(f"{self._base}/api/system/status")
                return {"online": resp.status_code == 200, "detail": resp.json()}
            except Exception as e:
                return {"online": False, "detail": str(e)}

    async def list_scans(self) -> list:
        result = await self._get("/api/scans")
        return result if isinstance(result, list) else []

    async def create_scan(
        self,
        web_url: str,
        workspace_name: str | None = None,
        config_yaml: str | None = None,
        claude_model: str | None = None,
    ) -> dict:
        body: dict = {"webUrl": web_url}
        if workspace_name:
            body["workspaceName"] = workspace_name
        if config_yaml:
            body["configYaml"] = config_yaml
        # Map Quiver's configured model to one Shannon accepts; fall back to Shannon default
        model = claude_model or CLAUDE_MODEL
        if model in SHANNON_MODELS:
            body["claudeModel"] = model
        result = await self._post("/api/scans", body)
        return result if isinstance(result, dict) else {}

    async def get_scan(self, scan_id: int) -> dict:
        result = await self._get(f"/api/scans/{scan_id}")
        return result if isinstance(result, dict) else {}

    async def get_pipeline_state(self, scan_id: int) -> object:
        return await self._get(f"/api/scans/{scan_id}/pipeline/state")

    async def list_deliverables(self, scan_id: int) -> list:
        result = await self._get(f"/api/scans/{scan_id}/deliverables")
        return result if isinstance(result, list) else []

    async def get_deliverable(self, scan_id: int, filename: str) -> str:
        result = await self._get(f"/api/scans/{scan_id}/deliverables/{filename}")
        return result if isinstance(result, str) else str(result)

    async def cancel_scan(self, scan_id: int) -> dict:
        result = await self._post(f"/api/scans/{scan_id}/cancel", {})
        return result if isinstance(result, dict) else {}


shannon_client = ShannonClient()
