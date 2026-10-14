"""FastAPI application factory."""

from fastapi import FastAPI

import quiver


def create_app() -> FastAPI:
    app = FastAPI(title="Quiver", version=quiver.__version__)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        """Liveness check. Unauthenticated; returns no engagement data."""
        return {"status": "ok", "version": quiver.__version__}

    return app
