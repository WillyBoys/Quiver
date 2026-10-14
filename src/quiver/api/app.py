"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import quiver
from quiver.api import auth
from quiver.core.config import Settings, get_settings
from quiver.core.db import make_engine, make_sessionmaker


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    # Fail at startup, not on first request, if the secret key is missing.
    settings.secret_key()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = make_engine(settings)
        app.state.sessionmaker = make_sessionmaker(engine)
        yield
        await engine.dispose()

    docs = settings.api_docs
    app = FastAPI(
        title="Quiver",
        version=quiver.__version__,
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        """Liveness check. Unauthenticated; returns no engagement data."""
        return {"status": "ok", "version": quiver.__version__}

    app.include_router(auth.public_router)
    app.include_router(auth.router)
    return app
