from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.db.database import init_db
from app.api.routes import tools, sessions, wordlists, runs
from app.db.seed import seed_default_tools


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_default_tools()
    yield


app = FastAPI(
    title="Quiver API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
app.include_router(wordlists.router, prefix="/api/wordlists", tags=["wordlists"])
app.include_router(runs.router, prefix="/api/runs", tags=["runs"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}
