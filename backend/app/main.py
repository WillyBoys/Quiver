import logging
import sys
import time
from logging.handlers import RotatingFileHandler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.db.database import init_db
from app.api.routes import tools, sessions, wordlists, runs, suites
from app.db.seed import seed_default_tools


def _setup_logging() -> None:
    fmt = logging.Formatter(
        fmt="%(asctime)s UTC | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fmt.converter = time.gmtime  # force UTC regardless of server timezone

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        fh = RotatingFileHandler(
            "/data/quiver.log",
            maxBytes=10 * 1024 * 1024,  # 10 MB per file
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        logging.getLogger(__name__).warning("Could not open /data/quiver.log — file logging disabled")


_setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Quiver API starting up")
    await init_db()
    await seed_default_tools()
    logger.info("Quiver API ready")
    yield
    logger.info("Quiver API shutting down")


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
app.include_router(suites.router, prefix="/api/suites", tags=["suites"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}
