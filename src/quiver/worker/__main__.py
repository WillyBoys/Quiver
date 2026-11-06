"""Worker entry point: runs the job scheduler until SIGTERM (Blueprint §6).

The worker gates jobs and hands allowed ones to the executor; it never starts a process.
"""

import asyncio
import logging
import signal

import quiver
from quiver.core.config import get_settings
from quiver.core.db import make_engine, make_sessionmaker
from quiver.worker.scheduler import Scheduler

log = logging.getLogger("quiver.worker")


async def _main() -> None:
    settings = get_settings()
    engine = make_engine(settings)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    log.info("worker %s started (specs: %s)", quiver.__version__, settings.job_spec_dir)
    try:
        await Scheduler(make_sessionmaker(engine), settings).run(stop)
    finally:
        await engine.dispose()
    log.info("worker stopped")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(_main())


if __name__ == "__main__":
    main()
