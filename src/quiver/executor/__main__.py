"""Executor entry point: `python -m quiver.executor`.

Configuration is two directories, from QUIVER_JOB_SPEC_DIR (read-only here) and
QUIVER_JOB_OUTPUT_DIR. The executor gets no secrets and no database settings.
"""

import logging
import os
import signal
import threading
from pathlib import Path

from quiver.executor.runner import Executor

log = logging.getLogger("quiver.executor")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    spec_dir = Path(os.environ.get("QUIVER_JOB_SPEC_DIR", "/data/job_specs"))
    output_dir = Path(os.environ.get("QUIVER_JOB_OUTPUT_DIR", "/data/job_output"))
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    executor = Executor(spec_dir, output_dir)
    log.info("executor started (specs: %s, output: %s)", spec_dir, output_dir)
    executor.serve(stop)
    log.info("executor stopping; cancelling running jobs")
    executor.shutdown(timeout=10)


if __name__ == "__main__":
    main()
