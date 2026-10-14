"""Worker entry point.

Placeholder until the job runner lands (Blueprint §6, build step 8): it starts, logs, and
waits for a stop signal so the Compose stack has its final shape.
"""

import logging
import signal
import threading

import quiver

log = logging.getLogger("quiver.worker")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    log.info("worker %s started (placeholder: no jobs are executed yet)", quiver.__version__)
    stop.wait()
    log.info("worker stopping")


if __name__ == "__main__":
    main()
