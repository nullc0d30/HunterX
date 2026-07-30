# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import json
import logging
import random
import string
import signal
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.logging import RichHandler

console = Console()
_shutting_down = False


def setup_logger(level="INFO", json_logs: bool = False):
    if json_logs:
        handler = JsonLogHandler()
    else:
        handler = RichHandler(rich_tracebacks=True, console=console)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[handler],
    )
    return logging.getLogger("hunterx")


logger = setup_logger()


class JsonLogHandler(logging.Handler):
    """Structured JSON log handler for ELK/Loki compatibility."""

    def emit(self, record):
        try:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            if hasattr(record, "extra"):
                entry["extra"] = record.extra
            sys.stdout.write(json.dumps(entry) + "\n")
            sys.stdout.flush()
        except Exception:
            pass


def setup_graceful_shutdown(engine=None):
    """Register signal handlers for graceful shutdown."""

    def _handler(signum, frame):
        global _shutting_down
        if _shutting_down:
            logger.warning("Force exit.")
            sys.exit(1)
        _shutting_down = True
        logger.warning(f"Received signal {signum}. Shutting down gracefully...")
        if engine and hasattr(engine, "stop"):
            engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def is_shutting_down() -> bool:
    return _shutting_down


def random_string(length=8):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))
