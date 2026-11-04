"""Logging for e2e validations: one factory, consistent shape.

Every validation gets a logger with its own prefix (the validation's
name), UTC timestamps, and the same line shape as the reconciler's
own logging contract: "<ts> [<prefix>] <LEVEL> <message>". INFO+ to
stdout — the harness output pane reads stdout.
"""

from __future__ import annotations

import logging
import sys
import time


class _PrefixedFormatter(logging.Formatter):
    """'<ts> [<prefix>] <LEVEL> <message>' with the prefix taken from
    the logger name (e2e.cmk-live -> cmk-live)."""

    def format(self, record: logging.LogRecord) -> str:
        record.name_short = record.name.removeprefix("e2e.")
        return super().format(record)


def get_logger(name: str) -> logging.Logger:
    """A validation logger: '[<name>]'-prefixed, UTC-stamped, INFO+.

    Idempotent: re-requesting the same name returns the same logger
    without re-adding handlers (a validation re-imported, or a test
    importing the module twice, must not double-log).
    """
    logger = logging.getLogger(f"e2e.{name}")
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        _PrefixedFormatter(
            "%(asctime)s [%(name_short)s] %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    )
    # UTC timestamps (logging defaults to local time).
    logging.Formatter.converter = time.gmtime
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger
