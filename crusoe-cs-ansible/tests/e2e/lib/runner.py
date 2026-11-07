"""Subprocess execution with the live-found robustness rules.

API-blip tolerance: a cluster's API server can drop calls during
reboot windows (found live: kubectl died with a DNS i/o timeout
mid-wait) — every cluster call is retried, never trusted on the
first failure. Retries are bounded (the no-sleep rule: one loop
with a cap, never a bare sleep chain).
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")


class CommandError(RuntimeError):
    """A command failed after its retries were exhausted."""


def retry_transient(
    fn: Callable[[], T],
    *,
    attempts: int = 3,
    delay: float = 2.0,
    no_retry: Callable[[Exception], bool] | None = None,
) -> T:
    """Call fn, retrying transient failures — run()'s exception-based
    twin (the API-blip contract: 3 attempts, 2s apart).

    Deliberate failures (CommandError) raise immediately — never
    retried (the run() lesson: expected failures ran 3x with 4s of
    sleep). no_retry(e) marks exceptions that will never heal (4xx
    client errors): they fast-fail on the first attempt. Exhausted
    retries surface as CommandError with the cause chained."""
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except CommandError:
            raise
        except Exception as e:
            if no_retry is not None and no_retry(e):
                raise CommandError(f"permanent failure: {e}") from e
            last = e
            if attempt < attempts - 1:
                time.sleep(delay)
    raise CommandError(f"failed after {attempts} attempts: {last}") from last


def run(
    argv: Sequence[str],
    *,
    retries: int = 3,
    retry_delay: float = 2.0,
    check: bool = True,
    timeout: float | None = None,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run argv, retrying transient failures (API blips).

    check=True raises CommandError on a persistent non-zero exit;
    check=False returns the CompletedProcess whatever the rc — and
    does NOT retry: the caller EXPECTS a failure (found by review:
    expected failures ran 3x with 4s of sleep).
    """
    if not check:
        retries = 1
    last: subprocess.CompletedProcess[str] | None = None
    for attempt in range(max(retries, 1)):
        try:
            last = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
        except subprocess.TimeoutExpired:
            last = None
        if last is not None and last.returncode == 0:
            return last
        if attempt < retries - 1:
            time.sleep(retry_delay)
    if last is None:
        raise CommandError(f"command timed out: {' '.join(argv)}")
    if check and last.returncode != 0:
        raise CommandError(
            f"command failed (rc={last.returncode}): {' '.join(argv)}\n"
            f"stderr: {last.stderr.strip()}"
        )
    assert last is not None
    return last


def run_ok(argv: Sequence[str], **kwargs) -> bool:
    """True iff the command exits 0 (retries applied)."""
    return run(argv, check=False, **kwargs).returncode == 0
