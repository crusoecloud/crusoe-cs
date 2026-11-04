"""Bounded, event-driven waits — the no-sleep rule as a primitive.

One polling loop with a max-attempts cap, never a bare sleep chain.
Every wait takes a predicate; the loop exits when the predicate
holds or the cap is hit (returning the predicate's value, so the
caller can die with the evidence in the message).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def wait_until(
    predicate: Callable[[], "T | None"],
    *,
    attempts: int = 30,
    delay: float = 2.0,
    message: str = "condition not met",
) -> "T | None":
    """Poll `predicate` until it returns a truthy value (or None on
    exhaustion). The caller asserts on the return.

    NB: a (bool, payload) tuple is truthy even when the bool is
    False — predicates returning that shape would ALWAYS read as
    success (found by review). A tuple's first element is checked
    when it is a bool."""
    for _ in range(max(attempts, 1)):
        value = predicate()
        if isinstance(value, tuple) and value and isinstance(value[0], bool):
            if value[0]:
                return value
        elif value:
            return value
        time.sleep(delay)
    return None


def wait_value(
    predicate: Callable[[], object],
    want: object,
    *,
    attempts: int = 30,
    delay: float = 2.0,
) -> object:
    """Poll until predicate() == want; returns the final value."""
    last: object = None
    for _ in range(max(attempts, 1)):
        last = predicate()
        if last == want:
            return last
        time.sleep(delay)
    return last
