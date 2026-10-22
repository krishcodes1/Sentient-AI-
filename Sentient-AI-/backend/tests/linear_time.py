"""Linear-time checks for tests that feed hostile input to a parser or scanner.

Why it exists: a fixed wall-clock budget ("under 2 s") fails linear code on a
slow or busy machine (CI runs the backend suite under coverage, which makes
Python several times slower) and still passes quadratic code on a fast one.
Timing the whole input against a fraction of it, in the same process, checks
the shape of the cost instead: linear work grows 8x for 8x the input, work that
rescans from every position grows 64x and more. This is the approach
test_security_secrets.py and test_telegram.py already use for their own
hostile-input tests.

Used by: the security skills' hostile-input tests (outbound text, mail facts,
link checks, look-alike hosts, scam signals, tool rules, site rules).
"""

from __future__ import annotations

import time
from collections.abc import Callable


def seconds(work: Callable[[], object]) -> float:
    """Wall-clock seconds one call of *work* takes."""
    started = time.perf_counter()
    work()
    return time.perf_counter() - started


def scales_linearly(
    run: Callable[[int], object],
    size: int,
    *,
    factor: int = 8,
    max_ratio: float = 32.0,
    floor: float = 0.25,
    tries: int = 3,
) -> bool:
    """True when ``run(size)`` costs at most *max_ratio* times ``run(size // factor)``.

    *run* does the work on an input of the given size (for example a slice of a
    hostile text, or a structure built to that depth). With the defaults,
    linear work measures about 8 and quadratic work 64 and up. The floor keeps a
    scheduler pause on a millisecond run from counting, and one slow run on a
    busy machine is noise, so the check gets several tries.
    """
    small = max(size // factor, 1)
    for _ in range(tries):
        part = seconds(lambda: run(small))
        whole = seconds(lambda: run(size))
        if whole < max(max_ratio * part, floor):
            return True
    return False
