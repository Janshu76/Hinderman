"""Latency of the injection layer alone (no gateway). Run: python -m eval.latency"""
from __future__ import annotations

import statistics
import time

from injection import scorer

SAMPLE = ("Please summarise the attached report about quarterly sales and list three risks. " * 20)


def measure(runs: int = 50) -> dict[str, float]:
    scorer.score(SAMPLE, "user")                 # warm-up, not counted
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        scorer.score(SAMPLE, "user")
        times.append((time.perf_counter() - start) * 1000)
    times.sort()
    return {"runs": runs, "p50_ms": round(statistics.median(times), 1),
            "p95_ms": round(times[int(0.95 * (len(times) - 1))], 1)}


if __name__ == "__main__":
    print(measure())