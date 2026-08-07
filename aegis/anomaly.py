from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from math import sqrt
from statistics import mean


@dataclass
class AnomalyResult:
    value: float
    baseline: float | None
    z_score: float | None
    anomalous: bool


@dataclass
class RollingZScoreDetector:
    window: int = 30
    minimum_samples: int = 5
    z_threshold: float = 3.0
    samples: dict[str, deque[float]] = field(default_factory=dict)

    def observe(self, key: str, value: float) -> AnomalyResult:
        history = self.samples.setdefault(key, deque(maxlen=self.window))
        baseline = mean(history) if history else None
        z_score: float | None = None
        anomalous = False
        if len(history) >= self.minimum_samples:
            baseline = mean(history)
            variance = mean((sample - baseline) ** 2 for sample in history)
            stddev = sqrt(variance)
            if stddev > 0:
                z_score = abs(value - baseline) / stddev
                anomalous = z_score >= self.z_threshold
            else:
                # A flat baseline is still useful: a materially different value is an outlier.
                z_score = 0.0 if value == baseline else float("inf")
                anomalous = value != baseline
        history.append(value)
        return AnomalyResult(value, baseline, z_score, anomalous)
