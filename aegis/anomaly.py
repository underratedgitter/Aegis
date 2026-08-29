"""Rolling Z-score anomaly detection for time series metrics."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from math import sqrt
from statistics import mean

from aegis.models import AnomalyResult


@dataclass
class RollingZScoreDetector:
    """
    Detects anomalies using rolling Z-score on time series data.

    Attributes:
        window: Number of samples to keep in the rolling window.
        minimum_samples: Minimum samples before anomaly detection activates.
        z_threshold: Z-score threshold for anomaly flagging.
        samples: Rolling sample history per key.
    """

    window: int = 30
    minimum_samples: int = 5
    z_threshold: float = 3.0
    samples: dict[str, deque[float]] = field(default_factory=dict)

    def observe(self, key: str, value: float) -> AnomalyResult:
        """
        Observe a new value and check for anomalies.

        Args:
            key: Identifier for the time series.
            value: The new observation value.

        Returns:
            AnomalyResult with value, baseline, z-score, and anomaly flag.
        """
        history = self.samples.setdefault(key, deque(maxlen=self.window))
        baseline: float | None = None
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
        return AnomalyResult(
            value=value,
            baseline=baseline,
            z_score=z_score,
            anomalous=anomalous,
        )
