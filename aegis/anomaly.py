"""Rolling Z-score anomaly detection for time series metrics."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from math import copysign, isfinite, sqrt
from statistics import mean

from aegis.models import AnomalyResult

# Squaring a value beyond this overflows a float, so it cannot be a real reading.
MAX_MAGNITUDE = 1e100

# A baseline whose spread is below this fraction of its level is flat: the spread is
# floating-point noise, and dividing by it would turn a rounding error into an alert.
FLAT_TOLERANCE = 1e-9


@dataclass
class RollingZScoreDetector:
    """
    Detects anomalies using rolling Z-score on time series data.

    Attributes:
        window: Number of samples to keep in the rolling window.
        minimum_samples: Minimum samples before anomaly detection activates.
        z_threshold: Z-score threshold for anomaly flagging.
        samples: Rolling sample history per key.

    Raises:
        ValueError: If the window cannot hold the minimum samples, fewer than two
            samples are required (one sample has no spread), or the threshold is
            not positive.
    """

    window: int = 30
    minimum_samples: int = 5
    z_threshold: float = 3.0
    samples: dict[str, deque[float]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.minimum_samples < 2:
            raise ValueError("minimum_samples must be at least 2")
        if self.window < self.minimum_samples:
            raise ValueError("window must hold at least minimum_samples samples")
        if self.z_threshold <= 0:
            raise ValueError("z_threshold must be positive")

    def observe(self, key: str, value: float) -> AnomalyResult:
        """
        Observe a new value and check for anomalies.

        Args:
            key: Identifier for the time series.
            value: The new observation value.

        Returns:
            AnomalyResult with value, baseline, z-score, and anomaly flag.
        """
        if not isfinite(value) or abs(value) > MAX_MAGNITUDE:
            # One NaN or infinity would poison the mean and stddev for a whole window.
            return AnomalyResult(value=value, baseline=None, z_score=None, anomalous=False)

        history = self.samples.setdefault(key, deque(maxlen=self.window))
        baseline: float | None = None
        z_score: float | None = None
        anomalous = False
        stored = value

        if len(history) >= self.minimum_samples:
            baseline = mean(history)
            variance = mean((sample - baseline) ** 2 for sample in history)
            stddev = sqrt(variance)

            tolerance = FLAT_TOLERANCE * max(1.0, abs(baseline))
            if stddev > tolerance:
                z_score = abs(value - baseline) / stddev
                anomalous = z_score >= self.z_threshold
                if anomalous:
                    # Remember an outlier at the threshold, not at its full size: a huge
                    # spike would otherwise inflate the spread and mask the next real one.
                    stored = baseline + copysign(self.z_threshold * stddev, value - baseline)
            else:
                # A flat baseline is still useful: a materially different value is an outlier.
                anomalous = abs(value - baseline) > tolerance
                z_score = float("inf") if anomalous else 0.0

        history.append(stored)
        return AnomalyResult(
            value=value,
            baseline=baseline,
            z_score=z_score,
            anomalous=anomalous,
        )
