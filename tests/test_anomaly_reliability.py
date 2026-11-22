import math

import pytest

from aegis.anomaly import RollingZScoreDetector


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_non_finite_values_are_ignored_and_do_not_poison_the_baseline(bad):
    detector = RollingZScoreDetector(window=10, minimum_samples=3)
    for value in (1.0, 2.0, 3.0):
        detector.observe("latency", value)

    skipped = detector.observe("latency", bad)

    assert skipped.anomalous is False
    assert skipped.z_score is None
    assert list(detector.samples["latency"]) == [1.0, 2.0, 3.0]
    after = detector.observe("latency", 2.0)
    assert after.baseline == 2.0
    assert after.z_score is not None
    assert math.isfinite(after.z_score)
