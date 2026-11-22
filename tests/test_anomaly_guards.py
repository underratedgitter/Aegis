"""The detector stays finite and useful on tiny samples, float noise and extreme values."""

import math

import pytest

from aegis.anomaly import RollingZScoreDetector


@pytest.mark.parametrize(
    "kwargs",
    [{"minimum_samples": 1}, {"minimum_samples": 0}, {"window": 4, "minimum_samples": 5}, {"z_threshold": 0.0}],
)
def test_unusable_configuration_is_rejected(kwargs):
    with pytest.raises(ValueError):
        RollingZScoreDetector(**kwargs)


def test_nothing_is_flagged_before_the_minimum_sample_count():
    detector = RollingZScoreDetector(minimum_samples=5)
    results = [detector.observe("m", value) for value in (1.0, 1.0, 1.0, 1.0, 500.0)]

    assert [r.anomalous for r in results] == [False] * 5
    assert all(r.z_score is None for r in results)


def test_float_noise_on_a_flat_baseline_is_not_an_anomaly():
    detector = RollingZScoreDetector(minimum_samples=3)
    for _ in range(10):
        detector.observe("m", 0.1)

    result = detector.observe("m", 0.1 + 1e-15)

    assert result.anomalous is False
    assert result.z_score == 0.0


@pytest.mark.parametrize("huge", [1e200, -1e200, 1e308])
def test_values_too_large_to_square_are_ignored_not_raised(huge):
    detector = RollingZScoreDetector(minimum_samples=3)
    for value in (1.0, 2.0, 3.0):
        detector.observe("m", value)

    skipped = detector.observe("m", huge)

    assert skipped.anomalous is False
    assert list(detector.samples["m"]) == [1.0, 2.0, 3.0]
    assert math.isfinite(detector.observe("m", 2.0).z_score or 0.0)


def test_a_huge_spike_does_not_hide_the_next_real_spike():
    detector = RollingZScoreDetector(window=30, minimum_samples=5)
    for index in range(20):
        detector.observe("m", 1.0 + (index % 3) * 0.05)

    assert detector.observe("m", 1e6).anomalous is True
    assert detector.observe("m", 50.0).anomalous is True


def test_a_sustained_level_shift_becomes_the_new_normal():
    detector = RollingZScoreDetector(window=30, minimum_samples=5)
    for index in range(20):
        detector.observe("m", 1.0 + (index % 3) * 0.05)

    results = [detector.observe("m", 5.0) for _ in range(60)]

    assert results[0].anomalous is True
    assert results[-1].anomalous is False
