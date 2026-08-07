from aegis.anomaly import RollingZScoreDetector


def test_rolling_z_score_waits_for_a_baseline_then_detects_outlier():
    detector = RollingZScoreDetector(window=10, minimum_samples=5, z_threshold=3)
    for value in (1, 1, 1, 1, 1):
        result = detector.observe("latency", value)
        assert not result.anomalous
    result = detector.observe("latency", 10)
    assert result.anomalous
    assert result.z_score == float("inf")
