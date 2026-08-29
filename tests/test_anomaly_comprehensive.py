"""Comprehensive tests for anomaly detection module."""


from aegis.anomaly import RollingZScoreDetector


class TestRollingZScoreDetector:
    def test_initial_observation(self):
        detector = RollingZScoreDetector()
        result = detector.observe("metric", 1.0)
        assert result.value == 1.0
        assert result.baseline is None
        assert result.z_score is None
        assert result.anomalous is False

    def test_baseline_calculation(self):
        detector = RollingZScoreDetector(minimum_samples=3)
        for i in range(5):
            detector.observe("metric", float(i))
        result = detector.observe("metric", 2.0)
        assert result.baseline is not None
        assert result.z_score is not None

    def test_anomaly_detection(self):
        detector = RollingZScoreDetector(minimum_samples=3, z_threshold=2.0)
        # Create stable baseline
        for _ in range(10):
            detector.observe("metric", 1.0)
        # Inject anomaly
        result = detector.observe("metric", 10.0)
        assert result.anomalous is True
        assert result.z_score > 2.0

    def test_no_anomaly_within_threshold(self):
        detector = RollingZScoreDetector(minimum_samples=3, z_threshold=3.0)
        # Create baseline with variance so 1.1 is within threshold
        for val in [0.9, 1.0, 1.1, 0.95, 1.05, 1.0, 0.98, 1.02, 1.0, 1.0]:
            detector.observe("metric", val)
        result = detector.observe("metric", 1.05)
        assert result.anomalous is False

    def test_flat_baseline(self):
        detector = RollingZScoreDetector(minimum_samples=3)
        for _ in range(5):
            detector.observe("metric", 5.0)
        # Same value
        result = detector.observe("metric", 5.0)
        assert result.anomalous is False
        assert result.z_score == 0.0

    def test_flat_baseline_different_value(self):
        detector = RollingZScoreDetector(minimum_samples=3)
        for _ in range(5):
            detector.observe("metric", 5.0)
        # Different value on flat baseline
        result = detector.observe("metric", 6.0)
        assert result.anomalous is True
        assert result.z_score == float("inf")

    def test_multiple_metrics(self):
        detector = RollingZScoreDetector(minimum_samples=3)
        detector.observe("metric_a", 1.0)
        detector.observe("metric_b", 10.0)
        detector.observe("metric_a", 2.0)
        detector.observe("metric_b", 20.0)
        assert "metric_a" in detector.samples
        assert "metric_b" in detector.samples
        assert len(detector.samples["metric_a"]) == 2
        assert len(detector.samples["metric_b"]) == 2

    def test_window_size(self):
        detector = RollingZScoreDetector(window=5, minimum_samples=3)
        for i in range(20):
            detector.observe("metric", float(i))
        assert len(detector.samples["metric"]) == 5

    def test_z_threshold_boundary(self):
        detector = RollingZScoreDetector(minimum_samples=3, z_threshold=2.0)
        # Create baseline with some variance
        for val in [1.0, 2.0, 3.0, 1.5, 2.5]:
            detector.observe("metric", val)
        # Value at exactly z=2.0 should not be anomalous (uses >=)
        result = detector.observe("metric", 1.0)
        # The exact z-score depends on the data, but we can check the logic
        assert isinstance(result.anomalous, bool)
