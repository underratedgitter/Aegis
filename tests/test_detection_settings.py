"""Detection settings have safe defaults, fail fast on bad values, and reach the control plane."""

import pytest

from aegis.settings import Settings, SettingsError

DETECTION = {
    "AEGIS_DETECTION_CYCLES": ("detection_cycles", 2, 1),
    "AEGIS_BLIND_SECONDS": ("blind_seconds", 300, 0),
    "AEGIS_REOPEN_COOLDOWN_SECONDS": ("reopen_cooldown_seconds", 300, 0),
}


@pytest.mark.parametrize(("name", "attribute", "default", "minimum"), [(n, *v) for n, v in DETECTION.items()])
class TestDetectionSettings:
    def test_default_applies_when_unset(self, monkeypatch, name, attribute, default, minimum):
        monkeypatch.delenv(name, raising=False)
        assert getattr(Settings(), attribute) == default

    def test_environment_value_is_read(self, monkeypatch, name, attribute, default, minimum):
        monkeypatch.setenv(name, "7")
        assert getattr(Settings(), attribute) == 7

    def test_below_the_minimum_is_rejected_by_name(self, monkeypatch, name, attribute, default, minimum):
        monkeypatch.setenv(name, str(minimum - 1))
        with pytest.raises(SettingsError, match=name):
            Settings()

    def test_the_minimum_itself_is_accepted(self, monkeypatch, name, attribute, default, minimum):
        monkeypatch.setenv(name, str(minimum))
        assert getattr(Settings(), attribute) == minimum

    def test_a_typo_is_rejected_by_name(self, monkeypatch, name, attribute, default, minimum):
        monkeypatch.setenv(name, "1O")
        with pytest.raises(SettingsError, match=name):
            Settings()
