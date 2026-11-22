"""Static checks on the dashboard. The UI has no JS test harness, so assert on the shipped files."""

import re
from pathlib import Path

from fastapi.routing import APIRoute

from aegis import control_plane

STATIC = Path(control_plane.__file__).parent / "static"
INDEX = (STATIC / "index.html").read_text()
APP_JS = (STATIC / "app.js").read_text()
CSS = (STATIC / "styles.css").read_text()

VIEWS = ("overview", "incidents", "chaos", "telemetry", "runbooks", "audit", "settings")


class TestShell:
    def test_every_view_has_a_nav_link_and_a_section(self):
        for view in VIEWS:
            assert f'href="#/{view}"' in INDEX, view
            assert f'id="view-{view}"' in INDEX, view

    def test_has_landmarks_and_skip_link(self):
        for landmark in ("<nav", "<main", "<header", 'class="skip-link"'):
            assert landmark in INDEX, landmark

    def test_status_regions_announce_updates(self):
        assert 'id="toasts"' in INDEX
        assert 'aria-live="polite"' in INDEX

    def test_confirm_and_key_dialogs_exist(self):
        assert 'id="confirm-dialog"' in INDEX
        assert 'id="key-dialog"' in INDEX

    def test_motion_is_opt_out(self):
        assert "prefers-reduced-motion" in CSS

    def test_focus_is_visible(self):
        assert ":focus-visible" in CSS


class TestNoInlineCode:
    def test_no_inline_event_handlers(self):
        pattern = re.compile(r"\son[a-z]+\s*=\s*[\"']", re.IGNORECASE)
        assert not pattern.search(INDEX)
        assert not pattern.search(APP_JS)

    def test_no_inline_style_attributes(self):
        assert not re.search(r"\sstyle\s*=", INDEX)
        assert not re.search(r"\sstyle=", APP_JS)

    def test_script_assigns_no_inline_handlers(self):
        assert not re.search(r"\.on(click|change|input|submit)\s*=", APP_JS)


class TestNoJitter:
    def test_polling_patches_the_dom_in_place(self):
        assert "function patchChildren" in APP_JS
        assert "renderedHtml" in APP_JS
        assert "TIMELINE_LIMIT" in APP_JS

    def test_tabular_numbers_and_stable_scrollbar(self):
        assert "tabular-nums" in CSS
        assert "scrollbar-gutter" in CSS


class TestEveryEndpointIsReachable:
    def test_app_js_references_every_api_route(self):
        missing = []
        for route in control_plane.app.routes:
            if not isinstance(route, APIRoute) or not route.path.startswith(
                ("/api", "/healthz", "/readyz")
            ):
                continue
            before, _, rest = route.path.partition("{")
            after = rest.partition("}")[2]
            for piece in (before, after):
                if piece and piece not in APP_JS:
                    missing.append((route.path, piece))
        assert not missing


class TestEngineHealthDisplay:
    def test_pill_shows_every_engine_state_and_the_reason(self):
        for state in ("degraded", "stalled", "stopped"):
            assert f"engine {state}" in APP_JS, state
        assert 'id="engine-status"' in INDEX
        assert ".pill-warn" in CSS
        assert "state.engine?.reason" in APP_JS

    def test_settings_view_has_an_engine_health_panel_patched_in_place(self):
        assert 'id="set-engine-status"' in INDEX
        assert 'setHtml("set-engine-status"' in APP_JS
        assert "circuit" in APP_JS

    def test_settings_health_panel_lists_each_alert_signal_state(self):
        body = APP_JS.split("function engineRows(engine)")[1].split("\n}\n")[0]
        assert "engine.signals" in body
        assert "unavailable" in body

    def test_a_failed_engine_read_never_marks_the_control_plane_disconnected(self):
        body = APP_JS.split("async function loadEngineStatus()")[1].split("\n}\n")[0]
        assert "setConnection" not in body
class TestRemediationOutcomes:
    """The control room must show whether a fix was verified, not just that it ran."""

    def test_verification_states_have_a_label_and_a_style(self):
        for state in ("verifying", "verified", "failed", "unverified"):
            assert f"{state}:" in APP_JS, state
            assert f".verify-{state}" in CSS, state
        assert "function verificationBadge" in APP_JS

    def test_the_badge_is_shown_wherever_an_incident_status_is(self):
        assert APP_JS.count("${verificationBadge(incident)}") == 3

    def test_the_fix_card_reports_attempts_verification_and_escalation(self):
        assert "attempt" in APP_JS
        assert "remediation.verification" in APP_JS
        assert "Escalated" in APP_JS

    def test_execute_distinguishes_replays_and_dry_runs(self):
        assert 'result.status === "dry_run"' in APP_JS
        assert 'result.status === "already_executed"' in APP_JS

    def test_new_audit_actions_are_offered_in_the_filter(self):
        for action in (
            "execute_replayed",
            "execute_dry_run",
            "execute_failed",
            "execute_refused",
            "remediation_verified",
            "remediation_escalated",
        ):
            assert f'"{action}"' in APP_JS, action

    def test_timeline_marks_verification_and_escalation(self):
        assert ".kind-remediation_verified" in CSS
        assert ".kind-remediation_escalated" in CSS
