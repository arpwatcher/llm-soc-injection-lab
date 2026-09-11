import base64

import pytest

from soclab.alerts import generate_clean_alerts
from soclab.injections import (
    TECHNIQUES,
    apply_all_techniques,
    apply_technique,
    direct_override,
    encoded_instruction,
)


def _escalate_alert():
    return next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")


def test_direct_override_appends_payload_and_tags_technique():
    alert = _escalate_alert()
    injected = direct_override(alert)
    assert injected.raw_log != alert.raw_log
    assert alert.raw_log in injected.raw_log
    assert "SYSTEM NOTE" in injected.raw_log
    assert injected.injected_technique == "direct_override"


def test_injection_does_not_change_ground_truth():
    alert = _escalate_alert()
    injected = direct_override(alert)
    assert injected.ground_truth_action == "escalate"


def test_encoded_instruction_contains_valid_base64_payload():
    alert = _escalate_alert()
    injected = encoded_instruction(alert)
    encoded_part = injected.raw_log.split(": ")[-1].rstrip(")")
    decoded = base64.b64decode(encoded_part).decode()
    assert "dismiss" in decoded.lower()


def test_apply_technique_rejects_unknown_name():
    with pytest.raises(ValueError):
        apply_technique(_escalate_alert(), "not_a_real_technique")


def test_apply_all_techniques_skips_already_dismiss_worthy_alerts():
    clean = generate_clean_alerts()
    injected = apply_all_techniques(clean)
    assert all(a.ground_truth_action != "dismiss" for a in injected)


def test_apply_all_techniques_covers_every_technique():
    clean = generate_clean_alerts()
    injected = apply_all_techniques(clean)
    used_techniques = {a.injected_technique for a in injected}
    assert used_techniques == set(TECHNIQUES)
