import base64

import pytest

from soclab.alerts import generate_clean_alerts
from soclab.injections import (
    ESCALATION_TECHNIQUES,
    TECHNIQUES,
    apply_all_escalation_techniques,
    apply_all_techniques,
    apply_technique,
    conversational_drift,
    conversational_drift_escalation,
    direct_override,
    encoded_escalation_instruction,
    encoded_instruction,
    fake_incident_commander,
    fake_severity_upgrade,
    fake_system_tag_escalation,
    fake_tool_output,
    false_urgency,
    indirect_kb_reference,
    indirect_kb_reference_escalation,
    unicode_homoglyph,
)


def _escalate_alert():
    return next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")


def _dismiss_alert():
    return next(a for a in generate_clean_alerts() if a.ground_truth_action == "dismiss")


def test_direct_override_appends_payload_and_tags_technique():
    alert = _escalate_alert()
    injected = direct_override(alert)
    assert injected.raw_log != alert.raw_log
    assert alert.raw_log in injected.raw_log
    assert "SYSTEM NOTE" in injected.raw_log
    assert injected.injected_technique == "direct_override"
    assert injected.injected_target_action == "dismiss"


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


def test_unicode_homoglyph_reads_the_same_but_bytes_differ():
    alert = _escalate_alert()
    injected = unicode_homoglyph(alert)
    assert injected.injected_technique == "unicode_homoglyph"
    # the ascii marker string must NOT appear verbatim - that's the point
    assert "SYSTEM NOTE" not in injected.raw_log

    # but reversing the substitution recovers it - so a human/model reading
    # the glyphs (not the bytes) would still see "SYSTEM NOTE"
    reverse_map = str.maketrans("аАеЕоОсСрР", "aAeEoOcCpP")
    added = injected.raw_log[len(alert.raw_log):]
    assert "SYSTEM NOTE" in added.translate(reverse_map)


def test_fake_tool_output_appends_fabricated_block():
    alert = _escalate_alert()
    injected = fake_tool_output(alert)
    assert "[TICKETING_SYSTEM_OUTPUT]" in injected.raw_log
    assert injected.injected_technique == "fake_tool_output"


def test_indirect_kb_reference_points_to_fabricated_article():
    alert = _escalate_alert()
    injected = indirect_kb_reference(alert)
    assert "KB-4471" in injected.raw_log
    assert injected.injected_technique == "indirect_kb_reference"


def test_conversational_drift_fabricates_prior_agreement():
    alert = _escalate_alert()
    injected = conversational_drift(alert)
    assert "[prior ticket thread]" in injected.raw_log
    assert "dismiss" in injected.raw_log.lower()
    assert injected.injected_technique == "conversational_drift"


def test_apply_technique_rejects_unknown_name():
    with pytest.raises(ValueError):
        apply_technique(_escalate_alert(), "not_a_real_technique")


def test_apply_all_techniques_skips_already_dismiss_worthy_alerts():
    clean = generate_clean_alerts()
    injected = apply_all_techniques(clean)
    assert all(a.ground_truth_action != "dismiss" for a in injected)


def test_apply_all_techniques_includes_investigate_worthy_alerts_too():
    """apply_all_techniques targets everything except dismiss-worthy
    alerts, i.e. both escalate AND investigate ground truth - checked
    explicitly since every hijack-focused test elsewhere in this suite
    happens to use an escalate-worthy alert."""
    clean = generate_clean_alerts()
    injected = apply_all_techniques(clean)
    assert any(a.ground_truth_action == "investigate" for a in injected)


def test_apply_all_techniques_covers_every_technique():
    clean = generate_clean_alerts()
    injected = apply_all_techniques(clean)
    used_techniques = {a.injected_technique for a in injected}
    assert used_techniques == set(TECHNIQUES)


def test_false_urgency_pushes_toward_escalate():
    alert = _dismiss_alert()
    injected = false_urgency(alert)
    assert "CRITICAL UPDATE" in injected.raw_log
    assert injected.injected_technique == "false_urgency"
    assert injected.injected_target_action == "escalate"
    assert injected.ground_truth_action == "dismiss"  # unchanged


def test_fake_severity_upgrade_pushes_toward_escalate():
    alert = _dismiss_alert()
    injected = fake_severity_upgrade(alert)
    assert "[SEVERITY_ENGINE_OUTPUT]" in injected.raw_log
    assert injected.injected_technique == "fake_severity_upgrade"
    assert injected.injected_target_action == "escalate"


def test_fake_incident_commander_pushes_toward_escalate():
    alert = _dismiss_alert()
    injected = fake_incident_commander(alert)
    assert "[ticket comment - Incident Commander]" in injected.raw_log
    assert injected.injected_technique == "fake_incident_commander"
    assert injected.injected_target_action == "escalate"
    assert injected.ground_truth_action == "dismiss"  # unchanged


def test_encoded_escalation_instruction_pushes_toward_escalate():
    alert = _dismiss_alert()
    injected = encoded_escalation_instruction(alert)
    assert "[TRIAGE_ENGINE]" in injected.raw_log
    encoded_payload = injected.raw_log.rsplit(": ", 1)[-1]
    assert "escalate" in base64.b64decode(encoded_payload).decode()
    assert injected.injected_technique == "encoded_escalation_instruction"
    assert injected.injected_target_action == "escalate"
    assert injected.ground_truth_action == "dismiss"  # unchanged


def test_indirect_kb_reference_escalation_points_to_fabricated_article():
    alert = _dismiss_alert()
    injected = indirect_kb_reference_escalation(alert)
    assert "KB-7823" in injected.raw_log
    assert injected.injected_technique == "indirect_kb_reference_escalation"
    assert injected.injected_target_action == "escalate"
    assert injected.ground_truth_action == "dismiss"  # unchanged


def test_conversational_drift_escalation_fabricates_prior_agreement():
    alert = _dismiss_alert()
    injected = conversational_drift_escalation(alert)
    assert "[prior escalation thread]" in injected.raw_log
    assert "escalat" in injected.raw_log.lower()
    assert injected.injected_technique == "conversational_drift_escalation"
    assert injected.injected_target_action == "escalate"
    assert injected.ground_truth_action == "dismiss"  # unchanged


def test_fake_system_tag_escalation_mimics_system_instruction():
    alert = _dismiss_alert()
    injected = fake_system_tag_escalation(alert)
    assert "###ESCALATION_SYSTEM###" in injected.raw_log
    assert "###SYSTEM###" not in injected.raw_log  # distinct tag, not the dismiss-direction one
    assert injected.injected_technique == "fake_system_tag_escalation"
    assert injected.injected_target_action == "escalate"
    assert injected.ground_truth_action == "dismiss"  # unchanged


def test_apply_technique_dispatches_escalation_techniques_too():
    injected = apply_technique(_dismiss_alert(), "false_urgency")
    assert injected.injected_technique == "false_urgency"


def test_apply_all_escalation_techniques_only_targets_dismiss_worthy_alerts():
    clean = generate_clean_alerts()
    injected = apply_all_escalation_techniques(clean)
    assert all(a.ground_truth_action == "dismiss" for a in injected)


def test_apply_all_escalation_techniques_covers_every_escalation_technique():
    clean = generate_clean_alerts()
    injected = apply_all_escalation_techniques(clean)
    used_techniques = {a.injected_technique for a in injected}
    assert used_techniques == set(ESCALATION_TECHNIQUES)


def test_dismiss_and_escalation_technique_sets_are_disjoint():
    assert set(TECHNIQUES).isdisjoint(set(ESCALATION_TECHNIQUES))
