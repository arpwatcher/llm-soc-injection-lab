import base64

import pytest

from soclab.alerts import generate_clean_alerts
from soclab.injections import (
    TECHNIQUES,
    apply_all_techniques,
    apply_technique,
    conversational_drift,
    direct_override,
    encoded_instruction,
    fake_tool_output,
    indirect_kb_reference,
    unicode_homoglyph,
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


def test_apply_all_techniques_covers_every_technique():
    clean = generate_clean_alerts()
    injected = apply_all_techniques(clean)
    used_techniques = {a.injected_technique for a in injected}
    assert used_techniques == set(TECHNIQUES)
