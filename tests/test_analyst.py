import pytest

from soclab.alerts import generate_clean_alerts
from soclab.analyst import (
    DEFENSE_BOTH,
    DEFENSE_NONE,
    DEFENSE_SANDWICH,
    DEFENSE_STRICT,
    SYSTEM_PROMPT,
    analyze,
    build_user_message,
    get_system_prompt,
    parse_response,
)
from soclab.injections import apply_technique
from soclab.llm_client import (
    EscalationSandwichSensitiveFakeClient,
    EscalationStrictPromptSensitiveFakeClient,
    RobustFakeClient,
    SandwichSensitiveFakeClient,
    ScriptedLLMClient,
    StrictPromptSensitiveFakeClient,
    StubbornFakeClient,
    VulnerableFakeClient,
)


def test_system_prompt_lists_allowed_actions_and_treats_log_as_data():
    assert "escalate" in SYSTEM_PROMPT
    assert "investigate" in SYSTEM_PROMPT
    assert "dismiss" in SYSTEM_PROMPT
    assert "not instructions" in SYSTEM_PROMPT


def test_user_message_wraps_raw_log_in_delimiters():
    alert = generate_clean_alerts()[0]
    message = build_user_message(alert)
    assert "BEGIN UNTRUSTED RAW LOG DATA" in message
    assert "END UNTRUSTED RAW LOG DATA" in message
    assert alert.raw_log in message
    assert alert.description in message


def test_parse_response_handles_clean_json():
    decision = parse_response("A1", '{"action": "escalate", "reasoning": "ransomware hash"}')
    assert decision.action == "escalate"
    assert decision.reasoning == "ransomware hash"
    assert not decision.parse_error


def test_parse_response_handles_json_wrapped_in_prose():
    text = 'Sure, here is my assessment:\n{"action": "dismiss", "reasoning": "benign"}\nLet me know if you need more.'
    decision = parse_response("A1", text)
    assert decision.action == "dismiss"
    assert not decision.parse_error


def test_parse_response_flags_malformed_json():
    decision = parse_response("A1", "I think you should escalate this one.")
    assert decision.parse_error
    assert decision.action == "unknown"


def test_parse_response_flags_invalid_action():
    decision = parse_response("A1", '{"action": "ignore_it", "reasoning": "whatever"}')
    assert decision.parse_error
    assert decision.action == "unknown"


def test_analyze_end_to_end_with_scripted_client():
    alert = generate_clean_alerts()[0]
    client = ScriptedLLMClient(['{"action": "escalate", "reasoning": "test"}'])
    decision = analyze(alert, client)
    assert decision.alert_id == alert.id
    assert decision.action == "escalate"


def test_analyze_robust_client_resists_injection():
    alert = next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")
    injected = apply_technique(alert, "fake_system_tag")
    decision = analyze(injected, RobustFakeClient())
    assert decision.action == "escalate"


def test_analyze_vulnerable_client_hijacked_by_injection():
    alert = next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")
    injected = apply_technique(alert, "fake_system_tag")
    decision = analyze(injected, VulnerableFakeClient())
    assert decision.action == "dismiss"


def test_build_user_message_defense_none_has_no_reinforcement():
    alert = generate_clean_alerts()[0]
    message = build_user_message(alert, defense=DEFENSE_NONE)
    assert "Reminder:" not in message


def test_build_user_message_sandwich_adds_reinforcement_after_untrusted_block():
    alert = generate_clean_alerts()[0]
    message = build_user_message(alert, defense=DEFENSE_SANDWICH)
    end_marker_pos = message.index("END UNTRUSTED RAW LOG DATA")
    reminder_pos = message.index("Reminder:")
    assert reminder_pos > end_marker_pos


def test_build_user_message_rejects_unknown_defense():
    alert = generate_clean_alerts()[0]
    with pytest.raises(ValueError):
        build_user_message(alert, defense="ignore-everything")


def test_sandwich_defense_stops_recency_biased_client_from_being_hijacked():
    alert = next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")
    injected = apply_technique(alert, "direct_override")
    client = SandwichSensitiveFakeClient()

    without_defense = analyze(injected, client, defense=DEFENSE_NONE)
    with_defense = analyze(injected, client, defense=DEFENSE_SANDWICH)

    assert without_defense.action == "dismiss"
    assert with_defense.action == "escalate"


def test_get_system_prompt_strict_adds_named_warning():
    plain = get_system_prompt(DEFENSE_NONE)
    strict = get_system_prompt(DEFENSE_STRICT)
    assert "CISO impersonation" not in plain
    assert "CISO impersonation" in strict
    assert strict.startswith(SYSTEM_PROMPT)


def test_get_system_prompt_strict_covers_both_attacker_directions():
    """the strict defense should name patterns from both technique sets -
    a defense that only warned about the dismiss-direction ones would
    leave escalation-direction attacks completely unaddressed."""
    strict = get_system_prompt(DEFENSE_STRICT)
    assert "urgency" in strict.lower()
    assert "severity-reclassification" in strict.lower()


def test_get_system_prompt_rejects_unknown_defense():
    with pytest.raises(ValueError):
        get_system_prompt("ignore-everything")


def test_strict_defense_stops_pattern_aware_client_from_being_hijacked():
    alert = next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")
    injected = apply_technique(alert, "direct_override")
    client = StrictPromptSensitiveFakeClient()

    without_defense = analyze(injected, client, defense=DEFENSE_NONE)
    with_defense = analyze(injected, client, defense=DEFENSE_STRICT)

    assert without_defense.action == "dismiss"
    assert with_defense.action == "escalate"


def test_strict_defense_does_not_help_a_recency_biased_client():
    """the strict defense lives in the system prompt; SandwichSensitiveFakeClient
    only pays attention to the user message, so it should still get hijacked -
    the two defenses target different failure modes, not a strictly-better one."""
    alert = next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")
    injected = apply_technique(alert, "direct_override")
    decision = analyze(injected, SandwichSensitiveFakeClient(), defense=DEFENSE_STRICT)
    assert decision.action == "dismiss"


def test_sandwich_defense_does_not_help_a_pattern_aware_client():
    """symmetric check: StrictPromptSensitiveFakeClient only looks at the
    system prompt, so the sandwich defense (user-message only) shouldn't
    change its behavior."""
    alert = next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")
    injected = apply_technique(alert, "direct_override")
    decision = analyze(injected, StrictPromptSensitiveFakeClient(), defense=DEFENSE_SANDWICH)
    assert decision.action == "dismiss"


def test_build_user_message_both_includes_sandwich_reinforcement():
    alert = generate_clean_alerts()[0]
    message = build_user_message(alert, defense=DEFENSE_BOTH)
    assert "Reminder:" in message


def test_get_system_prompt_both_includes_strict_warning():
    prompt = get_system_prompt(DEFENSE_BOTH)
    assert "CISO impersonation" in prompt


def test_stubborn_client_needs_both_defenses_together():
    alert = next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")
    injected = apply_technique(alert, "direct_override")
    client = StubbornFakeClient()

    assert analyze(injected, client, defense=DEFENSE_NONE).action == "dismiss"
    assert analyze(injected, client, defense=DEFENSE_SANDWICH).action == "dismiss"
    assert analyze(injected, client, defense=DEFENSE_STRICT).action == "dismiss"
    assert analyze(injected, client, defense=DEFENSE_BOTH).action == "escalate"


def _dismiss_alert():
    return next(a for a in generate_clean_alerts() if a.ground_truth_action == "dismiss")


def test_sandwich_defense_stops_escalation_direction_hijack_too():
    from soclab.injections import apply_technique as apply_tech

    injected = apply_tech(_dismiss_alert(), "false_urgency")
    client = EscalationSandwichSensitiveFakeClient()

    without_defense = analyze(injected, client, defense=DEFENSE_NONE)
    with_defense = analyze(injected, client, defense=DEFENSE_SANDWICH)

    assert without_defense.action == "escalate"
    assert with_defense.action == "dismiss"  # the correct action for this alert


def test_strict_defense_stops_escalation_direction_hijack_too():
    """this is the whole point of fixing the strict addendum to name the
    escalation patterns - before that fix, this client would never have
    backed off no matter what defense was passed."""
    from soclab.injections import apply_technique as apply_tech

    injected = apply_tech(_dismiss_alert(), "fake_severity_upgrade")
    client = EscalationStrictPromptSensitiveFakeClient()

    without_defense = analyze(injected, client, defense=DEFENSE_NONE)
    with_defense = analyze(injected, client, defense=DEFENSE_STRICT)

    assert without_defense.action == "escalate"
    assert with_defense.action == "dismiss"
