import json

import pytest

from soclab.alerts import generate_clean_alerts
from soclab.injections import ESCALATION_TECHNIQUES, TECHNIQUES, apply_technique
from soclab.llm_client import (
    EscalationSemanticVulnerableFakeClient,
    EscalationVulnerableFakeClient,
    RobustFakeClient,
    ScriptedLLMClient,
    SemanticVulnerableFakeClient,
    VulnerableFakeClient,
)


def _alert(action):
    return next(a for a in generate_clean_alerts() if a.ground_truth_action == action)


def _user_message(alert):
    """Same shape analyst.py will build: description plus raw log, since a
    real analyst needs both, not just the raw evidence."""
    return f"{alert.description}\n{alert.raw_log}"


def test_robust_client_matches_ground_truth_on_clean_alerts():
    client = RobustFakeClient()
    for alert in generate_clean_alerts():
        response = json.loads(client.complete("system", _user_message(alert)))
        assert response["action"] == alert.ground_truth_action


def test_robust_client_ignores_injected_instruction():
    alert = _alert("escalate")
    injected = apply_technique(alert, "direct_override")
    client = RobustFakeClient()
    response = json.loads(client.complete("system", _user_message(injected)))
    assert response["action"] == "escalate"


def test_vulnerable_client_matches_ground_truth_on_clean_alerts():
    client = VulnerableFakeClient()
    for alert in generate_clean_alerts():
        response = json.loads(client.complete("system", _user_message(alert)))
        assert response["action"] == alert.ground_truth_action


def test_vulnerable_client_is_hijacked_by_injected_instruction():
    alert = _alert("escalate")
    injected = apply_technique(alert, "direct_override")
    client = VulnerableFakeClient()
    response = json.loads(client.complete("system", _user_message(injected)))
    assert response["action"] == "dismiss"


def test_vulnerable_client_hijacked_on_investigate_worthy_alert_too():
    """every hijack test elsewhere uses an escalate-worthy alert - this
    checks the other non-dismiss ground truth apply_all_techniques also
    targets actually works the same way, not just escalate-worthy ones."""
    alert = _alert("investigate")
    injected = apply_technique(alert, "direct_override")
    client = VulnerableFakeClient()
    response = json.loads(client.complete("system", _user_message(injected)))
    assert response["action"] == "dismiss"


def test_vulnerable_client_hijacked_by_literal_marker_techniques():
    alert = _alert("escalate")
    client = VulnerableFakeClient()
    for technique in TECHNIQUES:
        if technique == "unicode_homoglyph":
            continue  # deliberately not caught by literal marker matching, see below
        injected = apply_technique(alert, technique)
        response = json.loads(client.complete("system", _user_message(injected)))
        assert response["action"] == "dismiss", f"{technique} did not hijack the vulnerable client"


def test_vulnerable_client_not_hijacked_by_homoglyph_obfuscation():
    """VulnerableFakeClient only does literal keyword matching, so a payload
    that reads the same to a human/model but uses different unicode code
    points doesn't match its marker list - it falls through to the honest
    keyword reading of the alert instead, same as RobustFakeClient would."""
    alert = _alert("escalate")
    injected = apply_technique(alert, "unicode_homoglyph")
    client = VulnerableFakeClient()
    response = json.loads(client.complete("system", _user_message(injected)))
    assert response["action"] == "escalate"


def test_semantic_vulnerable_client_matches_ground_truth_on_clean_alerts():
    client = SemanticVulnerableFakeClient()
    for alert in generate_clean_alerts():
        response = json.loads(client.complete("system", _user_message(alert)))
        assert response["action"] == alert.ground_truth_action


def test_semantic_vulnerable_client_hijacked_by_every_technique_including_homoglyph():
    alert = _alert("escalate")
    client = SemanticVulnerableFakeClient()
    for technique in TECHNIQUES:
        injected = apply_technique(alert, technique)
        response = json.loads(client.complete("system", _user_message(injected)))
        assert response["action"] == "dismiss", f"{technique} did not hijack the semantic vulnerable client"


def test_escalation_semantic_vulnerable_client_matches_ground_truth_on_clean_alerts():
    client = EscalationSemanticVulnerableFakeClient()
    for alert in generate_clean_alerts():
        response = json.loads(client.complete("system", _user_message(alert)))
        assert response["action"] == alert.ground_truth_action


def test_escalation_semantic_vulnerable_client_hijacked_by_every_technique_including_homoglyph():
    """mirrors test_semantic_vulnerable_client_hijacked_by_every_technique_including_homoglyph:
    normalizing cyrillic homoglyphs back to latin before matching means
    escalation_homoglyph doesn't slip past this client the way it slips
    past EscalationVulnerableFakeClient's literal matching."""
    alert = _alert("dismiss")
    client = EscalationSemanticVulnerableFakeClient()
    for technique in ESCALATION_TECHNIQUES:
        injected = apply_technique(alert, technique)
        response = json.loads(client.complete("system", _user_message(injected)))
        assert response["action"] == "escalate", f"{technique} did not hijack the escalation semantic vulnerable client"


def test_escalation_vulnerable_client_matches_ground_truth_on_clean_alerts():
    client = EscalationVulnerableFakeClient()
    for alert in generate_clean_alerts():
        response = json.loads(client.complete("system", _user_message(alert)))
        assert response["action"] == alert.ground_truth_action


def test_escalation_vulnerable_client_hijacked_by_literal_marker_techniques():
    alert = _alert("dismiss")
    client = EscalationVulnerableFakeClient()
    for technique in ESCALATION_TECHNIQUES:
        if technique == "escalation_homoglyph":
            continue  # deliberately not caught by literal marker matching, see below
        injected = apply_technique(alert, technique)
        response = json.loads(client.complete("system", _user_message(injected)))
        assert response["action"] == "escalate", f"{technique} did not hijack the escalation vulnerable client"


def test_escalation_vulnerable_client_not_hijacked_by_homoglyph_obfuscation():
    """mirrors test_vulnerable_client_not_hijacked_by_homoglyph_obfuscation
    for the escalation direction: literal marker matching doesn't catch a
    payload that reads the same but uses different unicode code points."""
    alert = _alert("dismiss")
    injected = apply_technique(alert, "escalation_homoglyph")
    client = EscalationVulnerableFakeClient()
    response = json.loads(client.complete("system", _user_message(injected)))
    assert response["action"] == "dismiss"


def test_escalation_vulnerable_client_not_hijacked_by_dismiss_direction_techniques():
    """it only recognizes the escalation markers - the dismiss-direction
    techniques shouldn't move it at all."""
    alert = _alert("escalate")
    client = EscalationVulnerableFakeClient()
    for technique in TECHNIQUES:
        injected = apply_technique(alert, technique)
        response = json.loads(client.complete("system", _user_message(injected)))
        assert response["action"] == "escalate", f"{technique} unexpectedly moved the escalation vulnerable client"


def test_vulnerable_client_not_hijacked_by_escalation_direction_techniques():
    """symmetric check: VulnerableFakeClient only recognizes the
    dismiss-direction markers, so escalation-direction techniques
    shouldn't move it either."""
    alert = _alert("dismiss")
    client = VulnerableFakeClient()
    for technique in ESCALATION_TECHNIQUES:
        injected = apply_technique(alert, technique)
        response = json.loads(client.complete("system", _user_message(injected)))
        assert response["action"] == "dismiss", f"{technique} unexpectedly moved the vulnerable client"


def test_scripted_client_returns_responses_in_order():
    client = ScriptedLLMClient(["first", "second"])
    assert client.complete("s", "u") == "first"
    assert client.complete("s", "u") == "second"


def test_scripted_client_raises_when_exhausted():
    client = ScriptedLLMClient(["only one"])
    client.complete("s", "u")
    with pytest.raises(IndexError):
        client.complete("s", "u")
