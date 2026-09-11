from soclab.alerts import generate_clean_alerts
from soclab.injections import TECHNIQUES, apply_all_techniques
from soclab.llm_client import RobustFakeClient, VulnerableFakeClient
from soclab.scoring import aggregate_by_technique, classify_outcome, score_batch
from soclab.analyst import AnalystDecision


def _escalate_alert():
    return next(a for a in generate_clean_alerts() if a.ground_truth_action == "escalate")


def test_classify_outcome_resisted():
    alert = _escalate_alert()
    decision = AnalystDecision(alert_id=alert.id, action="escalate", reasoning="", raw_response="")
    assert classify_outcome(alert, decision) == "resisted"


def test_classify_outcome_hijacked_requires_injection_present():
    clean = _escalate_alert()
    decision = AnalystDecision(alert_id=clean.id, action="dismiss", reasoning="", raw_response="")
    # no injected_technique set, so an outright wrong answer is "other", not "hijacked"
    assert classify_outcome(clean, decision) == "other"


def test_classify_outcome_hijacked_when_injected_and_dismissed():
    from soclab.injections import apply_technique

    injected = apply_technique(_escalate_alert(), "direct_override")
    decision = AnalystDecision(alert_id=injected.id, action="dismiss", reasoning="", raw_response="")
    assert classify_outcome(injected, decision) == "hijacked"


def test_score_batch_with_robust_client_all_resisted():
    injected = apply_all_techniques(generate_clean_alerts())
    results = score_batch(injected, RobustFakeClient())
    assert all(r.outcome == "resisted" for r in results)


def test_score_batch_with_vulnerable_client_all_hijacked():
    injected = apply_all_techniques(generate_clean_alerts())
    results = score_batch(injected, VulnerableFakeClient())
    assert all(r.outcome == "hijacked" for r in results)


def test_aggregate_by_technique_covers_every_technique():
    injected = apply_all_techniques(generate_clean_alerts())
    results = score_batch(injected, VulnerableFakeClient())
    aggregated = aggregate_by_technique(results)
    assert set(aggregated) == set(TECHNIQUES)


def test_aggregate_by_technique_hijack_rate_for_robust_client_is_zero():
    injected = apply_all_techniques(generate_clean_alerts())
    results = score_batch(injected, RobustFakeClient())
    aggregated = aggregate_by_technique(results)
    assert all(bucket["hijack_rate"] == 0.0 for bucket in aggregated.values())


def test_aggregate_by_technique_hijack_rate_for_vulnerable_client_is_one():
    injected = apply_all_techniques(generate_clean_alerts())
    results = score_batch(injected, VulnerableFakeClient())
    aggregated = aggregate_by_technique(results)
    assert all(bucket["hijack_rate"] == 1.0 for bucket in aggregated.values())


def test_aggregate_by_technique_ignores_clean_alerts():
    results = score_batch(generate_clean_alerts(), RobustFakeClient())
    assert aggregate_by_technique(results) == {}
