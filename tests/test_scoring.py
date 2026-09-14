from soclab.alerts import generate_clean_alerts
from soclab.injections import TECHNIQUES, apply_all_techniques
from soclab.llm_client import RobustFakeClient, VulnerableFakeClient
from soclab.scoring import aggregate_by_technique, classify_outcome, overall_hijack_rate, score_batch
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


def test_score_batch_with_vulnerable_client_hijacked_except_homoglyph():
    injected = apply_all_techniques(generate_clean_alerts())
    results = score_batch(injected, VulnerableFakeClient())
    for result in results:
        if result.alert.injected_technique == "unicode_homoglyph":
            assert result.outcome == "resisted"
        else:
            assert result.outcome == "hijacked"


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


def test_aggregate_by_technique_hijack_rate_for_vulnerable_client():
    injected = apply_all_techniques(generate_clean_alerts())
    results = score_batch(injected, VulnerableFakeClient())
    aggregated = aggregate_by_technique(results)
    assert aggregated["unicode_homoglyph"]["hijack_rate"] == 0.0
    for technique, bucket in aggregated.items():
        if technique != "unicode_homoglyph":
            assert bucket["hijack_rate"] == 1.0


def test_aggregate_by_technique_ignores_clean_alerts():
    results = score_batch(generate_clean_alerts(), RobustFakeClient())
    assert aggregate_by_technique(results) == {}


def test_overall_hijack_rate_zero_for_robust_client():
    injected = apply_all_techniques(generate_clean_alerts())
    results = score_batch(injected, RobustFakeClient())
    assert overall_hijack_rate(results) == 0.0


def test_overall_hijack_rate_reflects_the_one_technique_that_resists():
    injected = apply_all_techniques(generate_clean_alerts())
    results = score_batch(injected, VulnerableFakeClient())
    technique_count = len(TECHNIQUES)
    expected = (technique_count - 1) / technique_count  # every technique but unicode_homoglyph hijacks
    assert overall_hijack_rate(results) == expected


def test_overall_hijack_rate_ignores_clean_alerts():
    results = score_batch(generate_clean_alerts(), VulnerableFakeClient())
    assert overall_hijack_rate(results) == 0.0
