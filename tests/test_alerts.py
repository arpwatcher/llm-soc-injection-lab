import pytest

from soclab.alerts import SEVERITIES, Alert, generate_clean_alerts


def test_generate_clean_alerts_returns_multiple_alerts():
    alerts = generate_clean_alerts()
    assert len(alerts) >= 5


def test_clean_alerts_have_no_injection():
    for alert in generate_clean_alerts():
        assert alert.injected_technique is None


def test_clean_alerts_cover_all_ground_truth_actions():
    actions = {alert.ground_truth_action for alert in generate_clean_alerts()}
    assert actions == {"escalate", "investigate", "dismiss"}


def test_alert_ids_are_unique():
    ids = [alert.id for alert in generate_clean_alerts()]
    assert len(ids) == len(set(ids))


def test_clean_alerts_have_at_least_two_of_each_ground_truth_action():
    alerts = generate_clean_alerts()
    for action in ("escalate", "investigate", "dismiss"):
        count = sum(1 for a in alerts if a.ground_truth_action == action)
        assert count >= 2, f"only {count} alerts with ground_truth_action={action}"


def test_clean_alerts_cover_varied_sources():
    sources = {alert.source for alert in generate_clean_alerts()}
    assert len(sources) >= 6


def test_alert_rejects_unknown_action():
    with pytest.raises(ValueError):
        Alert(
            id="X",
            source="test",
            severity="low",
            description="d",
            raw_log="l",
            ground_truth_action="ignore_and_approve",
        )


def test_alert_rejects_unknown_severity():
    """severity feeds severity_weighted_hijack_rate's weight lookup - an
    unvalidated typo (e.g. "Critical" capitalized, or "info") would
    surface there as a bare KeyError instead of a clear error at the
    point the bad alert was actually constructed."""
    with pytest.raises(ValueError):
        Alert(
            id="X",
            source="test",
            severity="urgent",
            description="d",
            raw_log="l",
            ground_truth_action="dismiss",
        )


def test_clean_alerts_use_only_known_severities():
    for alert in generate_clean_alerts():
        assert alert.severity in SEVERITIES


def test_alert_rejects_unknown_injected_target_action():
    """injected_target_action feeds classify_outcome's hijacked check
    directly - an unvalidated typo (e.g. "escalte") would silently make
    that technique's hijack rate always read 0%, with no error anywhere
    to point at the actual mistake, instead of failing at construction
    time the way ground_truth_action and severity already do."""
    with pytest.raises(ValueError):
        Alert(
            id="X",
            source="test",
            severity="low",
            description="d",
            raw_log="l",
            ground_truth_action="escalate",
            injected_technique="some_technique",
            injected_target_action="escalte",
        )


def test_alert_allows_none_injected_target_action():
    # clean alerts (no injection) legitimately have no target action at all
    alert = Alert(
        id="X", source="test", severity="low", description="d", raw_log="l",
        ground_truth_action="dismiss",
    )
    assert alert.injected_target_action is None
