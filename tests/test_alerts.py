import pytest

from soclab.alerts import Alert, generate_clean_alerts


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
