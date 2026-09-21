import json

from soclab.report import (
    combined_rate_by_defense,
    rate_by_defense,
    render_combined_json_report,
    render_combined_report,
    render_json_report,
    render_markdown_report,
)


def _sample_aggregate():
    return {
        "direct_override": {"total": 5, "hijacked": 5, "resisted": 0, "other": 0, "hijack_rate": 1.0},
        "unicode_homoglyph": {"total": 5, "hijacked": 0, "resisted": 5, "other": 0, "hijack_rate": 0.0},
    }


def test_render_includes_client_name():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "fake-vulnerable" in report


def test_render_includes_a_section_per_defense():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate(), "sandwich": _sample_aggregate()})
    assert "defense: none" in report
    assert "defense: sandwich" in report


def test_render_formats_hijack_rate_as_percentage():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "100%" in report
    assert "0%" in report


def test_render_is_valid_markdown_table_shape():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "| technique | hijacked | resisted | other | hijack rate |" in report
    assert "|---|---|---|---|---|" in report


def test_render_includes_overall_hijack_rate():
    # 5 hijacked out of 10 total across both techniques in _sample_aggregate()
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "overall hijack rate: 50%" in report


def test_render_defaults_to_dismiss_direction():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "direction: dismiss" in report


def test_render_notes_escalate_direction_when_given():
    report = render_markdown_report("fake-escalation-vulnerable", {"none": _sample_aggregate()}, direction="escalate")
    assert "direction: escalate" in report


def test_render_includes_summary_table_when_multiple_defenses():
    report = render_markdown_report(
        "fake-vulnerable", {"none": _sample_aggregate(), "sandwich": _sample_aggregate()}
    )
    assert "summary: overall hijack rate by defense" in report
    assert "| defense | hijack rate |" in report
    assert "| none | 50% |" in report
    assert "| sandwich | 50% |" in report


def test_render_omits_summary_table_for_a_single_defense():
    """with only one defense a summary table would just repeat the
    "overall hijack rate" line already shown below it - skip it."""
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "summary:" not in report


def test_rate_by_defense_computes_overall_rate_per_defense():
    rates = rate_by_defense({"none": _sample_aggregate(), "sandwich": _sample_aggregate()})
    assert rates == {"none": 0.5, "sandwich": 0.5}


def test_combined_report_includes_both_directions():
    by_direction = {
        "dismiss": {"none": _sample_aggregate(), "sandwich": _sample_aggregate()},
        "escalate": {"none": _sample_aggregate(), "sandwich": _sample_aggregate()},
    }
    report = render_combined_report("fake-vulnerable", by_direction)
    assert "direction: dismiss" in report
    assert "direction: escalate" in report
    assert "defense: none" in report
    assert "defense: sandwich" in report


def test_combined_report_includes_client_name_and_tables():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    report = render_combined_report("fake-stubborn", by_direction)
    assert "fake-stubborn" in report
    assert "| technique | hijacked | resisted | other | hijack rate |" in report
    assert "100%" in report
    assert "0%" in report


def test_combined_report_includes_summary_section():
    by_direction = {"dismiss": {"none": _sample_aggregate()}, "escalate": {"none": _sample_aggregate()}}
    report = render_combined_report("fake-vulnerable", by_direction)
    assert "summary: overall hijack rate by defense" in report
    assert "| defense | hijack rate |" in report


def test_combined_rate_by_defense_sums_counts_across_directions():
    # 5/10 in dismiss + 5/10 in escalate = 10/20 = 50%, same as a single direction here
    by_direction = {"dismiss": {"none": _sample_aggregate()}, "escalate": {"none": _sample_aggregate()}}
    rates = combined_rate_by_defense(by_direction)
    assert rates == {"none": 0.5}


def test_combined_rate_by_defense_reflects_a_defense_that_only_helps_in_one_direction():
    fully_hijacked = {"direct_override": {"total": 5, "hijacked": 5, "resisted": 0, "other": 0, "hijack_rate": 1.0}}
    fully_resisted = {"direct_override": {"total": 5, "hijacked": 0, "resisted": 5, "other": 0, "hijack_rate": 0.0}}
    by_direction = {"dismiss": {"sandwich": fully_hijacked}, "escalate": {"sandwich": fully_resisted}}
    rates = combined_rate_by_defense(by_direction)
    assert rates == {"sandwich": 0.5}


def test_render_json_report_is_valid_json_with_expected_shape():
    report = render_json_report(
        "fake-vulnerable", {"none": _sample_aggregate(), "sandwich": _sample_aggregate()}, direction="escalate"
    )
    parsed = json.loads(report)
    assert parsed["client"] == "fake-vulnerable"
    assert parsed["direction"] == "escalate"
    assert parsed["summary_by_defense"] == {"none": 0.5, "sandwich": 0.5}
    assert parsed["per_defense"]["none"]["direct_override"]["hijack_rate"] == 1.0


def test_render_json_report_defaults_to_dismiss_direction():
    report = render_json_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert json.loads(report)["direction"] == "dismiss"


def test_render_combined_json_report_is_valid_json_with_expected_shape():
    by_direction = {"dismiss": {"none": _sample_aggregate()}, "escalate": {"none": _sample_aggregate()}}
    report = render_combined_json_report("fake-stubborn", by_direction)
    parsed = json.loads(report)
    assert parsed["client"] == "fake-stubborn"
    assert parsed["summary_by_defense"] == {"none": 0.5}
    assert set(parsed["by_direction"]) == {"dismiss", "escalate"}
    assert parsed["by_direction"]["dismiss"]["none"]["direct_override"]["hijacked"] == 5


def test_render_markdown_report_includes_severity_weighted_rate_when_given():
    report = render_markdown_report(
        "fake-vulnerable", {"none": _sample_aggregate()}, severity_weighted_by_defense={"none": 0.75},
    )
    assert "severity-weighted hijack rate: 75%" in report


def test_render_markdown_report_omits_severity_weighted_rate_when_not_given():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "severity-weighted hijack rate" not in report


def test_render_json_report_includes_severity_weighted_rate_when_given():
    report = render_json_report(
        "fake-vulnerable", {"none": _sample_aggregate()}, severity_weighted_by_defense={"none": 0.75},
    )
    assert json.loads(report)["severity_weighted_by_defense"] == {"none": 0.75}


def test_render_combined_report_includes_severity_weighted_rate_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate()}, "escalate": {"none": _sample_aggregate()}}
    severity_weighted_by_direction = {"dismiss": {"none": 0.9}, "escalate": {"none": 0.1}}
    report = render_combined_report("fake-stubborn", by_direction, severity_weighted_by_direction)
    assert "severity-weighted hijack rate: 90%" in report
    assert "severity-weighted hijack rate: 10%" in report


def test_render_combined_json_report_includes_severity_weighted_rate_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    severity_weighted_by_direction = {"dismiss": {"none": 0.9}}
    report = render_combined_json_report("fake-stubborn", by_direction, severity_weighted_by_direction)
    assert json.loads(report)["severity_weighted_by_direction"] == {"dismiss": {"none": 0.9}}


def test_render_markdown_report_includes_confidence_interval_when_given():
    report = render_markdown_report(
        "fake-vulnerable", {"none": _sample_aggregate()}, confidence_interval_by_defense={"none": (0.4, 0.6)},
    )
    assert "95% confidence interval: 40%-60%" in report


def test_render_markdown_report_omits_confidence_interval_when_not_given():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "confidence interval" not in report


def test_render_json_report_includes_confidence_interval_when_given():
    report = render_json_report(
        "fake-vulnerable", {"none": _sample_aggregate()}, confidence_interval_by_defense={"none": (0.4, 0.6)},
    )
    assert json.loads(report)["confidence_interval_by_defense"] == {"none": [0.4, 0.6]}


def test_render_combined_report_includes_confidence_interval_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    confidence_interval_by_direction = {"dismiss": {"none": (0.2, 0.8)}}
    report = render_combined_report("fake-stubborn", by_direction, confidence_interval_by_direction=confidence_interval_by_direction)
    assert "95% confidence interval: 20%-80%" in report


def test_render_combined_json_report_includes_confidence_interval_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    confidence_interval_by_direction = {"dismiss": {"none": (0.2, 0.8)}}
    report = render_combined_json_report(
        "fake-stubborn", by_direction, confidence_interval_by_direction=confidence_interval_by_direction
    )
    assert json.loads(report)["confidence_interval_by_direction"] == {"dismiss": {"none": [0.2, 0.8]}}
