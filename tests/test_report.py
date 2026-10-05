import csv
import io
import json

from soclab.alerts import Alert
from soclab.analyst import AnalystDecision
from soclab.report import (
    combined_rate_by_defense,
    rate_by_defense,
    render_combined_csv_report,
    render_combined_json_report,
    render_combined_report,
    render_combined_transcript,
    render_csv_report,
    render_json_report,
    render_leaderboard_csv_report,
    render_leaderboard_json_report,
    render_leaderboard_report,
    render_leaderboard_transcript,
    render_markdown_report,
    render_matrix_csv_report,
    render_matrix_json_report,
    render_matrix_report,
    render_technique_leaderboard_csv_report,
    render_technique_leaderboard_json_report,
    render_technique_leaderboard_report,
    render_transcript,
)
from soclab.scoring import ScoredResult


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


def test_render_csv_report_is_valid_csv_with_expected_shape():
    report = render_csv_report("fake-vulnerable", {"none": _sample_aggregate()}, direction="escalate")
    rows = list(csv.DictReader(io.StringIO(report)))
    assert len(rows) == 2  # one per technique in _sample_aggregate()
    assert rows[0]["client"] == "fake-vulnerable"
    assert rows[0]["direction"] == "escalate"
    assert rows[0]["defense"] == "none"
    assert rows[0]["technique"] == "direct_override"
    assert rows[0]["hijacked"] == "5"
    assert rows[0]["hijack_rate"] == "1.0"


def test_render_csv_report_defaults_to_dismiss_direction():
    report = render_csv_report("fake-vulnerable", {"none": _sample_aggregate()})
    rows = list(csv.DictReader(io.StringIO(report)))
    assert rows[0]["direction"] == "dismiss"


def test_render_csv_report_covers_multiple_defenses():
    report = render_csv_report("fake-vulnerable", {"none": _sample_aggregate(), "sandwich": _sample_aggregate()})
    rows = list(csv.DictReader(io.StringIO(report)))
    assert len(rows) == 4  # 2 defenses x 2 techniques
    assert {row["defense"] for row in rows} == {"none", "sandwich"}


def test_render_combined_csv_report_covers_every_direction():
    by_direction = {"dismiss": {"none": _sample_aggregate()}, "escalate": {"none": _sample_aggregate()}}
    report = render_combined_csv_report("fake-stubborn", by_direction)
    rows = list(csv.DictReader(io.StringIO(report)))
    assert len(rows) == 4  # 2 directions x 2 techniques
    assert {row["direction"] for row in rows} == {"dismiss", "escalate"}
    assert all(row["client"] == "fake-stubborn" for row in rows)


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


def _sample_severity_breakdown():
    return {
        "critical": {"total": 2, "hijacked": 1, "resisted": 1, "other": 0, "hijack_rate": 0.5,
                     "ci_low": 0.09, "ci_high": 0.91},
        "low": {"total": 3, "hijacked": 0, "resisted": 3, "other": 0, "hijack_rate": 0.0,
                "ci_low": 0.0, "ci_high": 0.56},
    }


def test_render_markdown_report_includes_severity_breakdown_when_given():
    report = render_markdown_report(
        "fake-vulnerable", {"none": _sample_aggregate()},
        severity_breakdown_by_defense={"none": _sample_severity_breakdown()},
    )
    assert "| severity | hijacked | resisted | other | hijack rate |" in report
    assert "| critical | 1 | 1 | 0 | 50% |" in report
    assert "| low | 0 | 3 | 0 | 0% |" in report


def test_render_markdown_report_omits_severity_breakdown_when_not_given():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "severity | hijacked" not in report


def test_render_json_report_includes_severity_breakdown_when_given():
    report = render_json_report(
        "fake-vulnerable", {"none": _sample_aggregate()},
        severity_breakdown_by_defense={"none": _sample_severity_breakdown()},
    )
    assert json.loads(report)["severity_breakdown_by_defense"] == {"none": _sample_severity_breakdown()}


def test_render_combined_report_includes_severity_breakdown_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    severity_breakdown_by_direction = {"dismiss": {"none": _sample_severity_breakdown()}}
    report = render_combined_report(
        "fake-stubborn", by_direction, severity_breakdown_by_direction=severity_breakdown_by_direction,
    )
    assert "| severity | hijacked | resisted | other | hijack rate |" in report
    assert "| critical | 1 | 1 | 0 | 50% |" in report


def test_render_combined_json_report_includes_severity_breakdown_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    severity_breakdown_by_direction = {"dismiss": {"none": _sample_severity_breakdown()}}
    report = render_combined_json_report(
        "fake-stubborn", by_direction, severity_breakdown_by_direction=severity_breakdown_by_direction,
    )
    assert json.loads(report)["severity_breakdown_by_direction"] == severity_breakdown_by_direction


def test_render_markdown_report_includes_severity_filter_when_given():
    report = render_markdown_report(
        "fake-vulnerable", {"none": _sample_aggregate()}, severity_filter=["critical", "high"],
    )
    assert "severity filter: critical, high" in report


def test_render_markdown_report_omits_severity_filter_when_not_given():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "severity filter" not in report


def test_render_json_report_includes_severity_filter_when_given():
    report = render_json_report(
        "fake-vulnerable", {"none": _sample_aggregate()}, severity_filter=["critical", "high"],
    )
    assert json.loads(report)["severity_filter"] == ["critical", "high"]


def test_render_json_report_severity_filter_defaults_to_none():
    report = render_json_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert json.loads(report)["severity_filter"] is None


def test_render_combined_report_includes_severity_filter_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    report = render_combined_report("fake-stubborn", by_direction, severity_filter=["low"])
    assert "severity filter: low" in report


def test_render_combined_json_report_includes_severity_filter_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    report = render_combined_json_report("fake-stubborn", by_direction, severity_filter=["low"])
    assert json.loads(report)["severity_filter"] == ["low"]


def test_render_markdown_report_includes_significance_when_given():
    # "none" itself never gets an entry - nothing to compare it against itself.
    report = render_markdown_report(
        "fake-vulnerable", {"none": _sample_aggregate(), "sandwich": _sample_aggregate()},
        significance_by_defense={"sandwich": (2.5, 0.0124)},
    )
    assert "## defense: none" in report
    none_section = report.split("## defense: none")[1].split("## defense: sandwich")[0]
    assert "significance vs none" not in none_section
    sandwich_section = report.split("## defense: sandwich")[1]
    assert "significance vs none (two-proportion z-test): p=0.0124 (significant at p<0.05)" in sandwich_section


def test_render_markdown_report_omits_significance_when_not_given():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "significance" not in report


def test_render_json_report_includes_significance_when_given():
    report = render_json_report(
        "fake-vulnerable", {"none": _sample_aggregate()}, significance_by_defense={"sandwich": (2.5, 0.0124)},
    )
    assert json.loads(report)["significance_vs_none_by_defense"] == {"sandwich": [2.5, 0.0124]}


def test_render_combined_report_includes_significance_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate(), "sandwich": _sample_aggregate()}}
    significance_by_direction = {"dismiss": {"sandwich": (2.5, 0.0124)}}
    report = render_combined_report("fake-stubborn", by_direction, significance_by_direction=significance_by_direction)
    assert "significance vs none (two-proportion z-test): p=0.0124 (significant at p<0.05)" in report


def test_render_combined_json_report_includes_significance_when_given():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    significance_by_direction = {"dismiss": {"sandwich": (2.5, 0.0124)}}
    report = render_combined_json_report(
        "fake-stubborn", by_direction, significance_by_direction=significance_by_direction,
    )
    assert json.loads(report)["significance_vs_none_by_direction"] == {"dismiss": {"sandwich": [2.5, 0.0124]}}


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


def _scored_result(outcome: str) -> ScoredResult:
    alert = Alert(
        id="A001", source="edr", severity="critical", description="d", raw_log="l",
        ground_truth_action="escalate", injected_technique="direct_override", injected_target_action="dismiss",
    )
    action = "dismiss" if outcome == "hijacked" else "escalate"
    decision = AnalystDecision(alert_id="A001", action=action, reasoning="because of the log note", raw_response="")
    return ScoredResult(alert=alert, decision=decision, outcome=outcome)


def test_render_transcript_is_valid_json_with_expected_shape():
    results = [_scored_result("hijacked"), _scored_result("resisted")]
    parsed = json.loads(render_transcript({"none": results}, direction="escalate"))
    assert len(parsed) == 2
    assert parsed[0]["alert_id"] == "A001"
    assert parsed[0]["technique"] == "direct_override"
    assert parsed[0]["severity"] == "critical"
    assert parsed[0]["ground_truth_action"] == "escalate"
    assert parsed[0]["defense"] == "none"
    assert parsed[0]["direction"] == "escalate"
    assert parsed[0]["action"] == "dismiss"
    assert parsed[0]["outcome"] == "hijacked"
    assert parsed[0]["reasoning"] == "because of the log note"
    assert parsed[0]["parse_error"] is False


def test_render_transcript_includes_raw_response_for_parse_errors():
    """reasoning is empty when parse_error is True - there was nothing
    valid to extract it from - so raw_response is the only place a
    parse failure can actually be debugged from the transcript alone."""
    alert = Alert(
        id="A002", source="edr", severity="low", description="d", raw_log="l",
        ground_truth_action="dismiss", injected_technique="direct_override", injected_target_action="dismiss",
    )
    decision = AnalystDecision(
        alert_id="A002", action="unknown", reasoning="", raw_response="I refuse to answer.", parse_error=True,
    )
    result = ScoredResult(alert=alert, decision=decision, outcome="other")
    parsed = json.loads(render_transcript({"none": [result]}))
    assert parsed[0]["parse_error"] is True
    assert parsed[0]["reasoning"] == ""
    assert parsed[0]["raw_response"] == "I refuse to answer."


def test_render_transcript_defaults_to_dismiss_direction():
    results = [_scored_result("hijacked")]
    parsed = json.loads(render_transcript({"none": results}))
    assert parsed[0]["direction"] == "dismiss"


def test_render_transcript_covers_multiple_defenses():
    results = [_scored_result("hijacked")]
    parsed = json.loads(render_transcript({"none": results, "sandwich": results}))
    assert {e["defense"] for e in parsed} == {"none", "sandwich"}


def test_render_transcript_empty_results():
    assert render_transcript({}) == "[]"
    assert render_transcript({"none": []}) == "[]"


def test_render_combined_transcript_covers_every_direction():
    results = [_scored_result("hijacked")]
    by_direction = {"dismiss": {"none": results}, "escalate": {"none": results}}
    parsed = json.loads(render_combined_transcript(by_direction))
    assert len(parsed) == 2
    assert {e["direction"] for e in parsed} == {"dismiss", "escalate"}


def _sample_leaderboard_rows():
    return [
        {"client": "fake-robust", "hijack_rate": 0.0, "ci_low": 0.0, "ci_high": 0.09,
         "severity_weighted_hijack_rate": 0.0, "clean_accuracy": 1.0},
        {"client": "fake-vulnerable", "hijack_rate": 0.88, "ci_low": 0.74, "ci_high": 0.95,
         "severity_weighted_hijack_rate": 0.88, "clean_accuracy": 1.0},
    ]


def test_render_leaderboard_report_lists_every_client_in_order():
    report = render_leaderboard_report(_sample_leaderboard_rows(), direction="dismiss", defense="none")
    assert "direction: dismiss, defense: none" in report
    assert report.index("fake-robust") < report.index("fake-vulnerable")
    assert "0%" in report
    assert "88%" in report


def test_render_leaderboard_json_report_is_valid_json_with_expected_shape():
    report = render_leaderboard_json_report(_sample_leaderboard_rows(), direction="escalate", defense="strict")
    parsed = json.loads(report)
    assert parsed["direction"] == "escalate"
    assert parsed["defense"] == "strict"
    assert [row["client"] for row in parsed["clients"]] == ["fake-robust", "fake-vulnerable"]
    assert parsed["pairwise_significance"] is None
    assert parsed["severity_filter"] is None


def test_render_leaderboard_report_includes_severity_filter_when_given():
    report = render_leaderboard_report(
        _sample_leaderboard_rows(), direction="dismiss", defense="none", severity_filter=["critical", "high"],
    )
    assert "severity filter: critical, high" in report


def test_render_leaderboard_json_report_includes_severity_filter_when_given():
    report = render_leaderboard_json_report(
        _sample_leaderboard_rows(), direction="dismiss", defense="none", severity_filter=["critical"],
    )
    assert json.loads(report)["severity_filter"] == ["critical"]


def test_render_leaderboard_report_includes_pairwise_significance_when_given():
    pairwise = {"client_a": "fake-robust", "client_b": "fake-vulnerable", "z": -7.9, "p_value": 0.0001}
    report = render_leaderboard_report(
        _sample_leaderboard_rows(), direction="dismiss", defense="none", pairwise_significance=pairwise,
    )
    assert "fake-robust vs fake-vulnerable (two-proportion z-test): p=0.0001 (significant at p<0.05)" in report


def test_render_leaderboard_report_omits_pairwise_significance_when_not_given():
    report = render_leaderboard_report(_sample_leaderboard_rows(), direction="dismiss", defense="none")
    assert "two-proportion z-test" not in report


def test_render_leaderboard_json_report_includes_pairwise_significance_when_given():
    pairwise = {"client_a": "fake-robust", "client_b": "fake-vulnerable", "z": -7.9, "p_value": 0.0001}
    report = render_leaderboard_json_report(
        _sample_leaderboard_rows(), direction="dismiss", defense="none", pairwise_significance=pairwise,
    )
    assert json.loads(report)["pairwise_significance"] == pairwise


def test_render_leaderboard_csv_report_is_valid_csv_with_expected_shape():
    report = render_leaderboard_csv_report(_sample_leaderboard_rows(), direction="dismiss", defense="both")
    rows = list(csv.DictReader(io.StringIO(report)))
    assert len(rows) == 2
    assert rows[0]["client"] == "fake-robust"
    assert rows[0]["direction"] == "dismiss"
    assert rows[0]["defense"] == "both"
    assert rows[1]["hijack_rate"] == "0.88"
    assert rows[0]["clean_accuracy"] == "1.0"


def test_render_leaderboard_transcript_is_valid_json_keyed_by_client():
    results = [_scored_result("hijacked")]
    by_client = {"fake-robust": results, "fake-vulnerable": results}
    parsed = json.loads(render_leaderboard_transcript(by_client, direction="escalate", defense="strict"))
    assert len(parsed) == 2
    assert {e["client"] for e in parsed} == {"fake-robust", "fake-vulnerable"}
    assert all(e["direction"] == "escalate" and e["defense"] == "strict" for e in parsed)


def test_render_leaderboard_transcript_defaults_to_dismiss_and_none():
    results = [_scored_result("hijacked")]
    parsed = json.loads(render_leaderboard_transcript({"fake-robust": results}))
    assert parsed[0]["direction"] == "dismiss"
    assert parsed[0]["defense"] == "none"


def test_render_leaderboard_transcript_empty_by_client():
    assert render_leaderboard_transcript({}) == "[]"


def _sample_technique_leaderboard_rows():
    return [
        ("direct_override", {"total": 10, "hijacked": 8, "resisted": 2, "other": 0,
                              "hijack_rate": 0.8, "ci_low": 0.49, "ci_high": 0.94}),
        ("unicode_homoglyph", {"total": 10, "hijacked": 1, "resisted": 9, "other": 0,
                                "hijack_rate": 0.1, "ci_low": 0.02, "ci_high": 0.40}),
    ]


def test_render_technique_leaderboard_report_lists_every_technique_in_order():
    report = render_technique_leaderboard_report(
        _sample_technique_leaderboard_rows(), direction="dismiss", defense="none", client_count=5,
    )
    assert "direction: dismiss, defense: none, across 5 client(s)" in report
    assert report.index("direct_override") < report.index("unicode_homoglyph")
    assert "80%" in report
    assert "10%" in report


def test_render_technique_leaderboard_json_report_is_valid_json_with_expected_shape():
    report = render_technique_leaderboard_json_report(
        _sample_technique_leaderboard_rows(), direction="escalate", defense="strict", client_count=3,
    )
    parsed = json.loads(report)
    assert parsed["direction"] == "escalate"
    assert parsed["defense"] == "strict"
    assert parsed["client_count"] == 3
    assert [row["technique"] for row in parsed["techniques"]] == ["direct_override", "unicode_homoglyph"]
    assert parsed["techniques"][0]["hijack_rate"] == 0.8
    assert parsed["severity_filter"] is None


def test_render_technique_leaderboard_report_includes_severity_filter_when_given():
    report = render_technique_leaderboard_report(
        _sample_technique_leaderboard_rows(), direction="dismiss", defense="none", client_count=5,
        severity_filter=["low"],
    )
    assert "severity filter: low" in report


def test_render_technique_leaderboard_json_report_includes_severity_filter_when_given():
    report = render_technique_leaderboard_json_report(
        _sample_technique_leaderboard_rows(), direction="dismiss", defense="none", client_count=5,
        severity_filter=["low"],
    )
    assert json.loads(report)["severity_filter"] == ["low"]


def test_render_technique_leaderboard_csv_report_is_valid_csv_with_expected_shape():
    report = render_technique_leaderboard_csv_report(
        _sample_technique_leaderboard_rows(), direction="dismiss", defense="both",
    )
    rows = list(csv.DictReader(io.StringIO(report)))
    assert len(rows) == 2
    assert rows[0]["technique"] == "direct_override"
    assert rows[0]["direction"] == "dismiss"
    assert rows[0]["defense"] == "both"
    assert rows[1]["hijack_rate"] == "0.1"


def test_render_technique_leaderboard_report_includes_pairwise_significance_when_given():
    pairwise = {"technique_a": "direct_override", "technique_b": "unicode_homoglyph", "z": 4.3, "p_value": 0.0001}
    report = render_technique_leaderboard_report(
        _sample_technique_leaderboard_rows(), direction="dismiss", defense="none", client_count=5,
        pairwise_significance=pairwise,
    )
    assert "direct_override vs unicode_homoglyph (two-proportion z-test): p=0.0001 (significant at p<0.05)" in report


def test_render_technique_leaderboard_report_omits_pairwise_significance_when_not_given():
    report = render_technique_leaderboard_report(
        _sample_technique_leaderboard_rows(), direction="dismiss", defense="none", client_count=5,
    )
    assert "two-proportion z-test" not in report


def test_render_technique_leaderboard_json_report_includes_pairwise_significance_when_given():
    pairwise = {"technique_a": "direct_override", "technique_b": "unicode_homoglyph", "z": 4.3, "p_value": 0.0001}
    report = render_technique_leaderboard_json_report(
        _sample_technique_leaderboard_rows(), direction="dismiss", defense="none", client_count=5,
        pairwise_significance=pairwise,
    )
    assert json.loads(report)["pairwise_significance"] == pairwise


def _sample_matrix_rows():
    return [
        {"client": "fake-robust", "rates": {"direct_override": 0.0, "unicode_homoglyph": 0.0}, "average": 0.0},
        {"client": "fake-vulnerable", "rates": {"direct_override": 1.0, "unicode_homoglyph": 0.1}, "average": 0.55},
    ]


def test_render_matrix_report_is_a_markdown_table_with_a_column_per_technique():
    report = render_matrix_report(
        _sample_matrix_rows(), ["direct_override", "unicode_homoglyph"], direction="dismiss", defense="none",
    )
    assert "direction: dismiss, defense: none" in report
    header, separator, robust_row, vulnerable_row = (
        line for line in report.splitlines() if line.startswith("|")
    )
    assert header == "| client | direct_override | unicode_homoglyph | average |"
    assert robust_row == "| fake-robust | 0% | 0% | 0% |"
    assert vulnerable_row == "| fake-vulnerable | 100% | 10% | 55% |"


def test_render_matrix_json_report_is_valid_json_with_expected_shape():
    report = render_matrix_json_report(
        _sample_matrix_rows(), ["direct_override", "unicode_homoglyph"], direction="escalate", defense="strict",
    )
    parsed = json.loads(report)
    assert parsed["direction"] == "escalate"
    assert parsed["defense"] == "strict"
    assert parsed["techniques"] == ["direct_override", "unicode_homoglyph"]
    assert parsed["clients"] == _sample_matrix_rows()
    assert parsed["severity_filter"] is None


def test_render_matrix_report_includes_severity_filter_when_given():
    report = render_matrix_report(
        _sample_matrix_rows(), ["direct_override", "unicode_homoglyph"], direction="dismiss", defense="none",
        severity_filter=["critical", "high"],
    )
    assert "severity filter: critical, high" in report


def test_render_matrix_json_report_includes_severity_filter_when_given():
    report = render_matrix_json_report(
        _sample_matrix_rows(), ["direct_override", "unicode_homoglyph"], direction="dismiss", defense="none",
        severity_filter=["critical"],
    )
    assert json.loads(report)["severity_filter"] == ["critical"]


def test_render_matrix_csv_report_is_valid_csv_with_one_row_per_client_and_one_column_per_technique():
    report = render_matrix_csv_report(
        _sample_matrix_rows(), ["direct_override", "unicode_homoglyph"], direction="dismiss", defense="both",
    )
    rows = list(csv.DictReader(io.StringIO(report)))
    assert len(rows) == 2
    assert rows[0]["client"] == "fake-robust"
    assert rows[0]["direction"] == "dismiss"
    assert rows[0]["defense"] == "both"
    assert rows[0]["direct_override"] == "0.0"
    assert rows[0]["average"] == "0.0"
    assert rows[1]["client"] == "fake-vulnerable"
    assert rows[1]["unicode_homoglyph"] == "0.1"
    assert rows[1]["average"] == "0.55"
