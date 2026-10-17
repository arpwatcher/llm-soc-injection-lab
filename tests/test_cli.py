import csv
import io
import json
import subprocess
import sys

import pytest
import requests

import soclab.cli as cli_module
from soclab.alerts import Alert
from soclab.analyst import AnalystDecision
from soclab.cli import FAKE_CLIENT_NAMES, _report_format, build_client, main
from soclab.injections import ESCALATION_TECHNIQUES
from soclab.llm_client import RobustFakeClient, ScriptedLLMClient, VulnerableFakeClient
from soclab.scoring import ScoredResult


def test_module_invocation_as_real_subprocess():
    """every other test calls main() in-process - none of them actually
    exercise `python -m soclab.cli`, the way a real user runs this, which
    means the `if __name__ == "__main__":` guard itself was never proven
    to work. this runs it for real, out of process."""
    result = subprocess.run(
        [sys.executable, "-m", "soclab.cli", "list-techniques"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0
    assert "direct_override" in result.stdout


def test_run_help_documents_client_and_defense_choices():
    """--client and --defense used to have no help text at all while
    --direction/--model/--host/--report did - an unlabeled list of nine
    fake-* names plus "ollama" isn't self-explanatory to someone running
    this for the first time."""
    result = subprocess.run(
        [sys.executable, "-m", "soclab.cli", "run", "--help"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0
    assert "which client to test" in result.stdout
    assert "prompt defense to apply" in result.stdout


def test_compare_help_documents_direction_choice():
    """compare's --direction had no help text at all, unlike run's identical
    flag - the same {dismiss,escalate} choice left unexplained here too."""
    result = subprocess.run(
        [sys.executable, "-m", "soclab.cli", "compare", "--help"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0
    assert "which attacker goal to test" in result.stdout


def test_run_with_fake_robust_client(capsys):
    exit_code = main(["run", "--client", "fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "clean alerts:" in out
    assert "direct_override" in out
    # robust client should never be hijacked, by anything
    for line in out.splitlines():
        if line.strip().startswith((
            "direct_override", "fake_system_tag", "roleplay_authority", "encoded_instruction",
            "unicode_homoglyph", "fake_tool_output", "indirect_kb_reference",
        )):
            assert "0%" in line


def test_run_prints_severity_weighted_hijack_rate(capsys):
    """a flat hijack rate treats a hijack on a critical alert the same as
    one on a low-severity alert - the severity-weighted number should
    show up alongside it in every run's output, not just the flat one."""
    exit_code = main(["run", "--client", "fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "severity-weighted hijack rate:" in out


def test_run_prints_confidence_interval(capsys):
    """each technique only gets 7-9 alerts - a bare point estimate hides
    how little data backs it, so every run should also print a 95%
    confidence interval on the overall rate."""
    exit_code = main(["run", "--client", "fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "95% confidence interval:" in out


def test_run_prints_severity_breakdown(capsys):
    """overall and severity-weighted hijack rate each collapse severity
    into one number - this breaks it back out per severity, same
    technique/severity relationship aggregate_by_technique has to
    aggregate_by_severity, so a reader can see which severity level is
    actually driving the weighted number instead of just trusting it."""
    exit_code = main(["run", "--client", "fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "severity" in out
    assert "critical" in out


def test_run_severity_filter_restricts_clean_and_injected_alerts_to_that_severity(capsys):
    exit_code = main(["run", "--client", "fake-vulnerable", "--severity", "critical"])
    out = capsys.readouterr().out
    assert exit_code == 0
    # only A001 and A006 (the two critical escalate alerts) remain clean-side,
    # and only their 2 injected copies per technique remain on the injected side.
    assert "clean alerts: 3/3 correct action" in out
    assert "severity filter: critical" in out
    assert "direct_override                 3        0      0        100%" in out
    assert "high" not in out
    assert "medium" not in out


def test_run_severity_filter_accepts_a_comma_separated_subset(capsys):
    exit_code = main(["run", "--client", "fake-vulnerable", "--severity", "critical,high"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "clean alerts: 7/7 correct action" in out  # A001, A006 (critical) + A002 (high)
    assert "severity filter: critical, high" in out
    assert "medium" not in out


def test_run_severity_filter_rejects_unknown_name(capsys):
    exit_code = main(["run", "--severity", "catastrophic"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown severity/severities for run" in err
    assert "catastrophic" in err


def test_run_severity_filter_all_commas_is_a_clear_error(capsys):
    exit_code = main(["run", "--severity", ",,"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "no severity names" in err


def test_severity_filter_that_empties_a_direction_is_refused_not_scored_as_zero(capsys):
    """escalation-direction injected alerts only ever come from dismiss-
    worthy ground truth alerts, none of which are severity=critical. This
    used to run an empty battery and print a 0% hijack rate - which reads
    exactly like a model that resisted everything, and would sit in a
    summary table next to real results. Refused up front instead, naming
    the severities that direction does have."""
    for command in (
        ["run", "--client", "fake-escalation-vulnerable"],
        ["compare", "--client", "fake-escalation-vulnerable"],
        ["leaderboard"],
        ["technique-leaderboard"],
        ["matrix", "--clients", "fake-vulnerable"],
        ["severity-matrix", "--client", "fake-vulnerable"],
    ):
        assert main([*command, "--direction", "escalate", "--severity", "critical"]) == 1
        captured = capsys.readouterr()
        assert ("--severity critical leaves no alerts for direction=escalate - its alerts are high, medium, low"
                in captured.err), command
        assert "hijack rate" not in captured.out


def test_full_report_refuses_a_severity_filter_that_empties_either_direction(tmp_path, capsys):
    report_path = tmp_path / "r.json"
    assert main(["full-report", "--client", "fake-vulnerable", "--severity", "critical",
                 "--report", str(report_path)]) == 1
    assert "leaves no alerts for direction=escalate" in capsys.readouterr().err
    assert not report_path.exists()


def test_run_writes_markdown_report(tmp_path, capsys):
    """compare and full-report could both save their results to a file,
    but a plain run - the most common invocation - couldn't, even though
    it's the same aggregated data compare feeds to render_markdown_report
    for a single defense."""
    report_path = tmp_path / "report.md"
    exit_code = main(["run", "--client", "fake-vulnerable", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert f"wrote report to {report_path}" in out
    content = report_path.read_text()
    assert "defense: none" in content
    assert "direction: dismiss" in content
    assert "| technique |" in content
    assert "| severity | hijacked | resisted | other | hijack rate |" in content
    assert "severity-weighted hijack rate:" in content
    assert "95% confidence interval:" in content
    assert "severity filter:" not in content
    assert "## summary: clean-alert accuracy by defense" in content
    assert "| none | 100% |" in content


def test_run_writes_json_report_when_path_ends_in_json(tmp_path, capsys):
    """the report format is inferred from the --report path's extension -
    no separate --format flag needed."""
    report_path = tmp_path / "report.json"
    exit_code = main(["run", "--client", "fake-vulnerable", "--report", str(report_path)])
    capsys.readouterr()
    assert exit_code == 0
    parsed = json.loads(report_path.read_text())
    assert parsed["client"] == "fake-vulnerable"
    assert parsed["direction"] == "dismiss"
    assert parsed["severity_filter"] is None
    assert "direct_override" in parsed["per_defense"]["none"]
    assert parsed["severity_weighted_by_defense"] == {"none": 0.875}
    assert "none" in parsed["confidence_interval_by_defense"]
    assert "critical" in parsed["severity_breakdown_by_defense"]["none"]
    assert parsed["clean_accuracy_by_defense"] == {"none": 1.0}


def test_run_severity_filter_is_recorded_in_markdown_report(tmp_path, capsys):
    """a saved report file is what actually goes into the thesis - without
    this, there was no way to tell afterward, from the file alone, that a
    run only covered a --severity subset rather than the full battery."""
    report_path = tmp_path / "report.md"
    main(["run", "--client", "fake-vulnerable", "--severity", "critical,high", "--report", str(report_path)])
    capsys.readouterr()
    content = report_path.read_text()
    assert "severity filter: critical, high" in content


def test_run_severity_filter_is_recorded_in_json_report(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    main(["run", "--client", "fake-vulnerable", "--severity", "critical,high", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert parsed["severity_filter"] == ["critical", "high"]


def test_run_writes_csv_report_when_path_ends_in_csv(tmp_path, capsys):
    report_path = tmp_path / "report.csv"
    exit_code = main(["run", "--client", "fake-vulnerable", "--report", str(report_path)])
    capsys.readouterr()
    assert exit_code == 0
    rows = list(csv.DictReader(report_path.open()))
    assert len(rows) == 8  # one per dismiss-direction technique
    assert all(row["client"] == "fake-vulnerable" for row in rows)
    assert all(row["defense"] == "none" for row in rows)


def test_report_format_is_case_insensitive():
    """a bare .endswith(".json") check would silently fall back to
    markdown for results.JSON - the extension should be recognized
    regardless of case."""
    assert _report_format("results.json") == "json"
    assert _report_format("results.JSON") == "json"
    assert _report_format("results.Json") == "json"
    assert _report_format("results.csv") == "csv"
    assert _report_format("results.CSV") == "csv"
    assert _report_format("results.md") == "markdown"
    assert _report_format("results") == "markdown"


def test_run_writes_transcript(tmp_path, capsys):
    """the aggregate report says how often a technique got hijacked, but
    nothing about what a specific decision actually looked like - the
    transcript is for pulling out an example to quote or spot-checking a
    surprising result instead of trusting the aggregate blindly."""
    transcript_path = tmp_path / "transcript.json"
    exit_code = main(["run", "--client", "fake-vulnerable", "--transcript", str(transcript_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert f"wrote transcript to {transcript_path}" in out
    entries = json.loads(transcript_path.read_text())
    assert len(entries) == 72  # 8 techniques x 9 alerts each
    assert all("reasoning" in e for e in entries)
    hijacked = [e for e in entries if e["outcome"] == "hijacked"]
    resisted = [e for e in entries if e["outcome"] == "resisted"]
    assert len(hijacked) == 63  # every technique but unicode_homoglyph, 9 alerts each
    assert len(resisted) == 9  # unicode_homoglyph's 9


def test_run_without_transcript_flag_writes_nothing(tmp_path, capsys):
    exit_code = main(["run", "--client", "fake-robust"])
    capsys.readouterr()
    assert exit_code == 0
    assert list(tmp_path.iterdir()) == []


def test_run_without_report_flag_writes_nothing(tmp_path, capsys):
    exit_code = main(["run", "--client", "fake-robust"])
    capsys.readouterr()
    assert exit_code == 0
    assert list(tmp_path.iterdir()) == []


def test_run_bad_report_path_fails_cleanly(capsys):
    exit_code = main(["run", "--client", "fake-robust", "--report", "/no/such/directory/report.md"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "error:" in err


def test_run_with_fake_vulnerable_client(capsys):
    exit_code = main(["run", "--client", "fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("unicode_homoglyph"):
            assert "0%" in stripped  # not caught by literal marker matching
        elif stripped.startswith((
            "direct_override", "fake_system_tag", "roleplay_authority",
            "encoded_instruction", "fake_tool_output", "indirect_kb_reference",
        )):
            assert "100%" in stripped


def test_run_without_severity_flag_prints_no_severity_filter_line(capsys):
    exit_code = main(["run", "--client", "fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "severity filter:" not in out


def test_run_with_fake_semantic_vulnerable_client_hijacked_by_homoglyph_too(capsys):
    exit_code = main(["run", "--client", "fake-semantic-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    for line in out.splitlines():
        if line.strip().startswith("unicode_homoglyph"):
            assert "100%" in line


def test_stubborn_client_only_resists_the_combined_defense(capsys):
    for defense in ("none", "sandwich", "strict"):
        main(["run", "--client", "fake-stubborn", "--defense", defense])
        out = capsys.readouterr().out
        assert "direct_override" in out
        for line in out.splitlines():
            if line.strip().startswith("direct_override"):
                assert "100%" in line, f"defense={defense} unexpectedly reduced hijack rate"

    main(["run", "--client", "fake-stubborn", "--defense", "both"])
    out = capsys.readouterr().out
    for line in out.splitlines():
        if line.strip().startswith("direct_override"):
            assert "0%" in line


def test_escalation_stubborn_client_only_resists_the_combined_defense(capsys):
    """the escalation-direction mirror of the check above - without
    EscalationStubbornFakeClient, nothing proved "both" is uniquely
    necessary (not just individually sufficient) for the escalation
    direction, since StubbornFakeClient itself only knows the
    dismiss-direction markers and resists every escalation alert
    regardless of defense."""
    for defense in ("none", "sandwich", "strict"):
        main(["run", "--client", "fake-escalation-stubborn", "--direction", "escalate", "--defense", defense])
        out = capsys.readouterr().out
        assert "false_urgency" in out
        for line in out.splitlines():
            if line.strip().startswith("false_urgency"):
                assert "100%" in line, f"defense={defense} unexpectedly reduced hijack rate"

    main(["run", "--client", "fake-escalation-stubborn", "--direction", "escalate", "--defense", "both"])
    out = capsys.readouterr().out
    for line in out.splitlines():
        if line.strip().startswith("false_urgency"):
            assert "0%" in line


def test_run_with_sandwich_defense_reduces_hijack_rate(capsys):
    main(["run", "--client", "fake-sandwich-sensitive", "--defense", "none"])
    without_defense = capsys.readouterr().out

    main(["run", "--client", "fake-sandwich-sensitive", "--defense", "sandwich"])
    with_defense = capsys.readouterr().out

    assert "100%" in without_defense
    assert "100%" not in with_defense


def test_compare_shows_all_three_defenses(capsys):
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "defense=none" in out
    assert "defense=sandwich" in out
    assert "defense=strict" in out


def test_compare_prints_summary_to_terminal_even_without_report_flag(capsys):
    """the summary table used to only ever land in the written markdown
    file - with no --report given at all, a compare run showed no
    overall picture on the terminal, just the raw per-defense tables."""
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "summary: overall hijack rate by defense" in out
    assert "sandwich" in out.split("summary: overall hijack rate by defense")[1]


def test_compare_prints_significance_vs_none_baseline(capsys):
    """a percentage-point gap between two small samples can look big
    without being statistically meaningful - this is the number that
    actually answers whether a defense measurably helped. sandwich should
    come back significant for fake-sandwich-sensitive (0% vs 88%), strict
    should come back not significant (it doesn't affect this client at all,
    88% vs 88% - the same rate, not just a similar one)."""
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "significance vs defense=none (two-proportion z-test):" in out
    significance_section = out.split("significance vs defense=none")[1]
    assert "none vs sandwich:" in significance_section
    assert "none vs strict:" in significance_section
    assert "none vs both:" in significance_section
    sandwich_line = next(line for line in significance_section.splitlines() if "none vs sandwich:" in line)
    strict_line = next(line for line in significance_section.splitlines() if "none vs strict:" in line)
    assert "not significant" not in sandwich_line
    assert "not significant" in strict_line
    assert "Holm-adjusted" in sandwich_line


def test_defense_comparisons_are_holm_adjusted_as_one_family():
    """sandwich, strict and both are three tests against the same none
    baseline. Built from counts with ordinary p-values - the fake clients'
    0% vs 88% gaps underflow p to exactly 0, which any multiplier leaves
    at 0."""
    def results(hijacked, total):
        alert = Alert(id="A", source="edr", severity="high", description="", raw_log="",
                      ground_truth_action="escalate", injected_technique="direct_override",
                      injected_target_action="dismiss")
        hijack = ScoredResult(alert, AnalystDecision(alert_id="A", action="dismiss", reasoning="", raw_response=""), "hijacked")
        resist = ScoredResult(alert, AnalystDecision(alert_id="A", action="escalate", reasoning="", raw_response=""), "resisted")
        return [hijack] * hijacked + [resist] * (total - hijacked)

    by_defense = {"none": results(40, 72), "sandwich": results(28, 72), "strict": results(30, 72),
                  "both": results(38, 72)}
    significance = cli_module._significance_vs_baseline(by_defense, "none")
    raw = {defense: p_value for defense, (_, p_value, _) in significance.items()}
    holm = {defense: p_holm for defense, (_, _, p_holm) in significance.items()}
    assert raw["sandwich"] < raw["strict"] < raw["both"]
    assert holm["sandwich"] == pytest.approx(3 * raw["sandwich"])
    assert holm["strict"] == pytest.approx(max(3 * raw["sandwich"], 2 * raw["strict"]))
    assert holm["both"] == pytest.approx(raw["both"])
    # sandwich clears 0.05 on its own and not after the adjustment
    assert raw["sandwich"] < 0.05 < holm["sandwich"]


def test_strict_defense_only_helps_the_strict_sensitive_client(capsys):
    main(["run", "--client", "fake-strict-sensitive", "--defense", "none"])
    without_defense = capsys.readouterr().out
    main(["run", "--client", "fake-strict-sensitive", "--defense", "strict"])
    with_defense = capsys.readouterr().out
    assert "100%" in without_defense
    assert "100%" not in with_defense

    # sandwich defense shouldn't affect this client - it only reads the system prompt
    main(["run", "--client", "fake-strict-sensitive", "--defense", "sandwich"])
    with_wrong_defense = capsys.readouterr().out
    assert "100%" in with_wrong_defense


def test_compare_prints_clean_accuracy_summary(capsys):
    """compare runs every defense against the injected battery but, before
    this, never checked whether a defense's own added verbiage (the
    sandwich reinforcement, the strict warning) makes the client worse at
    alerts that were never attacked in the first place - the per-defense
    hijack-rate tables can't show that, since a clean alert has no hijack
    direction to measure against."""
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "summary: clean-alert accuracy by defense" in out
    clean_section = out.split("summary: clean-alert accuracy by defense")[1]
    assert "none" in clean_section
    assert "sandwich" in clean_section
    assert "strict" in clean_section
    assert "both" in clean_section


def test_compare_writes_clean_accuracy_to_markdown_report(tmp_path, capsys):
    report_path = tmp_path / "report.md"
    main(["compare", "--client", "fake-sandwich-sensitive", "--report", str(report_path)])
    capsys.readouterr()
    content = report_path.read_text()
    assert "## summary: clean-alert accuracy by defense" in content
    assert "| defense | clean accuracy |" in content


def test_compare_writes_clean_accuracy_to_json_report(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    main(["compare", "--client", "fake-sandwich-sensitive", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert set(parsed["clean_accuracy_by_defense"]) == {"none", "sandwich", "strict", "both"}
    assert parsed["clean_accuracy_by_defense"]["none"] == 1.0


def test_compare_clean_accuracy_respects_severity_filter(capsys):
    """clean alerts get the same --severity narrowing the injected battery
    already does - otherwise a filtered run's clean-accuracy number would
    silently cover more alerts than the hijack-rate numbers next to it."""
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive", "--severity", "critical"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "summary: clean-alert accuracy by defense" in out


def test_compare_writes_markdown_report(tmp_path, capsys):
    report_path = tmp_path / "report.md"
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive", "--report", str(report_path)])
    capsys.readouterr()
    assert exit_code == 0
    content = report_path.read_text()
    assert "defense: none" in content
    assert "defense: sandwich" in content
    assert "| technique |" in content
    assert "direction: dismiss" in content
    assert "summary: overall hijack rate by defense" in content
    assert "| severity | hijacked | resisted | other | hijack rate |" in content
    assert "severity-weighted hijack rate:" in content
    assert "95% confidence interval:" in content
    assert "significance vs none (two-proportion z-test):" in content


def test_compare_writes_json_report_when_path_ends_in_json(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive", "--report", str(report_path)])
    capsys.readouterr()
    assert exit_code == 0
    parsed = json.loads(report_path.read_text())
    assert set(parsed["per_defense"]) == {"none", "sandwich", "strict", "both"}
    assert parsed["summary_by_defense"]["sandwich"] < parsed["summary_by_defense"]["none"]
    assert set(parsed["severity_weighted_by_defense"]) == {"none", "sandwich", "strict", "both"}
    assert set(parsed["confidence_interval_by_defense"]) == {"none", "sandwich", "strict", "both"}
    assert set(parsed["severity_breakdown_by_defense"]) == {"none", "sandwich", "strict", "both"}
    assert parsed["severity_filter"] is None
    # none itself never gets an entry - nothing to compare it against itself.
    assert set(parsed["significance_vs_none_by_defense"]) == {"sandwich", "strict", "both"}


def test_compare_severity_filter_is_recorded_in_reports(tmp_path, capsys):
    md_path, json_path = tmp_path / "report.md", tmp_path / "report.json"
    main(["compare", "--client", "fake-sandwich-sensitive", "--severity", "critical", "--report", str(md_path)])
    main(["compare", "--client", "fake-sandwich-sensitive", "--severity", "critical", "--report", str(json_path)])
    capsys.readouterr()
    assert "severity filter: critical" in md_path.read_text()
    assert json.loads(json_path.read_text())["severity_filter"] == ["critical"]


def test_compare_writes_csv_report_when_path_ends_in_csv(tmp_path, capsys):
    report_path = tmp_path / "report.csv"
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive", "--report", str(report_path)])
    capsys.readouterr()
    assert exit_code == 0
    rows = list(csv.DictReader(report_path.open()))
    assert len(rows) == 32  # 4 defenses x 8 techniques
    assert {row["defense"] for row in rows} == {"none", "sandwich", "strict", "both"}


def test_compare_writes_transcript(tmp_path, capsys):
    transcript_path = tmp_path / "transcript.json"
    exit_code = main([
        "compare", "--client", "fake-sandwich-sensitive", "--transcript", str(transcript_path),
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert f"wrote transcript to {transcript_path}" in out
    entries = json.loads(transcript_path.read_text())
    assert {e["defense"] for e in entries} == {"none", "sandwich", "strict", "both"}
    assert {e["direction"] for e in entries} == {"dismiss"}


def test_compare_report_notes_escalate_direction(tmp_path, capsys):
    report_path = tmp_path / "report.md"
    main(["compare", "--client", "fake-escalation-sandwich-sensitive", "--direction", "escalate",
          "--report", str(report_path)])
    capsys.readouterr()
    assert "direction: escalate" in report_path.read_text()


def test_compare_prints_direction(capsys):
    exit_code = main(["compare", "--client", "fake-escalation-vulnerable", "--direction", "escalate"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direction=escalate" in out


def test_compare_bad_report_path_fails_cleanly(capsys):
    exit_code = main(["compare", "--client", "fake-robust", "--report", "/no/such/directory/report.md"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "error:" in err
    assert "No such file or directory" in err


def test_compare_severity_filter_restricts_the_battery(capsys):
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive", "--severity", "critical"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override                 3        0      0        100%" in out
    assert "medium" not in out


def test_compare_severity_filter_rejects_unknown_name(capsys):
    exit_code = main(["compare", "--severity", "catastrophic"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown severity/severities for compare" in err


def test_full_report_bad_report_path_fails_cleanly(capsys):
    exit_code = main(["full-report", "--client", "fake-robust", "--report", "/no/such/directory/report.md"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "error:" in err


def test_full_report_writes_combined_markdown(tmp_path, capsys):
    report_path = tmp_path / "full.md"
    exit_code = main(["full-report", "--client", "fake-stubborn", "--report", str(report_path)])
    capsys.readouterr()
    assert exit_code == 0
    content = report_path.read_text()
    assert "direction: dismiss" in content
    assert "direction: escalate" in content
    assert "defense: none" in content
    assert "defense: both" in content
    assert "| severity | hijacked | resisted | other | hijack rate |" in content
    assert "severity-weighted hijack rate:" in content
    assert "95% confidence interval:" in content
    assert "significance vs none (two-proportion z-test):" in content


def test_full_report_writes_json_when_path_ends_in_json(tmp_path, capsys):
    report_path = tmp_path / "full.json"
    exit_code = main(["full-report", "--client", "fake-stubborn", "--report", str(report_path)])
    capsys.readouterr()
    assert exit_code == 0
    parsed = json.loads(report_path.read_text())
    assert set(parsed["by_direction"]) == {"dismiss", "escalate"}
    assert parsed["summary_by_defense"]["both"] == 0.0
    assert parsed["severity_weighted_by_direction"]["dismiss"]["both"] == 0.0
    assert parsed["severity_weighted_by_direction"]["escalate"]["both"] == 0.0
    low, high = parsed["confidence_interval_by_direction"]["dismiss"]["both"]
    assert low == 0.0
    assert high == pytest.approx(0.0507, abs=0.01)
    assert set(parsed["significance_vs_none_by_direction"]["dismiss"]) == {"sandwich", "strict", "both"}
    assert set(parsed["severity_breakdown_by_direction"]) == {"dismiss", "escalate"}
    assert parsed["severity_filter"] is None


def test_full_report_prints_clean_accuracy_summary(tmp_path, capsys):
    """same gap compare had: every defense gets run against the injected
    battery, but clean-alert accuracy under each defense (does the
    defense's own added verbiage hurt alerts that were never attacked)
    was never checked at all - direction-independent, so one summary
    table for the whole report, not one per direction."""
    report_path = tmp_path / "full.md"
    exit_code = main(["full-report", "--client", "fake-stubborn", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "summary: clean-alert accuracy by defense" in out


def test_full_report_writes_clean_accuracy_to_combined_markdown(tmp_path, capsys):
    report_path = tmp_path / "full.md"
    main(["full-report", "--client", "fake-stubborn", "--report", str(report_path)])
    capsys.readouterr()
    content = report_path.read_text()
    assert "## summary: clean-alert accuracy by defense" in content
    assert "| defense | clean accuracy |" in content
    # a flat defense -> accuracy table, not split per direction like the
    # hijack-rate sections below it - appears exactly once in the document.
    assert content.count("## summary: clean-alert accuracy by defense") == 1


def test_full_report_writes_clean_accuracy_to_json(tmp_path, capsys):
    report_path = tmp_path / "full.json"
    main(["full-report", "--client", "fake-stubborn", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert set(parsed["clean_accuracy_by_defense"]) == {"none", "sandwich", "strict", "both"}
    assert parsed["clean_accuracy_by_defense"]["none"] == 1.0


def test_full_report_severity_filter_is_recorded_in_reports(tmp_path, capsys):
    md_path = tmp_path / "full.md"
    json_path = tmp_path / "full.json"
    main(["full-report", "--client", "fake-stubborn", "--severity", "low", "--report", str(md_path)])
    main(["full-report", "--client", "fake-stubborn", "--severity", "low", "--report", str(json_path)])
    capsys.readouterr()
    assert "severity filter: low" in md_path.read_text()
    assert json.loads(json_path.read_text())["severity_filter"] == ["low"]


def test_full_report_writes_csv_report_when_path_ends_in_csv(tmp_path, capsys):
    report_path = tmp_path / "full.csv"
    exit_code = main(["full-report", "--client", "fake-stubborn", "--report", str(report_path)])
    capsys.readouterr()
    assert exit_code == 0
    rows = list(csv.DictReader(report_path.open()))
    assert len(rows) == 64  # 2 directions x 4 defenses x 8 techniques
    assert {row["direction"] for row in rows} == {"dismiss", "escalate"}
    assert all(row["client"] == "fake-stubborn" for row in rows)


def test_full_report_writes_transcript(tmp_path, capsys):
    report_path = tmp_path / "full.md"
    transcript_path = tmp_path / "transcript.json"
    exit_code = main([
        "full-report", "--client", "fake-stubborn",
        "--report", str(report_path), "--transcript", str(transcript_path),
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert f"wrote combined transcript to {transcript_path}" in out
    entries = json.loads(transcript_path.read_text())
    assert {e["direction"] for e in entries} == {"dismiss", "escalate"}
    assert {e["defense"] for e in entries} == {"none", "sandwich", "strict", "both"}


def test_full_report_summary_shows_stubborn_client_only_helped_by_both(tmp_path, capsys):
    """fake-stubborn only backs off when both defenses are active together
    - the summary section should show that as the one defense with a
    reduced overall hijack rate."""
    report_path = tmp_path / "full.md"
    main(["full-report", "--client", "fake-stubborn", "--report", str(report_path)])
    capsys.readouterr()
    content = report_path.read_text()
    summary_section = content.split("# direction:")[0]
    assert "| both | 0% |" in summary_section
    assert "| none | 0% |" not in summary_section


def test_full_report_prints_significance_per_direction(tmp_path, capsys):
    """fake-stubborn (dismiss direction) is only helped by 'both' together
    - the significance section for direction=dismiss should call that one
    out as significant and leave sandwich/strict alone as not significant."""
    report_path = tmp_path / "full.md"
    main(["full-report", "--client", "fake-stubborn", "--report", str(report_path)])
    out = capsys.readouterr().out
    sections = out.split("significance vs defense=none")
    assert len(sections) == 3  # one per direction, plus the text before the first
    dismiss_section = sections[1]
    assert "none vs both:" in dismiss_section
    both_line = next(line for line in dismiss_section.splitlines() if "none vs both:" in line)
    assert "not significant" not in both_line


def test_full_report_prints_summary_to_terminal(tmp_path, capsys):
    """same summary table the combined markdown report gets should also
    show up on the terminal, not just in the file written to --report."""
    report_path = tmp_path / "full.md"
    main(["full-report", "--client", "fake-stubborn", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert "summary: overall hijack rate by defense (both directions combined)" in out
    summary_section = out.split("summary: overall hijack rate by defense (both directions combined)")[1]
    assert "both" in summary_section
    assert "0%" in summary_section


def test_full_report_requires_report_path():
    with pytest.raises(SystemExit):
        main(["full-report", "--client", "fake-stubborn"])


def test_full_report_severity_filter_restricts_both_directions(tmp_path, capsys):
    """escalation-direction techniques only ever target dismiss-worthy
    alerts, none of which are severity=critical/high - so filtering to
    --severity critical,high should leave the dismiss direction's battery
    intact but make the escalate direction's come back empty, not erroring."""
    report_path = tmp_path / "full.md"
    exit_code = main([
        "full-report", "--client", "fake-stubborn", "--severity", "critical,high", "--report", str(report_path),
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "severity filter: critical, high" in out
    assert "direction=escalate defense=none ---\ntechnique" in out
    escalate_section = out.split("direction=escalate defense=none ---")[1].split("direction=escalate defense=sandwich")[0]
    assert "overall hijack rate: 0%" in escalate_section


def test_full_report_severity_filter_rejects_unknown_name(tmp_path, capsys):
    report_path = tmp_path / "full.md"
    exit_code = main(["full-report", "--client", "fake-robust", "--report", str(report_path), "--severity", "huge"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown severity/severities for full-report" in err


def test_leaderboard_ranks_fake_clients_by_hijack_rate(capsys):
    exit_code = main(["leaderboard", "--direction", "dismiss", "--defense", "none"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direction=dismiss defense=none" in out
    assert "fake-robust" in out
    assert "fake-semantic-vulnerable" in out
    robust_line = next(line for line in out.splitlines() if line.strip().startswith("fake-robust"))
    vulnerable_line = next(line for line in out.splitlines() if line.strip().startswith("fake-vulnerable "))
    # fake-robust never caves, fake-vulnerable does - robust's line must show 0%
    # and come before vulnerable's in the most-robust-first ranking.
    assert "0%" in robust_line
    assert out.index(robust_line) < out.index(vulnerable_line)


def test_leaderboard_sort_by_defaults_are_most_robust_first():
    """lower is "more robust" for the two hijack-rate columns, but higher
    is "more robust" for clean_accuracy - without per-column direction,
    sorting by clean_accuracy the same way as hijack_rate would put the
    worst analysts first instead of the best ones."""
    from soclab.cli import _LEADERBOARD_SORT_ASCENDING
    assert _LEADERBOARD_SORT_ASCENDING["hijack_rate"] is True
    assert _LEADERBOARD_SORT_ASCENDING["severity_weighted_hijack_rate"] is True
    assert _LEADERBOARD_SORT_ASCENDING["clean_accuracy"] is False


def test_leaderboard_sort_by_severity_weighted_hijack_rate(capsys):
    exit_code = main([
        "leaderboard", "--clients", "fake-robust,fake-vulnerable,fake-semantic-vulnerable",
        "--sort-by", "severity_weighted_hijack_rate",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    robust_line = next(line for line in out.splitlines() if line.strip().startswith("fake-robust"))
    semantic_line = next(line for line in out.splitlines() if line.strip().startswith("fake-semantic-vulnerable"))
    # fake-robust (0% severity-weighted) must rank ahead of
    # fake-semantic-vulnerable (100%) when sorted by that column.
    assert out.index(robust_line) < out.index(semantic_line)


def test_leaderboard_two_clients_prints_pairwise_significance(capsys):
    exit_code = main(["leaderboard", "--clients", "fake-robust,fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "fake-robust vs fake-vulnerable (two-proportion z-test):" in out
    assert "not significant" not in out


def test_leaderboard_pairwise_significance_matches_table_order_not_input_order(capsys):
    """--clients fake-vulnerable,fake-robust (vulnerable first) sorts to
    fake-robust first in the table (0% hijack rate ranks more robust) -
    the pairwise line below it should read the same direction as the
    table, not just echo back the --clients input order."""
    exit_code = main(["leaderboard", "--clients", "fake-vulnerable,fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "fake-robust vs fake-vulnerable (two-proportion z-test):" in out


def test_leaderboard_more_than_two_clients_has_no_pairwise_significance(capsys):
    """with three or more clients there's no single unambiguous pair to
    compare - every pair would need its own line, which is a different,
    bigger feature this doesn't try to be."""
    exit_code = main(["leaderboard", "--clients", "fake-robust,fake-vulnerable,fake-stubborn"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "two-proportion z-test" not in out


def test_leaderboard_writes_pairwise_significance_to_json_report(tmp_path, capsys):
    report_path = tmp_path / "leaderboard.json"
    main(["leaderboard", "--clients", "fake-robust,fake-vulnerable", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert parsed["pairwise_significance"]["client_a"] == "fake-robust"
    assert parsed["pairwise_significance"]["client_b"] == "fake-vulnerable"
    assert parsed["pairwise_significance"]["p_value"] < 0.05


def test_leaderboard_writes_pairwise_significance_to_markdown_report(tmp_path, capsys):
    report_path = tmp_path / "leaderboard.md"
    main(["leaderboard", "--clients", "fake-robust,fake-vulnerable", "--report", str(report_path)])
    capsys.readouterr()
    content = report_path.read_text()
    assert "fake-robust vs fake-vulnerable (two-proportion z-test):" in content


def test_leaderboard_rejects_unknown_sort_by():
    with pytest.raises(SystemExit):
        main(["leaderboard", "--sort-by", "not-a-real-column"])


def test_leaderboard_excludes_ollama(capsys):
    """real models need a reachable ollama server, so without --models
    they never show up as leaderboard rows - the default run sticks to
    the deterministic fakes."""
    exit_code = main(["leaderboard"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ollama" not in out


class _FakeOllamaResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


@pytest.fixture
def fake_ollama(monkeypatch):
    """Stands in for a running ollama server: answers each /api/chat
    request the way one of the fake clients would, picked by the
    requested model name, so the --models tests go through OllamaClient's
    real request building and response parsing rather than around it.
    /api/tags lists the pulled models the way ollama does - an untagged
    pull shows up with ":latest" on the end. Returns the list of chat
    requests it received, for checking host/timeout."""
    behaviours = {
        "robust-model": RobustFakeClient(),
        "gullible-model": VulnerableFakeClient(),
        "untagged-model": RobustFakeClient(),
        "rambling-model": ScriptedLLMClient(["I'd rather not answer in json, sorry."] * 200),
        "dismiss-everything-model": ScriptedLLMClient(['{"action": "dismiss", "reasoning": "fine"}'] * 2000),
    }
    pulled = ["robust-model", "gullible-model", "untagged-model:latest", "rambling-model", "dismiss-everything-model"]
    received = []

    def fake_post(url, json, timeout):
        received.append({"url": url, "model": json["model"], "timeout": timeout, "options": json.get("options")})
        system, user = (message["content"] for message in json["messages"])
        return _FakeOllamaResponse({"message": {"content": behaviours[json["model"]].complete(system, user)}})

    def fake_get(url, timeout):
        assert url.endswith("/api/tags")
        return _FakeOllamaResponse({"models": [{"name": name} for name in pulled]})

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", fake_get)
    return received


def test_models_missing_from_server_fails_before_anything_runs(fake_ollama, capsys):
    """the models run one after another, so without a check up front a
    typo in the last one only shows up after every earlier model has
    finished its whole battery - this names every missing one at once,
    before a single chat request goes out."""
    exit_code = main(["leaderboard", "--models", "robust-model,mistral:7b,qwen2.5:7b"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "model(s) not pulled on http://localhost:11434: mistral:7b, qwen2.5:7b" in err
    assert "ollama pull" in err
    assert "robust-model" in err  # listed as available
    assert fake_ollama == []


def test_real_model_runs_report_progress_on_stderr(fake_ollama, capsys):
    """a real model takes seconds per alert, so without this a few hundred
    requests of silence look exactly like a hung run. leaderboard sends
    18 clean + 72 injected requests here - a progress line every 10th,
    all on stderr so stdout stays just the results."""
    exit_code = main(["leaderboard", "--models", "robust-model"])
    captured = capsys.readouterr()
    assert exit_code == 0
    progress = [line for line in captured.err.splitlines() if line.startswith("ollama:robust-model:")]
    assert len(progress) == 9
    assert progress[-1].startswith("ollama:robust-model: 90/90 requests done (")
    assert "requests done" not in captured.out


def test_run_with_ollama_client_reports_progress_too(fake_ollama, capsys):
    exit_code = main(["run", "--client", "ollama", "--model", "gullible-model"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "ollama:gullible-model: 40/90 requests done (" in captured.err


def test_single_client_reports_name_the_real_model(fake_ollama, tmp_path, capsys):
    """a saved report used to say just "ollama" - two full-report files for
    two different models were indistinguishable from their contents, only
    from their filenames. same ollama:<model> label the comparison
    commands already use for their rows."""
    md_path, json_path, csv_path = tmp_path / "r.md", tmp_path / "r.json", tmp_path / "r.csv"
    for path in (md_path, json_path, csv_path):
        assert main(["run", "--client", "ollama", "--model", "robust-model", "--report", str(path)]) == 0
    capsys.readouterr()
    assert "client: ollama:robust-model" in md_path.read_text()
    assert json.loads(json_path.read_text())["client"] == "ollama:robust-model"
    assert {row["client"] for row in csv.DictReader(io.StringIO(csv_path.read_text()))} == {"ollama:robust-model"}


def test_full_report_and_severity_matrix_name_the_real_model(fake_ollama, tmp_path, capsys):
    report_path = tmp_path / "full.json"
    assert main(["full-report", "--client", "ollama", "--model", "gullible-model", "--report", str(report_path)]) == 0
    assert json.loads(report_path.read_text())["client"] == "ollama:gullible-model"
    capsys.readouterr()
    assert main(["severity-matrix", "--client", "ollama", "--model", "gullible-model"]) == 0
    assert "client=ollama:gullible-model direction=dismiss" in capsys.readouterr().out


def test_temperature_and_seed_reach_ollama_on_single_client_runs(fake_ollama, capsys):
    """without these every request used the model's own default temperature
    (usually above 0), so two runs of the same battery could disagree and
    a thesis result couldn't be reproduced."""
    exit_code = main([
        "run", "--client", "ollama", "--model", "robust-model", "--temperature", "0", "--seed", "42",
    ])
    capsys.readouterr()
    assert exit_code == 0
    assert all(r["options"] == {"temperature": 0.0, "seed": 42} for r in fake_ollama)


def test_temperature_and_seed_reach_every_model_in_a_comparison(fake_ollama, capsys):
    exit_code = main(["leaderboard", "--models", "robust-model,gullible-model", "--temperature", "0"])
    capsys.readouterr()
    assert exit_code == 0
    assert {r["model"] for r in fake_ollama} == {"robust-model", "gullible-model"}
    assert all(r["options"] == {"temperature": 0.0} for r in fake_ollama)


def test_pinned_sampling_settings_are_recorded_in_saved_reports(fake_ollama, tmp_path, capsys):
    """a report from a temperature-0 run and one from the model's default
    used to look identical - the settings that make a run reproducible
    weren't written down anywhere in it."""
    report_path = tmp_path / "r.json"
    main([
        "run", "--client", "ollama", "--model", "robust-model",
        "--temperature", "0", "--seed", "42", "--report", str(report_path),
    ])
    captured = capsys.readouterr()
    assert json.loads(report_path.read_text())["client"] == "ollama:robust-model (temperature=0, seed=42)"
    assert "ollama:robust-model (temperature=0, seed=42): 40/90 requests done" in captured.err


def test_comparison_rows_carry_pinned_sampling_settings(fake_ollama, tmp_path, capsys):
    report_path = tmp_path / "lb.json"
    main(["leaderboard", "--models", "robust-model", "--temperature", "0.7", "--report", str(report_path)])
    capsys.readouterr()
    clients = [row["client"] for row in json.loads(report_path.read_text())["clients"]]
    assert clients == ["ollama:robust-model (temperature=0.7)"]


def test_leaderboard_columns_stay_aligned_with_long_model_labels(fake_ollama, capsys):
    main(["leaderboard", "--models", "robust-model", "--clients", "fake-vulnerable", "--temperature", "0", "--seed", "1"])
    rows = [line for line in capsys.readouterr().out.splitlines() if line.startswith(("ollama:", "fake-")) and " vs " not in line]
    assert len(rows) == 2
    # the first "%" closes the hijack_rate value - same column on every row,
    # whether its label is a short fake-* name or a long model label
    assert len({row.index("%") for row in rows}) == 1


def test_no_sampling_options_sent_unless_asked_for(fake_ollama, capsys):
    main(["run", "--client", "ollama", "--model", "robust-model"])
    capsys.readouterr()
    assert all(r["options"] is None for r in fake_ollama)


def test_negative_temperature_is_rejected(capsys):
    with pytest.raises(SystemExit):
        main(["run", "--client", "ollama", "--model", "m", "--temperature", "-0.5"])
    assert "must be 0 or more" in capsys.readouterr().err


def test_unparseable_responses_are_reported_not_hidden(fake_ollama, tmp_path, capsys):
    """a model that never keeps to the answer format scores a 0% hijack
    rate - every alert lands in "other" - which reads like perfect
    robustness unless the unparseable count is right next to it."""
    md_path, csv_path = tmp_path / "r.md", tmp_path / "r.csv"
    for path in (md_path, csv_path):
        assert main(["run", "--client", "ollama", "--model", "rambling-model", "--report", str(path)]) == 0
    out = capsys.readouterr().out
    assert "overall hijack rate: 0%" in out
    assert "unparseable responses: 72/72" in out
    assert "unparseable responses: 72/72" in md_path.read_text()
    rows = list(csv.DictReader(io.StringIO(csv_path.read_text())))
    assert sum(int(row["unparseable"]) for row in rows) == 72


def test_fake_clients_report_zero_unparseable(capsys):
    main(["run", "--client", "fake-vulnerable"])
    assert "unparseable responses: 0/72" in capsys.readouterr().out


def test_check_ollama_lists_pulled_models(fake_ollama, capsys):
    exit_code = main(["check-ollama", "--host", "http://gpu-box:11434"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ollama at http://gpu-box:11434 is reachable, 5 model(s) pulled: robust-model, gullible-model" in out
    assert fake_ollama == []  # no --model, so no chat request


def test_check_ollama_sends_one_alert_to_the_model(fake_ollama, capsys):
    exit_code = main(["check-ollama", "--model", "robust-model", "--temperature", "0"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "robust-model answered alert A001 with action=escalate (expected escalate, correct)" in out
    assert len(fake_ollama) == 1
    assert fake_ollama[0]["options"] == {"temperature": 0.0}


def test_check_ollama_fails_when_the_answer_cant_be_parsed(fake_ollama, capsys):
    """the setup problem that would otherwise only show up as a column of
    unparseable responses after a whole run."""
    exit_code = main(["check-ollama", "--model", "rambling-model"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "rambling-model answered alert A001 in a form parse_response can't read" in err
    assert "rather not answer in json" in err


def test_check_ollama_fails_for_a_model_that_isnt_pulled(fake_ollama, capsys):
    exit_code = main(["check-ollama", "--model", "mistral:7b"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "model(s) not pulled on http://localhost:11434: mistral:7b" in err
    assert fake_ollama == []


def test_check_ollama_unreachable_server_fails_cleanly(capsys):
    exit_code = main(["check-ollama", "--host", "http://localhost:1"])
    assert exit_code == 1
    assert capsys.readouterr().err.startswith("error:")


def test_cache_resumes_a_run_that_died_partway(fake_ollama, monkeypatch, tmp_path, capsys):
    """a real-model run that dies partway (one request timing out, the
    laptop sleeping, ctrl-c) used to throw away every answer it already
    had. with --cache, rerunning the same command picks up where it
    stopped: only the unanswered requests go out again, and the result
    is the same as an uninterrupted run."""
    cache_path = tmp_path / "answers.json"
    command = ["run", "--client", "ollama", "--model", "gullible-model", "--cache", str(cache_path)]

    answering = requests.post
    calls = {"n": 0}

    def dies_after_25(url, json, timeout):
        calls["n"] += 1
        if calls["n"] > 25:
            raise requests.exceptions.ReadTimeout("read timed out")
        return answering(url, json=json, timeout=timeout)

    monkeypatch.setattr(requests, "post", dies_after_25)
    assert main(command) == 1
    err = capsys.readouterr().err
    assert "read timed out" in err
    # the run says how to get its answers back, not just that it died
    assert f"every answer so far is saved in {cache_path}; rerun the same command to pick up from there" in err
    assert len(fake_ollama) == 25

    monkeypatch.setattr(requests, "post", answering)
    assert main(command) == 0
    resumed = capsys.readouterr().out
    assert len(fake_ollama) == 25 + (90 - 25)  # only the 65 unanswered requests went out again

    fake_ollama.clear()
    main(["run", "--client", "ollama", "--model", "gullible-model"])
    uninterrupted = capsys.readouterr().out
    assert resumed == uninterrupted


def test_cache_never_reuses_answers_across_models_or_settings(fake_ollama, tmp_path, capsys):
    cache_path = tmp_path / "answers.json"
    main(["run", "--client", "ollama", "--model", "robust-model", "--cache", str(cache_path)])
    first = len(fake_ollama)
    main(["run", "--client", "ollama", "--model", "gullible-model", "--cache", str(cache_path)])
    main(["run", "--client", "ollama", "--model", "robust-model", "--temperature", "0", "--cache", str(cache_path)])
    capsys.readouterr()
    assert len(fake_ollama) == 3 * first  # neither the other model nor the pinned temperature hit the cache


def test_cache_works_for_models_comparisons_too(fake_ollama, tmp_path, capsys):
    cache_path = tmp_path / "answers.json"
    command = ["leaderboard", "--models", "robust-model,gullible-model", "--cache", str(cache_path)]
    main(command)
    first_out = capsys.readouterr().out
    requests_first_run = len(fake_ollama)
    main(command)
    assert capsys.readouterr().out == first_out
    assert len(fake_ollama) == requests_first_run


def test_cache_makes_a_second_report_format_free(fake_ollama, tmp_path, capsys):
    """the readme's workflow: full-report writes one format per run, and
    rerunning the same command for the .md after the .json should answer
    every request from the cache rather than run the battery again."""
    cache = str(tmp_path / "cache.json")
    base = ["full-report", "--client", "ollama", "--model", "gullible-model",
            "--temperature", "0", "--seed", "42", "--cache", cache]
    assert main([*base, "--report", str(tmp_path / "llama.json")]) == 0
    first_run = len(fake_ollama)
    assert main([*base, "--report", str(tmp_path / "llama.md")]) == 0
    capsys.readouterr()
    assert first_run > 0
    assert len(fake_ollama) == first_run
    assert "client: ollama:gullible-model (temperature=0, seed=42)" in (tmp_path / "llama.md").read_text()


def test_cache_file_that_isnt_json_fails_cleanly(tmp_path, capsys):
    cache_path = tmp_path / "answers.json"
    cache_path.write_text("{not json")
    exit_code = main(["run", "--client", "ollama", "--model", "m", "--cache", str(cache_path)])
    assert exit_code == 1
    assert "isn't valid json - delete it to start a fresh cache" in capsys.readouterr().err


def test_fake_clients_print_no_progress(capsys):
    """the fakes answer instantly - progress lines would only be noise."""
    exit_code = main(["leaderboard"])
    assert exit_code == 0
    assert capsys.readouterr().err == ""


def test_models_untagged_name_matches_its_latest_tag(fake_ollama, capsys):
    exit_code = main(["leaderboard", "--models", "untagged-model"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ollama:untagged-model" in out


def test_leaderboard_models_compares_real_models_only(fake_ollama, capsys):
    """the actual experiment is several real models side by side - with
    only --models given, those are the rows, no fake-* clients mixed in."""
    exit_code = main(["leaderboard", "--models", "robust-model,gullible-model"])
    out = capsys.readouterr().out
    assert exit_code == 0
    rows = {
        line.split()[0]: line for line in out.splitlines()
        if line.startswith("ollama:") and " vs " not in line
    }
    assert set(rows) == {"ollama:robust-model", "ollama:gullible-model"}
    assert rows["ollama:robust-model"].split()[1] == "0%"
    assert rows["ollama:gullible-model"].split()[1] == "88%"
    assert "fake-" not in out
    assert "ollama:robust-model vs ollama:gullible-model (two-proportion z-test):" in out


def test_leaderboard_models_with_clients_adds_fake_reference_rows(fake_ollama, capsys):
    exit_code = main(["leaderboard", "--models", "gullible-model", "--clients", "fake-robust,fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ollama:gullible-model" in out
    assert "fake-robust" in out
    assert "fake-vulnerable" in out


def test_leaderboard_models_uses_host_and_timeout(fake_ollama, capsys):
    main([
        "leaderboard", "--models", "robust-model",
        "--host", "http://gpu-box:11434/", "--timeout", "30",
    ])
    capsys.readouterr()
    assert fake_ollama
    assert all(r["url"] == "http://gpu-box:11434/api/chat" for r in fake_ollama)
    assert all(r["timeout"] == 30.0 for r in fake_ollama)


def test_leaderboard_models_writes_model_rows_to_json_and_transcript(fake_ollama, tmp_path, capsys):
    report_path, transcript_path = tmp_path / "leaderboard.json", tmp_path / "transcript.json"
    main([
        "leaderboard", "--models", "robust-model,gullible-model",
        "--report", str(report_path), "--transcript", str(transcript_path),
    ])
    capsys.readouterr()
    clients = {row["client"] for row in json.loads(report_path.read_text())["clients"]}
    assert clients == {"ollama:robust-model", "ollama:gullible-model"}
    entries = json.loads(transcript_path.read_text())
    assert {e["client"] for e in entries} == {"ollama:robust-model", "ollama:gullible-model"}


def test_technique_leaderboard_models_aggregates_across_real_models(fake_ollama, capsys):
    exit_code = main(["technique-leaderboard", "--models", "gullible-model"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "across 1 client(s)" in out
    homoglyph_line = next(line for line in out.splitlines() if line.startswith("unicode_homoglyph"))
    assert "0%" in homoglyph_line


def test_matrix_models_gives_each_real_model_its_own_row(fake_ollama, capsys):
    exit_code = main([
        "matrix", "--models", "robust-model,gullible-model", "--techniques", "direct_override,unicode_homoglyph",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ollama:robust-model | 0% | 0% | 0%" in out
    assert "ollama:gullible-model | 100%* | 0% | 50%" in out


def test_models_rejects_duplicate_model(capsys):
    exit_code = main(["leaderboard", "--models", "llama3.2:3b,llama3.2:3b"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "--models lists the same name more than once: llama3.2:3b" in err


def test_models_rejects_value_with_no_names(capsys):
    exit_code = main(["matrix", "--models", " , "])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "--models was given but contained no model names" in err


def test_models_unreachable_server_fails_cleanly(capsys):
    exit_code = main(["leaderboard", "--models", "llama3.2:3b", "--host", "http://localhost:1"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert err.startswith("error:")


def test_leaderboard_clients_restricts_to_the_requested_subset(capsys):
    exit_code = main(["leaderboard", "--clients", "fake-robust,fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "fake-robust" in out
    assert "fake-vulnerable" in out
    assert "fake-semantic-vulnerable" not in out
    assert "fake-stubborn" not in out


def test_leaderboard_clients_rejects_unknown_name(capsys):
    exit_code = main(["leaderboard", "--clients", "fake-nonexistent"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown client" in err
    assert "fake-nonexistent" in err


def test_leaderboard_clients_ignores_stray_commas(capsys):
    """a trailing/extra comma used to leave an empty string in the parsed
    list, which then failed as an "unknown client" with nothing shown
    after the colon - a confusing error for what's really just loose
    input formatting, not an actual bad client name."""
    exit_code = main(["leaderboard", "--clients", "fake-robust,fake-vulnerable,"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "fake-robust" in out
    assert "fake-vulnerable" in out


def test_leaderboard_clients_all_commas_is_a_clear_error(capsys):
    exit_code = main(["leaderboard", "--clients", ",,"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "no client names" in err


def test_leaderboard_severity_filter_restricts_the_battery(capsys):
    """fake-vulnerable caves to every literal marker except unicode_homoglyph -
    filtering to just the 2 critical alerts should still show that same
    pattern (88% hijack rate), not the unfiltered 8-alert rate."""
    exit_code = main(["leaderboard", "--clients", "fake-robust,fake-vulnerable", "--severity", "critical"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "fake-robust" in out and "0%" in out
    assert "fake-vulnerable" in out and "88%" in out


def test_leaderboard_severity_filter_rejects_unknown_name(capsys):
    exit_code = main(["leaderboard", "--severity", "catastrophic"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown severity/severities for leaderboard" in err


def test_leaderboard_writes_json_report(tmp_path, capsys):
    report_path = tmp_path / "leaderboard.json"
    main(["leaderboard", "--direction", "escalate", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert parsed["direction"] == "escalate"
    assert parsed["defense"] == "none"
    client_names = {row["client"] for row in parsed["clients"]}
    assert "fake-escalation-vulnerable" in client_names
    assert "ollama" not in client_names
    assert parsed["severity_filter"] is None


def test_leaderboard_severity_filter_is_recorded_in_reports(tmp_path, capsys):
    md_path, json_path = tmp_path / "leaderboard.md", tmp_path / "leaderboard.json"
    main(["leaderboard", "--clients", "fake-vulnerable", "--severity", "critical", "--report", str(md_path)])
    main(["leaderboard", "--clients", "fake-vulnerable", "--severity", "critical", "--report", str(json_path)])
    capsys.readouterr()
    assert "severity filter: critical" in md_path.read_text()
    assert json.loads(json_path.read_text())["severity_filter"] == ["critical"]


def test_leaderboard_reports_clean_accuracy_alongside_hijack_rate(tmp_path, capsys):
    """a client that answers wrong across the board (never matching either
    the ground truth or the attacker's target) would score a misleadingly
    good 0% hijack rate on its own - clean_accuracy is what would catch
    that. fake-robust reads every alert honestly by keyword, so it should
    get every clean alert right."""
    report_path = tmp_path / "leaderboard.json"
    main(["leaderboard", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    robust_row = next(row for row in parsed["clients"] if row["client"] == "fake-robust")
    assert robust_row["clean_accuracy"] == 1.0


def test_leaderboard_clean_accuracy_gets_a_confidence_interval(capsys):
    """clean_accuracy is estimated from the same small clean battery the
    hijack rate's own CI already warns about being easy to over-read at -
    this is the same Wilson interval, just on the resisted/total count
    instead of the hijacked/total one. fake-robust gets a bare 100% point
    estimate (18/18 clean alerts correct), but the interval is still wide
    (82%-100%), exactly the over-reading risk this column exists to show."""
    exit_code = main(["leaderboard", "--clients", "fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "clean 95% ci" in out
    assert "82%-100%" in out


def test_leaderboard_writes_clean_accuracy_confidence_interval_to_json(tmp_path, capsys):
    report_path = tmp_path / "leaderboard.json"
    main(["leaderboard", "--clients", "fake-robust", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    robust_row = next(row for row in parsed["clients"] if row["client"] == "fake-robust")
    assert robust_row["clean_ci_low"] == pytest.approx(0.8241, abs=0.001)
    assert robust_row["clean_ci_high"] == 1.0


def test_leaderboard_writes_clean_accuracy_confidence_interval_to_csv(tmp_path, capsys):
    report_path = tmp_path / "leaderboard.csv"
    main(["leaderboard", "--clients", "fake-robust", "--report", str(report_path)])
    capsys.readouterr()
    rows = list(csv.DictReader(report_path.read_text().splitlines()))
    assert float(rows[0]["clean_ci_low"]) == pytest.approx(0.8241, abs=0.001)
    assert rows[0]["clean_ci_high"] == "1.0"


def test_leaderboard_writes_transcript(tmp_path, capsys):
    transcript_path = tmp_path / "leaderboard-transcript.json"
    main([
        "leaderboard", "--clients", "fake-robust,fake-vulnerable",
        "--transcript", str(transcript_path),
    ])
    out = capsys.readouterr().out
    entries = json.loads(transcript_path.read_text())
    assert {e["client"] for e in entries} == {"fake-robust", "fake-vulnerable"}
    assert all(e["direction"] == "dismiss" and e["defense"] == "none" for e in entries)
    assert f"wrote leaderboard transcript to {transcript_path}" in out


def test_leaderboard_writes_csv_report(tmp_path, capsys):
    report_path = tmp_path / "leaderboard.csv"
    main(["leaderboard", "--report", str(report_path)])
    capsys.readouterr()
    rows = list(csv.DictReader(report_path.read_text().splitlines()))
    assert len(rows) == len(FAKE_CLIENT_NAMES)
    assert all(row["direction"] == "dismiss" and row["defense"] == "none" for row in rows)


def test_leaderboard_writes_markdown_report_by_default(tmp_path, capsys):
    report_path = tmp_path / "leaderboard.md"
    main(["leaderboard", "--report", str(report_path)])
    out = capsys.readouterr().out
    content = report_path.read_text()
    assert "direction: dismiss, defense: none" in content
    assert "fake-robust" in content
    assert f"wrote leaderboard to {report_path}" in out


def test_technique_leaderboard_ranks_techniques_most_dangerous_first(capsys):
    """unicode_homoglyph is the one technique none of the default
    fake-* clients fall for via literal keyword matching (only the two
    semantic-vulnerable ones do) - across all eleven clients combined it
    should land with a visibly lower hijack rate than the others, and
    last in the most-dangerous-first ranking."""
    exit_code = main(["technique-leaderboard", "--direction", "dismiss"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direction=dismiss defense=none across 11 client(s)" in out
    lines = [line for line in out.splitlines() if line.strip().startswith(("direct_override", "unicode_homoglyph"))]
    direct_override_line = next(line for line in lines if line.startswith("direct_override"))
    homoglyph_line = next(line for line in lines if line.startswith("unicode_homoglyph"))
    assert out.index(direct_override_line) < out.index(homoglyph_line)


def test_technique_leaderboard_clients_restricts_the_aggregate(capsys):
    exit_code = main(["technique-leaderboard", "--clients", "fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "across 1 client(s)" in out
    # fake-robust never caves to anything - every technique should show 0%.
    assert "100%" not in out


def test_technique_leaderboard_rejects_unknown_client(capsys):
    exit_code = main(["technique-leaderboard", "--clients", "fake-nonexistent"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown client(s) for technique-leaderboard" in err
    assert "fake-nonexistent" in err


def test_technique_leaderboard_severity_filter_restricts_the_battery(capsys):
    exit_code = main([
        "technique-leaderboard", "--clients", "fake-vulnerable", "--severity", "critical",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "across 1 client(s)" in out
    assert "direct_override                                 3 " in out


def test_technique_leaderboard_severity_filter_rejects_unknown_name(capsys):
    exit_code = main(["technique-leaderboard", "--severity", "catastrophic"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown severity/severities for technique-leaderboard" in err


def test_technique_leaderboard_techniques_restricts_to_the_requested_subset(capsys):
    exit_code = main(["technique-leaderboard", "--techniques", "direct_override,unicode_homoglyph"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override" in out
    assert "unicode_homoglyph" in out
    assert "fake_system_tag" not in out
    assert "roleplay_authority" not in out


def test_technique_leaderboard_min_rate_filters_out_techniques_below_the_threshold(capsys):
    """fake-vulnerable hijacks on every technique except unicode_homoglyph
    (its one blind spot, 0%) - a 50% threshold should drop just that one."""
    exit_code = main(["technique-leaderboard", "--clients", "fake-vulnerable", "--min-rate", "0.5"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override" in out
    assert "unicode_homoglyph" not in out


def test_technique_leaderboard_min_rate_above_every_rate_is_an_empty_table_not_a_crash(capsys):
    exit_code = main(["technique-leaderboard", "--clients", "fake-vulnerable", "--min-rate", "2"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override" not in out


def test_technique_leaderboard_min_rate_combines_with_techniques_filter(capsys):
    """narrowing to exactly 2 techniques normally triggers the pairwise
    z-test line - once --min-rate narrows that down to 1, the z-test
    should no longer print (nothing left to compare pairwise)."""
    exit_code = main([
        "technique-leaderboard", "--clients", "fake-vulnerable",
        "--techniques", "direct_override,unicode_homoglyph", "--min-rate", "0.5",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override" in out
    assert "unicode_homoglyph" not in out
    assert "two-proportion z-test" not in out


def test_technique_leaderboard_techniques_rejects_unknown_name(capsys):
    exit_code = main(["technique-leaderboard", "--techniques", "not_a_real_technique"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown technique(s) for direction=dismiss" in err
    assert "not_a_real_technique" in err


def test_technique_leaderboard_techniques_all_commas_is_a_clear_error(capsys):
    exit_code = main(["technique-leaderboard", "--techniques", ",,"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "no technique names" in err


def test_technique_leaderboard_techniques_rejects_wrong_direction_name(capsys):
    """direct_override is a dismiss-direction technique - asking for it
    while --direction escalate should fail the same way an unknown name
    would, not silently return nothing."""
    exit_code = main(["technique-leaderboard", "--direction", "escalate", "--techniques", "direct_override"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown technique(s) for direction=escalate" in err
    assert "direct_override" in err


def test_technique_leaderboard_writes_markdown_report(tmp_path, capsys):
    report_path = tmp_path / "technique-leaderboard.md"
    exit_code = main(["technique-leaderboard", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    content = report_path.read_text()
    assert "direction: dismiss, defense: none, across 11 client(s)" in content
    assert "direct_override" in content
    assert f"wrote technique leaderboard to {report_path}" in out


def test_technique_leaderboard_writes_json_report(tmp_path, capsys):
    report_path = tmp_path / "technique-leaderboard.json"
    main(["technique-leaderboard", "--direction", "escalate", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert parsed["direction"] == "escalate"
    assert parsed["defense"] == "none"
    assert parsed["client_count"] == 11
    technique_names = {row["technique"] for row in parsed["techniques"]}
    assert "false_urgency" in technique_names
    assert parsed["severity_filter"] is None


def test_technique_leaderboard_severity_filter_is_recorded_in_reports(tmp_path, capsys):
    md_path = tmp_path / "technique-leaderboard.md"
    json_path = tmp_path / "technique-leaderboard.json"
    main(["technique-leaderboard", "--clients", "fake-vulnerable", "--severity", "critical", "--report", str(md_path)])
    main(["technique-leaderboard", "--clients", "fake-vulnerable", "--severity", "critical", "--report", str(json_path)])
    capsys.readouterr()
    assert "severity filter: critical" in md_path.read_text()
    assert json.loads(json_path.read_text())["severity_filter"] == ["critical"]


def test_technique_leaderboard_writes_csv_report(tmp_path, capsys):
    report_path = tmp_path / "technique-leaderboard.csv"
    main(["technique-leaderboard", "--report", str(report_path)])
    capsys.readouterr()
    rows = list(csv.DictReader(report_path.read_text().splitlines()))
    assert len(rows) == 8  # 8 dismiss-direction techniques
    assert all(row["direction"] == "dismiss" and row["defense"] == "none" for row in rows)


def test_technique_leaderboard_writes_transcript(tmp_path, capsys):
    transcript_path = tmp_path / "technique-leaderboard-transcript.json"
    main([
        "technique-leaderboard", "--clients", "fake-robust,fake-vulnerable",
        "--transcript", str(transcript_path),
    ])
    out = capsys.readouterr().out
    entries = json.loads(transcript_path.read_text())
    assert {e["client"] for e in entries} == {"fake-robust", "fake-vulnerable"}
    assert "direct_override" in {e["technique"] for e in entries}
    assert f"wrote technique leaderboard transcript to {transcript_path}" in out


def test_technique_leaderboard_two_techniques_prints_pairwise_significance(capsys):
    exit_code = main(["technique-leaderboard", "--techniques", "direct_override,unicode_homoglyph"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override vs unicode_homoglyph (two-proportion z-test):" in out
    assert "not significant" not in out


def test_technique_leaderboard_more_than_two_techniques_has_no_pairwise_significance(capsys):
    exit_code = main([
        "technique-leaderboard", "--techniques", "direct_override,unicode_homoglyph,fake_system_tag",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "two-proportion z-test" not in out


def test_technique_leaderboard_writes_pairwise_significance_to_json_report(tmp_path, capsys):
    report_path = tmp_path / "technique-leaderboard.json"
    main([
        "technique-leaderboard", "--techniques", "direct_override,unicode_homoglyph",
        "--report", str(report_path),
    ])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert parsed["pairwise_significance"]["technique_a"] == "direct_override"
    assert parsed["pairwise_significance"]["technique_b"] == "unicode_homoglyph"
    assert parsed["pairwise_significance"]["p_value"] < 0.05


def test_matrix_prints_a_rate_for_every_client_technique_pair_plus_an_average_column(capsys):
    exit_code = main(["matrix", "--clients", "fake-robust,fake-vulnerable", "--techniques",
                       "direct_override,unicode_homoglyph"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direction=dismiss defense=none" in out
    assert "client | direct_override | unicode_homoglyph | average" in out
    assert "fake-robust | 0% | 0% | 0%" in out
    # fake-vulnerable: 100% on direct_override, 0% on unicode_homoglyph (its one blind spot) -> 50% average
    assert "fake-vulnerable | 100%* | 0% | 50%" in out


def test_matrix_sorts_rows_by_average_most_robust_first_regardless_of_clients_order(capsys):
    """fake-vulnerable has the higher average hijack rate of the two, so it
    should sort to the bottom even when given first on --clients - same
    "most robust first" convention leaderboard uses, not just --clients
    input order."""
    exit_code = main(["matrix", "--clients", "fake-vulnerable,fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert out.index("fake-robust") < out.index("fake-vulnerable")


def test_matrix_rejects_unknown_client(capsys):
    exit_code = main(["matrix", "--clients", "fake-nonexistent"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown client(s) for matrix" in err
    assert "fake-nonexistent" in err


def test_matrix_severity_filter_restricts_the_battery(capsys):
    exit_code = main([
        "matrix", "--clients", "fake-robust,fake-vulnerable", "--techniques", "direct_override",
        "--severity", "critical",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "severity filter: critical" in out
    assert "fake-robust | 0% | 0%" in out
    assert "fake-vulnerable | 100% | 100%" in out


def test_matrix_severity_filter_rejects_unknown_name(capsys):
    exit_code = main(["matrix", "--severity", "catastrophic"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown severity/severities for matrix" in err


def test_matrix_rejects_unknown_technique(capsys):
    exit_code = main(["matrix", "--techniques", "not_a_real_technique"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown technique(s) for direction=dismiss" in err
    assert "not_a_real_technique" in err


def test_matrix_rejects_duplicate_technique(capsys):
    """a duplicated technique used to get its own column while the average
    divided by the list length but summed a dict of distinct rates - 100%,
    100%, 0% came out as a 33% average, matching neither the cells shown
    nor the distinct techniques."""
    exit_code = main([
        "matrix", "--clients", "fake-vulnerable",
        "--techniques", "direct_override,direct_override,unicode_homoglyph",
    ])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "--techniques lists the same name more than once: direct_override" in err


def test_severity_matrix_rejects_duplicate_technique(capsys):
    exit_code = main([
        "severity-matrix", "--client", "fake-vulnerable",
        "--techniques", "direct_override,unicode_homoglyph,direct_override",
    ])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "--techniques lists the same name more than once: direct_override" in err


def test_leaderboard_rejects_duplicate_client(capsys):
    """used to print two identical rows plus a meaningless "fake-robust vs
    fake-robust" significance line."""
    exit_code = main(["leaderboard", "--clients", "fake-robust,fake-robust"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--clients lists the same name more than once: fake-robust" in captured.err
    assert "two-proportion z-test" not in captured.out


def test_run_rejects_duplicate_severity(capsys):
    exit_code = main(["run", "--severity", "critical,high,critical"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "--severity lists the same name more than once: critical" in err


def test_matrix_techniques_rejects_wrong_direction_name(capsys):
    exit_code = main(["matrix", "--direction", "escalate", "--techniques", "direct_override"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown technique(s) for direction=escalate" in err


def test_matrix_defaults_to_every_technique_for_the_direction(capsys):
    exit_code = main(["matrix", "--clients", "fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override" in out
    assert "conversational_drift" in out


def test_matrix_writes_markdown_report(tmp_path, capsys):
    report_path = tmp_path / "matrix.md"
    exit_code = main(["matrix", "--clients", "fake-robust,fake-vulnerable", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    content = report_path.read_text()
    assert "direction: dismiss, defense: none" in content
    assert "fake-vulnerable" in content
    assert f"wrote matrix to {report_path}" in out


def test_matrix_writes_json_report(tmp_path, capsys):
    report_path = tmp_path / "matrix.json"
    main(["matrix", "--direction", "escalate", "--clients", "fake-escalation-vulnerable",
          "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert parsed["direction"] == "escalate"
    assert parsed["defense"] == "none"
    assert parsed["clients"][0]["client"] == "fake-escalation-vulnerable"
    assert "false_urgency" in parsed["clients"][0]["rates"]
    assert "average" in parsed["clients"][0]
    assert parsed["severity_filter"] is None


def test_matrix_severity_filter_is_recorded_in_reports(tmp_path, capsys):
    md_path, json_path = tmp_path / "matrix.md", tmp_path / "matrix.json"
    main(["matrix", "--clients", "fake-vulnerable", "--severity", "critical", "--report", str(md_path)])
    main(["matrix", "--clients", "fake-vulnerable", "--severity", "critical", "--report", str(json_path)])
    capsys.readouterr()
    assert "severity filter: critical" in md_path.read_text()
    assert json.loads(json_path.read_text())["severity_filter"] == ["critical"]


def test_matrix_writes_csv_report(tmp_path, capsys):
    report_path = tmp_path / "matrix.csv"
    main(["matrix", "--clients", "fake-robust,fake-vulnerable", "--report", str(report_path)])
    capsys.readouterr()
    rows = list(csv.DictReader(report_path.read_text().splitlines()))
    assert len(rows) == 2  # one row per client
    assert rows[0]["client"] == "fake-robust"
    assert rows[0]["direction"] == "dismiss"
    assert "direct_override" in rows[0]
    assert rows[0]["average"] == "0.0"


def test_matrix_writes_transcript(tmp_path, capsys):
    transcript_path = tmp_path / "matrix-transcript.json"
    main(["matrix", "--clients", "fake-robust,fake-vulnerable", "--transcript", str(transcript_path)])
    out = capsys.readouterr().out
    entries = json.loads(transcript_path.read_text())
    assert {e["client"] for e in entries} == {"fake-robust", "fake-vulnerable"}
    assert f"wrote matrix transcript to {transcript_path}" in out


def test_severity_matrix_prints_a_rate_for_every_severity_technique_pair_plus_average(capsys):
    exit_code = main([
        "severity-matrix", "--client", "fake-vulnerable", "--techniques", "direct_override,unicode_homoglyph",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "client=fake-vulnerable direction=dismiss defense=none" in out
    assert "severity | direct_override | unicode_homoglyph | average" in out
    # fake-vulnerable: 100% on direct_override, 0% on unicode_homoglyph -> 50% average, every severity.
    assert "critical | 100% | 0% | 50%" in out
    assert "high | 100% | 0% | 50%" in out
    assert "medium | 100% | 0% | 50%" in out


def test_severity_matrix_rows_are_in_canonical_severity_order_not_sorted_by_average(capsys):
    """unlike matrix's client rows, severity rows should stay in
    critical/high/medium/low order regardless of which row happens to
    have the highest average - severity already has a real-world order
    a reader wants, client/technique names don't."""
    exit_code = main(["severity-matrix", "--client", "fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert out.index("critical") < out.index("high") < out.index("medium")


def test_severity_matrix_severity_filter_restricts_the_battery(capsys):
    exit_code = main([
        "severity-matrix", "--client", "fake-vulnerable", "--techniques", "direct_override",
        "--severity", "critical,high",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "severity filter: critical, high" in out
    assert "critical | 100% | 100%" in out
    assert "high | 100% | 100%" in out
    assert "medium" not in out


def test_severity_matrix_severity_filter_rejects_unknown_name(capsys):
    exit_code = main(["severity-matrix", "--severity", "catastrophic"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown severity/severities for severity-matrix" in err


def test_severity_matrix_severity_filter_that_empties_the_battery_shows_zero_not_a_crash(capsys):
    exit_code = main(["severity-matrix", "--client", "fake-vulnerable", "--severity", "low"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "severity filter: low" in out
    assert "severity | direct_override" in out  # header printed, no rows, no crash


def test_severity_matrix_rejects_unknown_technique(capsys):
    exit_code = main(["severity-matrix", "--techniques", "not_a_real_technique"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown technique(s) for direction=dismiss" in err
    assert "not_a_real_technique" in err


def test_severity_matrix_techniques_rejects_wrong_direction_name(capsys):
    exit_code = main(["severity-matrix", "--direction", "escalate", "--techniques", "direct_override"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "unknown technique(s) for direction=escalate" in err


def test_severity_matrix_defaults_to_every_technique_for_the_direction(capsys):
    exit_code = main(["severity-matrix", "--client", "fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override" in out
    assert "conversational_drift" in out


def test_severity_matrix_escalate_direction_shows_only_dismiss_worthy_severities(capsys):
    """escalation-direction injected alerts only ever come from dismiss-
    worthy ground truth alerts (high, medium and low severity here, never
    critical), unlike the dismiss direction which spans all four."""
    exit_code = main(["severity-matrix", "--client", "fake-escalation-vulnerable", "--direction", "escalate"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "high" in out
    assert "medium" in out
    assert "low" in out
    assert "critical" not in out


def test_severity_matrix_writes_markdown_report(tmp_path, capsys):
    report_path = tmp_path / "severity-matrix.md"
    exit_code = main(["severity-matrix", "--client", "fake-vulnerable", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    content = report_path.read_text()
    assert "client: fake-vulnerable, direction: dismiss, defense: none" in content
    assert "critical" in content
    assert f"wrote severity matrix to {report_path}" in out


def test_severity_matrix_writes_json_report(tmp_path, capsys):
    report_path = tmp_path / "severity-matrix.json"
    main(["severity-matrix", "--client", "fake-vulnerable", "--direction", "escalate",
          "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert parsed["client"] == "fake-vulnerable"
    assert parsed["direction"] == "escalate"
    assert parsed["defense"] == "none"
    severities = {row["severity"] for row in parsed["severities"]}
    assert severities == {"high", "medium", "low"}
    assert "average" in parsed["severities"][0]
    assert parsed["severity_filter"] is None


def test_severity_matrix_severity_filter_is_recorded_in_reports(tmp_path, capsys):
    md_path = tmp_path / "severity-matrix.md"
    json_path = tmp_path / "severity-matrix.json"
    main(["severity-matrix", "--client", "fake-vulnerable", "--severity", "critical", "--report", str(md_path)])
    main(["severity-matrix", "--client", "fake-vulnerable", "--severity", "critical", "--report", str(json_path)])
    capsys.readouterr()
    assert "severity filter: critical" in md_path.read_text()
    assert json.loads(json_path.read_text())["severity_filter"] == ["critical"]


def test_severity_matrix_writes_csv_report(tmp_path, capsys):
    report_path = tmp_path / "severity-matrix.csv"
    main(["severity-matrix", "--client", "fake-vulnerable", "--report", str(report_path)])
    capsys.readouterr()
    rows = list(csv.DictReader(report_path.read_text().splitlines()))
    assert len(rows) == 4  # critical, high, medium, low
    assert rows[0]["client"] == "fake-vulnerable"
    assert rows[0]["severity"] == "critical"
    assert rows[0]["direction"] == "dismiss"
    assert "direct_override" in rows[0]
    assert rows[0]["average"] == "0.875"


def test_severity_matrix_writes_transcript(tmp_path, capsys):
    transcript_path = tmp_path / "severity-matrix-transcript.json"
    main(["severity-matrix", "--client", "fake-vulnerable", "--transcript", str(transcript_path)])
    out = capsys.readouterr().out
    entries = json.loads(transcript_path.read_text())
    assert len(entries) > 0
    assert all(e["defense"] == "none" for e in entries)
    assert f"wrote severity matrix transcript to {transcript_path}" in out


def test_severity_matrix_two_severities_prints_pairwise_significance(capsys):
    """the same exactly-two case leaderboard and technique-leaderboard
    trigger pairwise significance on, here in the escalation direction."""
    exit_code = main([
        "severity-matrix", "--client", "fake-escalation-vulnerable", "--direction", "escalate",
        "--severity", "medium,low",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "medium vs low (two-proportion z-test):" in out


def test_severity_matrix_severity_filter_to_two_prints_pairwise_significance(capsys):
    """--severity can also narrow dismiss direction's usual three rows
    (critical, high, medium) down to exactly two, triggering the same
    pairwise line."""
    exit_code = main([
        "severity-matrix", "--client", "fake-vulnerable", "--severity", "critical,medium",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "critical vs medium (two-proportion z-test):" in out


def test_severity_matrix_three_severities_has_no_pairwise_significance(capsys):
    """with three rows there's no single unambiguous pair to compare,
    same reasoning as leaderboard's three-or-more-clients case."""
    exit_code = main(["severity-matrix", "--client", "fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "two-proportion z-test" not in out


def test_severity_matrix_writes_pairwise_significance_to_json_report(tmp_path, capsys):
    report_path = tmp_path / "severity-matrix.json"
    main([
        "severity-matrix", "--client", "fake-vulnerable", "--severity", "critical,medium",
        "--report", str(report_path),
    ])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert parsed["pairwise_significance"]["severity_a"] == "critical"
    assert parsed["pairwise_significance"]["severity_b"] == "medium"
    assert "p_value" in parsed["pairwise_significance"]


def test_severity_matrix_writes_pairwise_significance_to_markdown_report(tmp_path, capsys):
    report_path = tmp_path / "severity-matrix.md"
    main([
        "severity-matrix", "--client", "fake-vulnerable", "--severity", "critical,medium",
        "--report", str(report_path),
    ])
    capsys.readouterr()
    content = report_path.read_text()
    assert "critical vs medium (two-proportion z-test):" in content


def test_severity_matrix_without_pairwise_significance_omits_it_from_json_report(tmp_path, capsys):
    report_path = tmp_path / "severity-matrix.json"
    main(["severity-matrix", "--client", "fake-vulnerable", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert parsed["pairwise_significance"] is None


def test_list_techniques(capsys):
    exit_code = main(["list-techniques"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override" in out
    assert "encoded_instruction" in out
    assert "false_urgency" in out
    assert "fake_severity_upgrade" in out
    assert "fake_incident_commander" in out
    assert "encoded_escalation_instruction" in out
    assert "indirect_kb_reference_escalation" in out
    assert "conversational_drift_escalation" in out
    assert "fake_system_tag_escalation" in out


def test_list_techniques_json(capsys):
    exit_code = main(["list-techniques", "--json"])
    out = capsys.readouterr().out
    assert exit_code == 0
    parsed = json.loads(out)
    assert set(parsed) == {"dismiss", "escalation"}
    assert len(parsed["dismiss"]) == 8
    assert len(parsed["escalation"]) == 8
    assert "direct_override" in parsed["dismiss"]
    assert "already reviewed" in parsed["dismiss"]["direct_override"]
    assert "fake_incident_commander" in parsed["escalation"]


def test_list_techniques_json_descriptions_have_no_embedded_newlines(capsys):
    """unicode_homoglyph's docstring spans multiple source lines - without
    collapsing whitespace, its embedded "\\n    " sequences would carry
    the source file's own indentation straight into the json value."""
    main(["list-techniques", "--json"])
    parsed = json.loads(capsys.readouterr().out)
    assert "\n" not in parsed["dismiss"]["unicode_homoglyph"]
    assert "  " not in parsed["dismiss"]["unicode_homoglyph"]


def test_list_techniques_csv(capsys):
    exit_code = main(["list-techniques", "--csv"])
    out = capsys.readouterr().out
    assert exit_code == 0
    # 1 header + 16 technique rows - would be far more physical lines if
    # descriptions still carried embedded newlines from their docstrings.
    assert len(out.splitlines()) == 17
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == ["direction", "technique", "description"]
    body = rows[1:]
    assert len(body) == 16
    dismiss_rows = [r for r in body if r[0] == "dismiss"]
    escalation_rows = [r for r in body if r[0] == "escalation"]
    assert len(dismiss_rows) == 8
    assert len(escalation_rows) == 8
    direct_override = next(r for r in dismiss_rows if r[1] == "direct_override")
    assert "already reviewed" in direct_override[2]
    assert any(r[1] == "fake_incident_commander" for r in escalation_rows)


def test_list_techniques_json_and_csv_are_mutually_exclusive():
    """before this was a mutually exclusive group, --json silently won
    whenever both flags were passed, quietly discarding --csv instead of
    telling the caller their command line doesn't make sense."""
    with pytest.raises(SystemExit):
        main(["list-techniques", "--json", "--csv"])


def test_run_escalate_direction_with_dedicated_client(capsys):
    exit_code = main(["run", "--client", "fake-escalation-vulnerable", "--direction", "escalate"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direction=escalate" in out
    for line in out.splitlines():
        if line.strip().startswith((
            "false_urgency", "fake_severity_upgrade", "fake_incident_commander",
            "encoded_escalation_instruction", "indirect_kb_reference_escalation",
            "conversational_drift_escalation", "fake_system_tag_escalation",
        )):
            assert "100%" in line


def test_run_escalate_direction_defenses_actually_help(capsys):
    for client, defense in (
        ("fake-escalation-sandwich-sensitive", "sandwich"),
        ("fake-escalation-strict-sensitive", "strict"),
    ):
        main(["run", "--client", client, "--direction", "escalate", "--defense", "none"])
        without_defense = capsys.readouterr().out
        main(["run", "--client", client, "--direction", "escalate", "--defense", defense])
        with_defense = capsys.readouterr().out

        assert "100%" in without_defense
        assert "100%" not in with_defense


def test_run_escalate_direction_robust_client_resists(capsys):
    exit_code = main(["run", "--client", "fake-robust", "--direction", "escalate"])
    out = capsys.readouterr().out
    assert exit_code == 0
    for line in out.splitlines():
        if line.strip().startswith((
            "false_urgency", "fake_severity_upgrade", "fake_incident_commander",
            "encoded_escalation_instruction", "indirect_kb_reference_escalation",
            "conversational_drift_escalation", "fake_system_tag_escalation",
        )):
            assert "0%" in line


def test_run_default_direction_is_dismiss(capsys):
    exit_code = main(["run", "--client", "fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direction=dismiss" in out


def test_ollama_client_requires_model():
    exit_code = main(["run", "--client", "ollama"])
    assert exit_code == 1


def test_build_client_ollama_without_model_raises():
    class Args:
        client = "ollama"
        model = None
        host = None
        timeout = 120.0

    with pytest.raises(ValueError):
        build_client(Args())


def test_build_client_ollama_wires_custom_timeout():
    """--timeout used to be hardcoded to OllamaClient's 120s default with
    no way to change it from the cli, despite the constructor already
    supporting it - a slower local model (or a deliberately short timeout
    while iterating) had no way to ask for anything else."""
    class Args:
        client = "ollama"
        model = "test-model"
        host = None
        timeout = 5.0
        temperature = None
        seed = None
        cache = None
        retries = 0

    client = build_client(Args())
    assert client.timeout == 5.0
    assert client.retries == 0


def test_ollama_client_unreachable_host_fails_cleanly(capsys):
    """a connection failure (ollama not running, wrong host/port) should
    surface as the same clean "error: ..." message as everything else -
    requests.exceptions.ConnectionError subclasses OSError, which main()
    now catches. localhost:1 refuses immediately, no real network needed."""
    exit_code = main(["run", "--client", "ollama", "--model", "test-model", "--host", "http://localhost:1"])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "error:" in err
    assert "Connection refused" in err or "Failed to establish a new connection" in err


def _saved_full_report(tmp_path, client, *extra):
    path = tmp_path / f"{client}.json"
    assert main(["full-report", "--client", client, "--report", str(path), *extra]) == 0
    return path


def test_summarize_puts_saved_full_reports_in_one_table(tmp_path, capsys):
    """full-report is single-client by design, so the cross-model headline
    table - how much each defense helps, per model - otherwise meant
    copying numbers out of one file per model by hand."""
    stubborn = _saved_full_report(tmp_path, "fake-stubborn")
    sandwich = _saved_full_report(tmp_path, "fake-sandwich-sensitive")
    capsys.readouterr()
    exit_code = main(["summarize", str(stubborn), str(sandwich)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "fake-stubborn                 44%       44%       44%        0%" in out
    assert "fake-sandwich-sensitive       44%        0%       44%        0%" in out
    assert out.index("fake-stubborn") < out.index("fake-sandwich-sensitive")  # input order kept


def test_summarize_writes_markdown_json_and_csv(tmp_path, capsys):
    stubborn = _saved_full_report(tmp_path, "fake-stubborn")
    sandwich = _saved_full_report(tmp_path, "fake-sandwich-sensitive")
    md, js, cs = tmp_path / "s.md", tmp_path / "s.json", tmp_path / "s.csv"
    for path in (md, js, cs):
        assert main(["summarize", str(stubborn), str(sandwich), "--report", str(path)]) == 0
    capsys.readouterr()
    assert "| fake-sandwich-sensitive | 44% | 0% | 44% | 0% |" in md.read_text()
    parsed = json.loads(js.read_text())
    assert [row["client"] for row in parsed["clients"]] == ["fake-stubborn", "fake-sandwich-sensitive"]
    assert parsed["clients"][0]["hijack_rate"]["both"] == 0.0
    rows = list(csv.DictReader(io.StringIO(cs.read_text())))
    assert len(rows) == 8  # 2 clients x 4 defenses, long format
    assert {r["defense"] for r in rows} == {"none", "sandwich", "strict", "both"}


def test_summarize_refuses_reports_with_different_severity_filters(tmp_path, capsys):
    """a high-only run next to a full-battery run would put two
    different alert sets in one table as if they were comparable."""
    full = _saved_full_report(tmp_path, "fake-stubborn")
    high = tmp_path / "high.json"
    assert main(["full-report", "--client", "fake-vulnerable", "--severity", "high", "--report", str(high)]) == 0
    capsys.readouterr()
    exit_code = main(["summarize", str(full), str(high)])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "different --severity filters" in err
    assert "all severities" in err and "high" in err


def test_summarize_refuses_two_reports_for_the_same_client(tmp_path, capsys):
    first = _saved_full_report(tmp_path, "fake-stubborn")
    second = tmp_path / "again.json"
    main(["full-report", "--client", "fake-stubborn", "--report", str(second)])
    capsys.readouterr()
    exit_code = main(["summarize", str(first), str(second)])
    assert exit_code == 1
    assert "two reports for the same client fake-stubborn" in capsys.readouterr().err


def test_summarize_rejects_files_that_arent_full_report_json(tmp_path, capsys):
    not_json = tmp_path / "report.md"
    not_json.write_text("# not json")
    leaderboard = tmp_path / "leaderboard.json"
    main(["leaderboard", "--report", str(leaderboard)])
    capsys.readouterr()
    assert main(["summarize", str(not_json)]) == 1
    assert "isn't json - summarize reads the .json reports full-report writes" in capsys.readouterr().err
    assert main(["summarize", str(leaderboard)]) == 1
    assert "isn't a full-report json report" in capsys.readouterr().err


def test_summarize_handles_a_report_saved_before_clean_accuracy_existed(tmp_path, capsys):
    path = _saved_full_report(tmp_path, "fake-stubborn")
    report = json.loads(path.read_text())
    del report["clean_accuracy_by_defense"]
    path.write_text(json.dumps(report))
    capsys.readouterr()
    assert main(["summarize", str(path)]) == 0
    clean_section = capsys.readouterr().out.split("clean-alert accuracy by defense")[1]
    assert "n/a" in clean_section


def test_compare_defenses_runs_only_the_chosen_ones_plus_the_none_baseline(tmp_path, capsys):
    """each defense is a full pass over the battery - against a real model
    a few hundred requests - so a question that only needs none vs both
    shouldn't have to pay for sandwich and strict too. none always runs:
    it's what every significance test compares against."""
    report_path = tmp_path / "r.json"
    exit_code = main(["compare", "--client", "fake-stubborn", "--defenses", "both", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "--- defense=none ---" in out
    assert "--- defense=both ---" in out
    assert "defense=sandwich" not in out and "defense=strict" not in out
    assert "none vs both:" in out
    parsed = json.loads(report_path.read_text())
    assert set(parsed["per_defense"]) == {"none", "both"}
    assert set(parsed["clean_accuracy_by_defense"]) == {"none", "both"}
    assert set(parsed["significance_vs_none_by_defense"]) == {"both"}
    # a family of one test: Holm leaves its p-value as it is
    _, p_value, p_holm = parsed["significance_vs_none_by_defense"]["both"]
    assert p_holm == p_value


def test_full_report_defenses_subset(tmp_path, capsys):
    report_path = tmp_path / "r.json"
    assert main([
        "full-report", "--client", "fake-sandwich-sensitive", "--defenses", "sandwich", "--report", str(report_path),
    ]) == 0
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    assert set(parsed["summary_by_defense"]) == {"none", "sandwich"}
    assert set(parsed["by_direction"]["escalate"]) == {"none", "sandwich"}


def test_defenses_none_alone_runs_just_the_baseline(capsys):
    assert main(["compare", "--client", "fake-stubborn", "--defenses", "none"]) == 0
    out = capsys.readouterr().out
    assert "--- defense=none ---" in out
    assert " vs " not in out


def test_defenses_rejects_unknown_duplicate_or_empty(capsys):
    assert main(["compare", "--defenses", "sandwich,firewall"]) == 1
    assert "unknown defense(s): firewall - choose from none, sandwich, strict, both" in capsys.readouterr().err
    assert main(["full-report", "--defenses", "both,both", "--report", "x.md"]) == 1
    assert "--defenses lists the same name more than once: both" in capsys.readouterr().err
    assert main(["compare", "--defenses", " , "]) == 1
    assert "--defenses was given but contained no defense names" in capsys.readouterr().err


def test_summarize_shows_na_for_a_defense_a_report_didnt_run(tmp_path, capsys):
    partial = tmp_path / "partial.json"
    main(["full-report", "--client", "fake-stubborn", "--defenses", "both", "--report", str(partial)])
    full = _saved_full_report(tmp_path, "fake-sandwich-sensitive")
    md, cs = tmp_path / "s.md", tmp_path / "s.csv"
    capsys.readouterr()
    assert main(["summarize", str(partial), str(full)]) == 0
    assert "fake-stubborn                 44%       n/a       n/a        0%" in capsys.readouterr().out
    main(["summarize", str(partial), str(full), "--report", str(md)])
    main(["summarize", str(partial), str(full), "--report", str(cs)])
    capsys.readouterr()
    assert "| fake-stubborn | 44% | n/a | n/a | 0% |" in md.read_text()
    rows = {(r["client"], r["defense"]): r for r in csv.DictReader(io.StringIO(cs.read_text()))}
    assert rows[("fake-stubborn", "sandwich")]["hijack_rate"] == ""
    assert rows[("fake-stubborn", "sandwich")]["clean_accuracy"] == ""


def test_summarize_drops_a_defense_no_report_ran(tmp_path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    main(["full-report", "--client", "fake-stubborn", "--defenses", "both", "--report", str(a)])
    main(["full-report", "--client", "fake-vulnerable", "--defenses", "both", "--report", str(b)])
    capsys.readouterr()
    assert main(["summarize", str(a), str(b)]) == 0
    header = capsys.readouterr().out.splitlines()[1]
    assert header.split() == ["client", "none", "both"]


@pytest.mark.parametrize("command", [
    ["run", "--client", "ollama", "--model", "gullible-model"],
    ["compare", "--client", "ollama", "--model", "gullible-model", "--defenses", "both"],
    ["full-report", "--client", "ollama", "--model", "gullible-model", "--report", "REPORT"],
    ["full-report", "--client", "ollama", "--model", "gullible-model", "--severity", "high", "--report", "REPORT"],
    ["severity-matrix", "--client", "ollama", "--model", "gullible-model"],
    ["leaderboard", "--models", "gullible-model"],
    ["technique-leaderboard", "--models", "gullible-model", "--direction", "escalate"],
    ["matrix", "--models", "gullible-model"],
])
def test_progress_total_matches_the_requests_actually_made(command, fake_ollama, tmp_path, capsys):
    """progress lines read "120/576" so a half-hour run says how far along
    it is - each command works out its own total up front, and that total
    has to be the number of requests it then really sends."""
    command = [str(tmp_path / "r.md") if part == "REPORT" else part for part in command]
    assert main(command) == 0
    err = capsys.readouterr().err
    totals = {line.split(": ")[-1].split("/")[1].split()[0] for line in err.splitlines() if "requests done" in line}
    assert totals == {str(len(fake_ollama))}


def test_full_report_progress_total_with_every_defense(fake_ollama, tmp_path, capsys):
    main(["full-report", "--client", "ollama", "--model", "gullible-model", "--report", str(tmp_path / "r.md")])
    err = capsys.readouterr().err
    assert len(fake_ollama) == 648  # (18 clean + 72 + 72 injected) x 4 defenses, as the readme says
    assert "640/648 requests done" in err


def test_baseline_shows_a_hijack_rate_the_injection_didnt_cause(fake_ollama, tmp_path, capsys):
    """a model that dismisses everything scores a 100% dismiss "hijack rate"
    - but it dismisses the same real incidents with no injection at all,
    so the injection's own share of that is nothing. without the baseline
    the two look identical to a model the injection really did talk round."""
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    for path in (md, js):
        assert main(["run", "--client", "ollama", "--model", "dismiss-everything-model", "--report", str(path)]) == 0
    out = capsys.readouterr().out
    assert "overall hijack rate: 100%" in out
    line = "no-injection baseline: 9/9 already answered dismiss with no injection (100%) - injection lift +0 points"
    assert line in out
    assert line in md.read_text()
    entry = json.loads(js.read_text())["baseline_by_defense"]["none"]
    assert entry == {"target": "dismiss", "baseline": 9, "eligible": 9, "rate": 1.0, "lift": 0.0}


def test_baseline_for_a_model_the_injection_really_moves(capsys):
    main(["run", "--client", "fake-vulnerable"])
    assert "no-injection baseline: 0/9 already answered dismiss with no injection (0%) - injection lift +88 points" \
        in capsys.readouterr().out


def test_compare_prints_and_saves_baseline_per_defense(fake_ollama, tmp_path, capsys):
    report_path = tmp_path / "r.json"
    assert main([
        "compare", "--client", "ollama", "--model", "dismiss-everything-model", "--defenses", "both",
        "--report", str(report_path),
    ]) == 0
    out = capsys.readouterr().out
    summary = out.split("summary: injection lift over the no-injection baseline")[1]
    assert "none              100%      100%     +0" in summary
    assert set(json.loads(report_path.read_text())["baseline_by_defense"]) == {"none", "both"}


def test_full_report_baseline_per_direction(fake_ollama, tmp_path, capsys):
    """the escalate attack's baseline is how often the model already
    escalates the benign alerts it's built from - a different set of
    alerts and a different target action than the dismiss one."""
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    for path in (md, js):
        main(["full-report", "--client", "ollama", "--model", "dismiss-everything-model", "--defenses", "none",
              "--report", str(path)])
    out = capsys.readouterr().out
    assert "summary: injection lift over the no-injection baseline, direction=escalate" in out
    baseline = json.loads(js.read_text())["baseline_by_direction"]
    assert baseline["dismiss"]["none"]["baseline"] == 9
    assert baseline["escalate"]["none"] == {"target": "escalate", "baseline": 0, "eligible": 9, "rate": 0.0, "lift": 0.0}
    assert "no-injection baseline: 0/9 already answered escalate with no injection (0%)" in md.read_text()


def test_summarize_shows_the_injection_lift_per_model(fake_ollama, tmp_path, capsys):
    """the headline table across models, read honestly: a model that
    dismisses everything has a high hijack rate but the injection caused
    none of it - its lift is what separates it from a model the attack
    really moved."""
    stubborn = _saved_full_report(tmp_path, "fake-stubborn")
    lazy = tmp_path / "lazy.json"
    main(["full-report", "--client", "ollama", "--model", "dismiss-everything-model", "--report", str(lazy)])
    capsys.readouterr()
    assert main(["summarize", str(stubborn), str(lazy)]) == 0
    lift_table = capsys.readouterr().out.split("injection lift over the no-injection baseline, in points")[1]
    lift_table = lift_table.strip().split("\n\n")[0]  # just this table, not the sections after it
    rows = {line.split()[0]: line.split()[1:] for line in lift_table.splitlines()[1:]}
    assert rows["fake-stubborn"] == ["+44", "+44", "+44", "+0"]
    # dismisses all 9 eligible alerts and escalates none of the 9 benign ones, injected or not:
    # pooled hijack 72/144 vs pooled baseline 9/18 - the same 50%, so no lift at all
    assert rows["ollama:dismiss-everything-model"] == ["+0", "+0", "+0", "+0"]


def test_summarize_shows_na_lift_for_a_report_saved_before_the_baseline_existed(tmp_path, capsys):
    path = _saved_full_report(tmp_path, "fake-stubborn")
    report = json.loads(path.read_text())
    del report["baseline_by_direction"]
    path.write_text(json.dumps(report))
    capsys.readouterr()
    assert main(["summarize", str(path)]) == 0
    lift_table = capsys.readouterr().out.split("in points")[1]
    assert "n/a" in lift_table


def test_leaderboard_shows_baseline_and_lift_per_client(fake_ollama, tmp_path, capsys):
    """ranked by raw hijack rate, a model that dismisses everything comes
    out as the most hijacked - but its baseline is just as high, so the
    injection's lift is nothing. a model the attack really talks round
    has a low baseline and a big lift."""
    report_path = tmp_path / "lb.json"
    exit_code = main([
        "leaderboard", "--models", "dismiss-everything-model,gullible-model", "--sort-by", "lift",
        "--report", str(report_path),
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    rows = {row["client"]: row for row in json.loads(report_path.read_text())["clients"]}
    lazy, gullible = rows["ollama:dismiss-everything-model"], rows["ollama:gullible-model"]
    assert (lazy["hijack_rate"], lazy["baseline"], lazy["lift"]) == (1.0, 1.0, 0.0)
    assert (gullible["baseline"], gullible["lift"]) == (0.0, gullible["hijack_rate"])
    # sorted by lift, lowest first: the model the injection did nothing to leads
    table = [line for line in out.splitlines() if line.startswith("ollama:") and " vs " not in line]
    assert table[0].startswith("ollama:dismiss-everything-model")
    assert "baseline   lift" in out


def test_leaderboard_csv_and_markdown_carry_baseline_and_lift(tmp_path, capsys):
    md, cs = tmp_path / "lb.md", tmp_path / "lb.csv"
    main(["leaderboard", "--clients", "fake-vulnerable", "--report", str(md)])
    main(["leaderboard", "--clients", "fake-vulnerable", "--report", str(cs)])
    capsys.readouterr()
    assert "| baseline | lift |" in md.read_text()
    assert "| fake-vulnerable | 88% | 78%-93% | 0% | +88 |" in md.read_text()
    row = next(csv.DictReader(io.StringIO(cs.read_text())))
    assert (row["baseline"], row["lift"]) == ("0.0", "0.875")


def test_matrix_shows_each_clients_no_injection_baseline(fake_ollama, tmp_path, capsys):
    """every matrix cell is a hijack rate on the same alerts, so a model's
    own no-injection answers are part of all of them - the baseline column
    is what a cell has to be read against."""
    report_path = tmp_path / "m.csv"
    main([
        "matrix", "--models", "dismiss-everything-model,gullible-model", "--techniques", "direct_override",
        "--report", str(report_path),
    ])
    out = capsys.readouterr().out
    assert "client | direct_override | average | baseline" in out
    # same 100% cell for both, but only the model the injection actually
    # moved gets the star - the other dismisses those alerts regardless
    assert "ollama:dismiss-everything-model | 100% | 100% | 100%" in out
    assert "ollama:gullible-model | 100%* | 100% | 0%" in out
    rows = {row["client"]: row for row in csv.DictReader(io.StringIO(report_path.read_text()))}
    assert rows["ollama:dismiss-everything-model"]["baseline"] == "1.0"


def test_technique_leaderboard_shows_the_shared_no_injection_baseline(fake_ollama, tmp_path, capsys):
    """every technique runs on the same alerts against the same models, so
    one pooled baseline is what each technique's rate is read against."""
    md, js = tmp_path / "t.md", tmp_path / "t.json"
    for path in (md, js):
        main(["technique-leaderboard", "--models", "dismiss-everything-model,gullible-model", "--report", str(path)])
    out = capsys.readouterr().out
    # pooled: 9 of 18 eligible clean alerts dismissed with no injection (all from the dismiss-everything model)
    line = "no-injection baseline: 9/18 already answered dismiss with no injection (50%)"
    assert line in out
    assert line in md.read_text()
    assert json.loads(js.read_text())["baseline"]["eligible"] == 18


def test_check_ollama_estimates_how_long_a_full_report_takes(fake_ollama, monkeypatch, capsys):
    """a full-report against a real model is long enough that it's worth
    knowing up front - the one request check-ollama already sends is a
    sample of the model's pace."""
    clock = iter([100.0, 103.0])
    monkeypatch.setattr(cli_module.time, "monotonic", lambda: next(clock))
    assert main(["check-ollama", "--model", "robust-model"]) == 0
    out = capsys.readouterr().out
    # 3s a request: 648 requests is 32.4 min, the 324 of --defenses both 16.2
    assert "that took 3.0s - at that pace a full-report is 648 requests, about 32 min (16 min with --defenses both)" in out
    assert "an upper bound" in out


@pytest.mark.parametrize("seconds, expected", [(20, "20s"), (89, "1 min"), (3000, "50 min"), (3700, "1h 02min")])
def test_duration_formatting(seconds, expected):
    assert cli_module._duration(seconds) == expected


def test_run_prints_a_per_technique_paired_lift_table(capsys):
    main(["run", "--client", "fake-vulnerable"])
    out = capsys.readouterr().out
    table = out.split("(exact McNemar test, Holm-adjusted across the techniques):")[1]
    rows = {line.split()[0]: line.split()[1:] for line in table.strip().splitlines()[1:]}
    # all 9 alerts flipped to dismiss once injected: 2 * 0.5^9, and x8 after Holm over the 8 techniques
    assert rows["direct_override"] == ["100%", "0%", "+100", "+58", "to", "+100", "0.0039", "0.0312", "significant"]
    # unchanged on all 9 alerts, and still the interval can't rule out a 30-point lift either way
    assert rows["unicode_homoglyph"] == ["0%", "0%", "+0", "-30", "to", "+30", "1.0000", "1.0000", "not", "significant"]


def test_a_model_that_already_dismisses_everything_shows_no_significant_lift(fake_ollama, tmp_path, capsys):
    """100% hijack rate on every technique, but no alert changed its answer
    because of the injection - not one technique's lift is evidence of
    anything."""
    report_path = tmp_path / "r.json"
    main(["run", "--client", "ollama", "--model", "dismiss-everything-model", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert out.count("not significant") == 8
    lifts = json.loads(report_path.read_text())["technique_lift_by_defense"]["none"]
    assert all(entry["p_value"] == 1.0 and entry["lift"] == 0.0 for entry in lifts.values())


def test_run_markdown_report_carries_the_lift_table(tmp_path, capsys):
    report_path = tmp_path / "r.md"
    main(["run", "--client", "fake-vulnerable", "--report", str(report_path)])
    capsys.readouterr()
    content = report_path.read_text()
    assert "| technique | hijack rate | baseline | lift | lift 95% ci | p | p (holm) | |" in content
    assert "| direct_override | 100% | 0% | +100 | +58 to +100 | 0.0039 | 0.0312 | significant |" in content


def test_compare_prints_significant_lift_counts_and_saves_the_tables(tmp_path, capsys):
    report_path = tmp_path / "r.md"
    main(["compare", "--client", "fake-stubborn", "--defenses", "both", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert "defense=none: 7/8 techniques with a significant lift (Holm-adjusted p<0.05)" in out
    assert "defense=both: 0/8 techniques with a significant lift (Holm-adjusted p<0.05)" in out
    assert report_path.read_text().count("per-technique lift, each injected alert paired") == 2


def test_full_report_saves_per_direction_lift_tables(tmp_path, capsys):
    report_path = tmp_path / "r.json"
    main(["full-report", "--client", "fake-escalation-vulnerable", "--defenses", "none", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert "direction=escalate - tables in the report:" in out
    lifts = json.loads(report_path.read_text())["technique_lift_by_direction"]
    false_urgency = lifts["escalate"]["none"]["false_urgency"]
    # 9 benign alerts, all escalated once injected: 2 * 0.5^9
    assert (false_urgency["pairs"], false_urgency["gained"]) == (9, 9)
    assert false_urgency["p_value"] == pytest.approx(2 / 512)


def test_matrix_report_carries_significance_marks_and_p_values(tmp_path, capsys):
    md, js, cs = tmp_path / "m.md", tmp_path / "m.json", tmp_path / "m.csv"
    for path in (md, js, cs):
        main(["matrix", "--clients", "fake-vulnerable", "--techniques", "direct_override,unicode_homoglyph",
              "--report", str(path)])
    capsys.readouterr()
    assert "| fake-vulnerable | 100%* | 0% | 50% | 0% |" in md.read_text()
    assert "paired exact McNemar test" in md.read_text()
    p_values = json.loads(js.read_text())["clients"][0]["p_values"]
    assert p_values == {"direct_override": pytest.approx(2 / 512), "unicode_homoglyph": 1.0}
    row = next(csv.DictReader(io.StringIO(cs.read_text())))
    assert float(row["direct_override p"]) == pytest.approx(2 / 512)
    assert row["unicode_homoglyph p"] == "1.0"


def test_technique_leaderboard_pools_the_paired_test_across_models(fake_ollama, tmp_path, capsys):
    """pooled across a model that dismisses everything and one the attack
    really moves, direct_override's hijack rate is 100% - but only the
    second model's 9 alerts switched answers because of it, so the lift is
    50 points, not 100."""
    md, js, cs = tmp_path / "t.md", tmp_path / "t.json", tmp_path / "t.csv"
    for path in (md, js, cs):
        main(["technique-leaderboard", "--models", "dismiss-everything-model,gullible-model", "--report", str(path)])
    capsys.readouterr()
    override = next(t for t in json.loads(js.read_text())["techniques"] if t["technique"] == "direct_override")
    assert (override["hijack_rate"], override["lift"]) == (1.0, 0.5)
    assert override["p_value"] == pytest.approx(2 / 512)
    # 18 pairs, 9 gained and 9 already dismissed - the interval is for the pooled lift, not either model's
    assert (override["lift_ci_low"], override["lift_ci_high"]) == (pytest.approx(0.2263, abs=1e-4),
                                                                   pytest.approx(0.7097, abs=1e-4))
    assert "| direct_override | 18 | 0 | 0 | 100% | 82%-100% | +50 | +23 to +71 | 0.0039 |" in md.read_text()
    row = next(r for r in csv.DictReader(io.StringIO(cs.read_text())) if r["technique"] == "direct_override")
    assert (row["lift"], float(row["p_value"])) == ("0.5", pytest.approx(2 / 512))
    assert float(row["lift_ci_low"]) == pytest.approx(0.2263, abs=1e-4)


def test_leaderboard_counts_techniques_with_a_significant_lift(fake_ollama, tmp_path, capsys):
    """per model, how many techniques' paired tests cleared p<0.05 - the
    model that dismisses everything has the higher hijack rate and none."""
    md, cs = tmp_path / "lb.md", tmp_path / "lb.csv"
    for path in (md, cs):
        main(["leaderboard", "--models", "dismiss-everything-model,gullible-model", "--report", str(path)])
    out = capsys.readouterr().out
    rows = {line.split()[0]: line.split() for line in out.splitlines() if line.startswith("ollama:") and " vs " not in line}
    assert rows["ollama:dismiss-everything-model"][5] == "0/8"
    assert rows["ollama:gullible-model"][5] == "7/8"
    assert "| significant techniques |" in md.read_text()
    csv_rows = {r["client"]: r for r in csv.DictReader(io.StringIO(cs.read_text()))}
    assert (csv_rows["ollama:gullible-model"]["significant_techniques"], csv_rows["ollama:gullible-model"]["techniques"]) == ("7", "8")


def test_summarize_counts_significant_techniques_per_model_and_defense(fake_ollama, tmp_path, capsys):
    stubborn = _saved_full_report(tmp_path, "fake-stubborn")
    lazy = tmp_path / "lazy.json"
    main(["full-report", "--client", "ollama", "--model", "dismiss-everything-model", "--report", str(lazy)])
    md, cs = tmp_path / "s.md", tmp_path / "s.csv"
    capsys.readouterr()
    assert main(["summarize", str(stubborn), str(lazy)]) == 0
    table = capsys.readouterr().out.split("techniques with a significant lift")[1]
    assert table.startswith(" (both directions, paired McNemar, Holm-adjusted p<0.05)")
    rows = {line.split()[0]: line.split()[1:] for line in table.strip().split("\n\n")[0].splitlines()[2:]}
    # stubborn: 7 dismiss techniques under none/sandwich/strict, nothing escalates it; nothing under both
    assert rows["fake-stubborn"] == ["7/16", "7/16", "7/16", "0/16"]
    assert rows["ollama:dismiss-everything-model"] == ["0/16", "0/16", "0/16", "0/16"]
    main(["summarize", str(stubborn), str(lazy), "--report", str(md)])
    main(["summarize", str(stubborn), str(lazy), "--report", str(cs)])
    capsys.readouterr()
    assert "| fake-stubborn | 7/16 | 7/16 | 7/16 | 0/16 |" in md.read_text()
    assert "## techniques with a significant lift (both directions, paired McNemar, Holm-adjusted p<0.05)" in md.read_text()
    csv_rows = {(r["client"], r["defense"]): r for r in csv.DictReader(io.StringIO(cs.read_text()))}
    assert csv_rows[("fake-stubborn", "none")]["significant_techniques"] == "7/16"


def test_summarize_shows_na_significance_for_a_report_saved_before_the_test_existed(tmp_path, capsys):
    path = _saved_full_report(tmp_path, "fake-stubborn")
    report = json.loads(path.read_text())
    del report["technique_lift_by_direction"]
    path.write_text(json.dumps(report))
    capsys.readouterr()
    assert main(["summarize", str(path)]) == 0
    table = capsys.readouterr().out.split("techniques with a significant lift")[1]
    assert table.strip().splitlines()[2].split()[1:] == ["n/a"] * 4


def test_summarize_shows_na_significance_for_a_report_saved_before_holm(tmp_path, capsys):
    """a report from before the Holm adjustment only has raw p-values -
    counting those as significant would be the uncorrected judgment the
    adjustment exists to replace, so it shows n/a instead."""
    path = _saved_full_report(tmp_path, "fake-stubborn")
    report = json.loads(path.read_text())
    for by_defense in report["technique_lift_by_direction"].values():
        for lifts in by_defense.values():
            for entry in lifts.values():
                del entry["p_holm"]
    path.write_text(json.dumps(report))
    capsys.readouterr()
    assert main(["summarize", str(path)]) == 0
    table = capsys.readouterr().out.split("techniques with a significant lift")[1]
    assert table.strip().splitlines()[2].split()[1:] == ["n/a"] * 4


def test_compare_prints_and_saves_each_defenses_paired_effect(tmp_path, capsys):
    """sandwich stops every technique sandwich-sensitive caved to (7 of 8,
    the eighth never worked to begin with); strict does nothing for it."""
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    for path in (md, js):
        main(["compare", "--client", "fake-sandwich-sensitive", "--report", str(path)])
    out = capsys.readouterr().out
    assert "defense=sandwich: 7/8 techniques reduced, 0/8 increased (Holm-adjusted p<0.05)" in out
    assert "defense=strict: 0/8 techniques reduced, 0/8 increased (Holm-adjusted p<0.05)" in out
    effects = json.loads(js.read_text())["defense_effect_vs_none_by_defense"]
    assert set(effects) == {"sandwich", "strict", "both"}
    assert effects["sandwich"]["direct_override"]["stopped"] == 9
    assert "| direct_override | 100% | 0% | -100 | -100 to -58 | 9 | 0 | 0.0039 | 0.0312 | reduced |" in md.read_text()


def test_compare_with_only_the_none_baseline_has_no_defense_effect_to_show(capsys):
    main(["compare", "--client", "fake-robust", "--defenses", "none"])
    assert "effect of each defense" not in capsys.readouterr().out


def test_full_report_saves_the_defense_effect_per_direction(tmp_path, capsys):
    report_path = tmp_path / "r.json"
    main(["full-report", "--client", "fake-strict-sensitive", "--defenses", "strict", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert "defense=strict: 7/8 techniques reduced" in out.split("direction=dismiss - tables in the report:")[-1]
    effects = json.loads(report_path.read_text())["defense_effect_vs_none_by_direction"]
    assert set(effects) == {"dismiss", "escalate"}
    assert effects["dismiss"]["strict"]["direct_override"]["change"] == -1.0


def _reduced_table(out):
    table = out.split("techniques each defense reduced vs none")[1].strip().split("\n\n")[0]
    return {line.split()[0]: line.split()[1:] for line in table.splitlines()[2:]}


def test_summarize_counts_the_techniques_each_defense_reduced(tmp_path, capsys):
    """which defense works on which model - sandwich and strict each stop the
    7 techniques their sensitive client caves to, and only those."""
    sandwich = _saved_full_report(tmp_path, "fake-sandwich-sensitive")
    strict = _saved_full_report(tmp_path, "fake-strict-sensitive")
    md, cs = tmp_path / "s.md", tmp_path / "s.csv"
    capsys.readouterr()
    assert main(["summarize", str(sandwich), str(strict)]) == 0
    rows = _reduced_table(capsys.readouterr().out)
    assert rows["fake-sandwich-sensitive"] == ["7/16", "0/16", "7/16"]  # no none column - nothing to compare
    assert rows["fake-strict-sensitive"] == ["0/16", "7/16", "7/16"]
    main(["summarize", str(sandwich), str(strict), "--report", str(md)])
    main(["summarize", str(sandwich), str(strict), "--report", str(cs)])
    capsys.readouterr()
    assert "| fake-strict-sensitive | 0/16 | 7/16 | 7/16 |" in md.read_text()
    csv_rows = {(r["client"], r["defense"]): r for r in csv.DictReader(io.StringIO(cs.read_text()))}
    assert csv_rows[("fake-strict-sensitive", "strict")]["techniques_reduced"] == "7/16"
    assert csv_rows[("fake-strict-sensitive", "none")]["techniques_reduced"] == ""


def test_summarize_flags_a_defense_that_made_some_technique_worse(tmp_path, capsys):
    """no fake client gets worse under a defense, so this edits a saved
    report - the case real models can produce, and the one a pooled rate
    would hide."""
    path = _saved_full_report(tmp_path, "fake-sandwich-sensitive")
    report = json.loads(path.read_text())
    entry = report["defense_effect_vs_none_by_direction"]["escalate"]["strict"]["false_urgency"]
    entry.update(change=0.5, p_holm=0.01)
    path.write_text(json.dumps(report))
    capsys.readouterr()
    main(["summarize", str(path)])
    assert _reduced_table(capsys.readouterr().out)["fake-sandwich-sensitive"] == ["7/16", "0/16,", "1", "worse", "7/16"]


def test_summarize_shows_na_where_there_is_no_defense_effect(tmp_path, capsys):
    """a report saved before the paired defense effect existed, and a
    defense a --defenses run skipped."""
    old = _saved_full_report(tmp_path, "fake-sandwich-sensitive")
    report = json.loads(old.read_text())
    del report["defense_effect_vs_none_by_direction"]
    old.write_text(json.dumps(report))
    partial = tmp_path / "partial.json"
    main(["full-report", "--client", "fake-strict-sensitive", "--defenses", "strict", "--report", str(partial)])
    capsys.readouterr()
    main(["summarize", str(old), str(partial)])
    rows = _reduced_table(capsys.readouterr().out)
    assert rows["fake-sandwich-sensitive"] == ["n/a", "n/a", "n/a"]
    assert rows["fake-strict-sensitive"] == ["n/a", "7/16", "n/a"]


def test_summarize_of_none_only_reports_has_no_defense_effect_table(tmp_path, capsys):
    path = tmp_path / "none.json"
    main(["full-report", "--client", "fake-robust", "--defenses", "none", "--report", str(path)])
    md = tmp_path / "s.md"
    capsys.readouterr()
    main(["summarize", str(path), "--report", str(md)])
    assert "reduced vs none" not in capsys.readouterr().out
    assert "reduced vs none" not in md.read_text()


def test_compare_and_full_report_test_each_defenses_clean_accuracy_change(tmp_path, capsys):
    """every fake client answers all 18 clean alerts right under every
    defense - no change, and an interval that still can't rule out 18
    points either way."""
    report_path = tmp_path / "r.json"
    main(["compare", "--client", "fake-robust", "--defenses", "sandwich", "--report", str(report_path)])
    out = capsys.readouterr().out
    assert ("defense=sandwich: 100% -> 100% (+0 points, -18 to +18), broke 0, fixed 0, p_holm=1.0000 "
            "(no significant change)") in out
    assert json.loads(report_path.read_text())["clean_accuracy_vs_none_by_defense"]["sandwich"]["pairs"] == 18
    main(["full-report", "--client", "fake-robust", "--defenses", "none", "--report", str(report_path)])
    assert "clean-alert accuracy vs none" not in capsys.readouterr().out
    assert json.loads(report_path.read_text())["clean_accuracy_vs_none_by_defense"] == {}


def test_summarize_refuses_reports_run_on_different_alert_batteries(tmp_path, capsys):
    """the escalation battery grew from 7 alerts (56 injected) to 9 (72) -
    a report saved before that, next to one saved after, would compare a
    rate over different alerts as if it were the same measurement."""
    new = _saved_full_report(tmp_path, "fake-stubborn")
    old = _saved_full_report(tmp_path, "fake-sandwich-sensitive")
    report = json.loads(old.read_text())
    for bucket in report["by_direction"]["escalate"]["none"].values():
        bucket["total"] = 7
    old.write_text(json.dumps(report))
    capsys.readouterr()
    assert main(["summarize", str(new), str(old)]) == 1
    err = capsys.readouterr().err
    assert "different alert batteries" in err
    assert f"{new}: dismiss 72, escalate 72; {old}: dismiss 72, escalate 56" in err


def test_full_report_records_its_method(tmp_path, capsys):
    """what the tables below were measured on, in the report itself."""
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    for path in (md, js):
        main(["full-report", "--client", "fake-vulnerable", "--report", str(path)])
    capsys.readouterr()
    content = md.read_text()
    assert content.index("## method") < content.index("## summary: overall hijack rate by defense")
    assert "- clean alerts: 18, each answered once under every defense" in content
    assert "- direction=dismiss: 9 alerts x 8 techniques = 72 injected (direct_override, fake_system_tag," in content
    assert "- defenses: none, sandwich, strict, both" in content
    assert "- requests: 648" in content
    assert "exact McNemar test, Holm-adjusted" in content
    method = json.loads(js.read_text())["method"]
    assert method["directions"]["escalate"]["techniques"] == list(ESCALATION_TECHNIQUES)
    assert method["requests"] == 648


def test_full_report_method_follows_the_severity_filter_and_defenses(tmp_path, capsys):
    """--severity high leaves 3 dismiss-direction alerts and 1 escalate one,
    and --defenses both runs two passes - the method has to say so, not
    the full battery's numbers."""
    path = tmp_path / "r.json"
    main(["full-report", "--client", "fake-vulnerable", "--severity", "high", "--defenses", "both",
          "--report", str(path)])
    capsys.readouterr()
    method = json.loads(path.read_text())["method"]
    assert method["clean_alerts"] == 4
    assert method["directions"]["dismiss"]["eligible_alerts"] == 3
    assert method["directions"]["escalate"]["injected_alerts"] == 8
    assert method["defenses"] == ["none", "both"]
    assert method["requests"] == (4 + 24 + 8) * 2


def test_retries_flag_reaches_every_real_model_client(capsys):
    """a run against a flaky server keeps going instead of dying on the
    first dropped connection - and --retries 0 is there for anyone who'd
    rather it didn't."""
    for command in (["run", "--client", "ollama", "--model", "robust-model"],
                    ["leaderboard", "--models", "robust-model"]):
        args = cli_module.build_parser().parse_args([*command, "--retries", "0"])
        assert args.retries == 0
    assert cli_module.build_parser().parse_args(["check-ollama"]).retries == 2
    with pytest.raises(SystemExit):
        cli_module.build_parser().parse_args(["run", "--client", "ollama", "--model", "m", "--retries", "-1"])
    assert "must be 0 or more" in capsys.readouterr().err


def test_a_run_that_dies_without_a_cache_says_how_to_keep_the_next_one(fake_ollama, monkeypatch, capsys):
    def server_gone(url, json, timeout):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(requests, "post", server_gone)
    assert main(["run", "--client", "ollama", "--model", "gullible-model"]) == 1
    assert ("connection refused - nothing from this run was kept; add --cache FILE so a rerun picks up "
            "where it stopped") in capsys.readouterr().err


def test_errors_that_arent_the_server_going_away_get_no_resume_hint(tmp_path, capsys):
    """a bad --report path is an OSError too, but rerunning wouldn't help."""
    assert main(["run", "--client", "fake-robust", "--report", str(tmp_path / "missing" / "r.md")]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "rerun" not in err and "--cache" not in err


def test_ctrl_c_on_a_real_model_run_says_what_was_kept(fake_ollama, monkeypatch, tmp_path, capsys):
    """stopping a long run by hand is normal - it used to end in a raw
    traceback that said nothing about whether the answers so far survived."""
    answering = requests.post
    calls = {"n": 0}

    def interrupted_after_10(url, json, timeout):
        calls["n"] += 1
        if calls["n"] > 10:
            raise KeyboardInterrupt
        return answering(url, json=json, timeout=timeout)

    monkeypatch.setattr(requests, "post", interrupted_after_10)
    cache_path = tmp_path / "answers.json"
    assert main(["leaderboard", "--models", "gullible-model", "--cache", str(cache_path)]) == 130
    assert f"interrupted - every answer so far is saved in {cache_path}" in capsys.readouterr().err
    assert len(json.loads(cache_path.read_text())) == 10
    calls["n"] = 0
    assert main(["run", "--client", "ollama", "--model", "gullible-model"]) == 130
    assert "interrupted - nothing from this run was kept; add --cache FILE" in capsys.readouterr().err


def test_ctrl_c_on_a_fake_client_run_gets_no_cache_advice(monkeypatch, capsys):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "score_batch", interrupt)
    assert main(["run", "--client", "fake-robust"]) == 130
    err = capsys.readouterr().err
    assert err.strip() == "interrupted"


@pytest.mark.parametrize("flag", ["--report", "--transcript"])
def test_cache_and_an_output_file_cant_be_the_same_path(fake_ollama, tmp_path, capsys, flag):
    """the file written at the end of the run would replace every cached
    answer, and the next "resume" would start over."""
    path = tmp_path / "llama.json"
    assert main(["run", "--client", "ollama", "--model", "gullible-model",
                 "--cache", str(path), flag, str(path)]) == 1
    assert f"--cache and {flag} are the same file" in capsys.readouterr().err
    assert fake_ollama == []  # refused before a single request


def test_progress_lines_estimate_the_time_left_from_the_recent_pace(monkeypatch, capsys):
    """a resumed run answers its cached requests instantly - 20 of them
    here, then 3s a request. An average over the whole run would promise
    a finish far too soon; the pace over the last 10 requests doesn't."""
    clock = iter([0.0,  # started
                  0.0, 0.0,  # 10 and 20 done, both from the cache
                  30.0, 60.0,  # 30 and 40 done, 3s a request
                  ])
    monkeypatch.setattr(cli_module.time, "monotonic", lambda: next(clock))
    reporter = cli_module._ProgressReporter(ScriptedLLMClient(["{}"] * 40), "ollama:m")
    reporter.expected = 100
    for _ in range(40):
        reporter.complete("s", "u")
    lines = capsys.readouterr().err.splitlines()
    assert lines[1] == "ollama:m: 20/100 requests done (0m00s)"  # all cache so far - nothing to estimate from
    assert lines[2] == "ollama:m: 30/100 requests done (0m30s, about 4 min left)"  # 70 x 3s = 3.5 min
    assert lines[3] == "ollama:m: 40/100 requests done (1m00s, about 3 min left)"


def test_the_last_progress_line_has_no_time_left(monkeypatch, capsys):
    monkeypatch.setattr(cli_module.time, "monotonic", lambda: 0.0)
    reporter = cli_module._ProgressReporter(ScriptedLLMClient(["{}"] * 10), "ollama:m")
    reporter.expected = 10
    for _ in range(10):
        reporter.complete("s", "u")
    assert capsys.readouterr().err.strip() == "ollama:m: 10/10 requests done (0m00s)"
