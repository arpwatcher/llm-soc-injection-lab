import csv
import io
import json
import subprocess
import sys

import pytest
import requests

from soclab.cli import FAKE_CLIENT_NAMES, _report_format, build_client, main
from soclab.llm_client import RobustFakeClient, VulnerableFakeClient


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
    """each technique only gets 3-5 alerts - a bare point estimate hides
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
    assert "clean alerts: 2/2 correct action" in out
    assert "severity filter: critical" in out
    assert "direct_override                 2        0      0        100%" in out
    assert "high" not in out
    assert "medium" not in out


def test_run_severity_filter_accepts_a_comma_separated_subset(capsys):
    exit_code = main(["run", "--client", "fake-vulnerable", "--severity", "critical,high"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "clean alerts: 3/3 correct action" in out  # A001, A006 (critical) + A002 (high)
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


def test_run_severity_filter_with_nothing_present_is_empty_not_a_crash(capsys):
    """dismiss-direction injected alerts only ever come from escalate/
    investigate ground truth alerts, none of which are severity=low -
    asking for --severity low should produce an empty (not erroring)
    injected battery, same as an injected-alerts-only filter in scoring.py
    gracefully returning 0.0/empty rather than raising on an empty batch."""
    exit_code = main(["run", "--client", "fake-vulnerable", "--severity", "low"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "overall hijack rate: 0%" in out


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
    assert len(entries) == 40  # 8 techniques x 5 alerts each
    assert all("reasoning" in e for e in entries)
    hijacked = [e for e in entries if e["outcome"] == "hijacked"]
    resisted = [e for e in entries if e["outcome"] == "resisted"]
    assert len(hijacked) == 35  # every technique but unicode_homoglyph
    assert len(resisted) == 5


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
    assert "direct_override                 2        0      0        100%" in out
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
    assert high == pytest.approx(0.0876, abs=0.01)
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

    def __init__(self, content):
        self._content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"message": {"content": self._content}}


@pytest.fixture
def fake_ollama(monkeypatch):
    """Stands in for a running ollama server: answers each /api/chat
    request the way one of the fake clients would, picked by the
    requested model name, so the --models tests go through OllamaClient's
    real request building and response parsing rather than around it.
    Returns the list of requests it received, for checking host/timeout."""
    behaviours = {"robust-model": RobustFakeClient(), "gullible-model": VulnerableFakeClient()}
    received = []

    def fake_post(url, json, timeout):
        received.append({"url": url, "model": json["model"], "timeout": timeout})
        system, user = (message["content"] for message in json["messages"])
        return _FakeOllamaResponse(behaviours[json["model"]].complete(system, user))

    monkeypatch.setattr(requests, "post", fake_post)
    return received


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
    assert "ollama:gullible-model | 100% | 0% | 50%" in out


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
    estimate (8/8 clean alerts correct), but the interval is still wide
    (68%-100%), exactly the over-reading risk this column exists to show."""
    exit_code = main(["leaderboard", "--clients", "fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "clean 95% ci" in out
    assert "68%-100%" in out


def test_leaderboard_writes_clean_accuracy_confidence_interval_to_json(tmp_path, capsys):
    report_path = tmp_path / "leaderboard.json"
    main(["leaderboard", "--clients", "fake-robust", "--report", str(report_path)])
    capsys.readouterr()
    parsed = json.loads(report_path.read_text())
    robust_row = next(row for row in parsed["clients"] if row["client"] == "fake-robust")
    assert robust_row["clean_ci_low"] == pytest.approx(0.6756, abs=0.001)
    assert robust_row["clean_ci_high"] == 1.0


def test_leaderboard_writes_clean_accuracy_confidence_interval_to_csv(tmp_path, capsys):
    report_path = tmp_path / "leaderboard.csv"
    main(["leaderboard", "--clients", "fake-robust", "--report", str(report_path)])
    capsys.readouterr()
    rows = list(csv.DictReader(report_path.read_text().splitlines()))
    assert float(rows[0]["clean_ci_low"]) == pytest.approx(0.6756, abs=0.001)
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
    assert "direct_override                                 2 " in out


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
    assert "fake-vulnerable | 100% | 0% | 50%" in out


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


def test_matrix_severity_filter_that_empties_the_battery_shows_zero_not_a_crash(capsys):
    """dismiss-direction injected alerts only ever come from escalate/
    investigate ground truth alerts, none of which are severity=low - every
    technique column used to KeyError on a direct aggregated[technique]
    lookup once --severity filtered the injected battery down to nothing,
    instead of falling back to the same 0% every other subcommand shows
    for an empty battery."""
    exit_code = main(["matrix", "--clients", "fake-vulnerable", "--severity", "low"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "fake-vulnerable | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0%" in out


def test_matrix_severity_filter_that_empties_the_battery_works_for_escalate_direction_too(capsys):
    exit_code = main([
        "matrix", "--clients", "fake-escalation-vulnerable", "--direction", "escalate",
        "--severity", "critical",
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "fake-escalation-vulnerable | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0%" in out


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
    worthy ground truth alerts (medium and low severity here), unlike
    the dismiss direction's critical/high/medium."""
    exit_code = main(["severity-matrix", "--client", "fake-escalation-vulnerable", "--direction", "escalate"])
    out = capsys.readouterr().out
    assert exit_code == 0
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
    assert severities == {"medium", "low"}
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
    assert len(rows) == 3  # critical, high, medium
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
    """escalation-direction alerts naturally only ever come from two
    severities (medium, low) - the same exactly-two case leaderboard and
    technique-leaderboard trigger pairwise significance on, here reached
    without needing --severity at all."""
    exit_code = main(["severity-matrix", "--client", "fake-escalation-vulnerable", "--direction", "escalate"])
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

    client = build_client(Args())
    assert client.timeout == 5.0


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
