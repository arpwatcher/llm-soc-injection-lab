import json
import subprocess
import sys

import pytest

from soclab.cli import build_client, main


def test_module_invocation_as_real_subprocess():
    """every other test calls main() in-process - none of them actually
    exercise `python -m soclab.cli`, the way a real user runs this, which
    means the `if __name__ == "__main__":` guard itself was never proven
    to work. this runs it for real, out of process."""
    result = subprocess.run(
        [sys.executable, "-m", "soclab.cli", "list-techniques"],
        capture_output=True, text=True, timeout=10,
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
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "which client to test" in result.stdout
    assert "prompt defense to apply" in result.stdout


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
    assert "severity-weighted hijack rate:" in content
    assert "95% confidence interval:" in content


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
    assert "direct_override" in parsed["per_defense"]["none"]
    assert parsed["severity_weighted_by_defense"] == {"none": 0.875}
    assert "none" in parsed["confidence_interval_by_defense"]


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
    assert "severity-weighted hijack rate:" in content
    assert "95% confidence interval:" in content


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
    assert "severity-weighted hijack rate:" in content
    assert "95% confidence interval:" in content


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


def test_run_escalate_direction_with_dedicated_client(capsys):
    exit_code = main(["run", "--client", "fake-escalation-vulnerable", "--direction", "escalate"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direction=escalate" in out
    for line in out.splitlines():
        if line.strip().startswith((
            "false_urgency", "fake_severity_upgrade", "fake_incident_commander",
            "encoded_escalation_instruction", "indirect_kb_reference_escalation",
            "conversational_drift_escalation",
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
            "conversational_drift_escalation",
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

    with pytest.raises(ValueError):
        build_client(Args())


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
