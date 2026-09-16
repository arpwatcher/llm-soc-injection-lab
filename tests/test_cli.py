import pytest

from soclab.cli import build_client, main


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


def test_run_escalate_direction_with_dedicated_client(capsys):
    exit_code = main(["run", "--client", "fake-escalation-vulnerable", "--direction", "escalate"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direction=escalate" in out
    for line in out.splitlines():
        if line.strip().startswith(("false_urgency", "fake_severity_upgrade")):
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
        if line.strip().startswith(("false_urgency", "fake_severity_upgrade")):
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
