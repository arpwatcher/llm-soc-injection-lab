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


def test_run_with_sandwich_defense_reduces_hijack_rate(capsys):
    main(["run", "--client", "fake-sandwich-sensitive", "--defense", "none"])
    without_defense = capsys.readouterr().out

    main(["run", "--client", "fake-sandwich-sensitive", "--defense", "sandwich"])
    with_defense = capsys.readouterr().out

    assert "100%" in without_defense
    assert "100%" not in with_defense


def test_compare_shows_both_defenses(capsys):
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "defense=none" in out
    assert "defense=sandwich" in out


def test_compare_writes_markdown_report(tmp_path, capsys):
    report_path = tmp_path / "report.md"
    exit_code = main(["compare", "--client", "fake-sandwich-sensitive", "--report", str(report_path)])
    capsys.readouterr()
    assert exit_code == 0
    content = report_path.read_text()
    assert "defense: none" in content
    assert "defense: sandwich" in content
    assert "| technique |" in content


def test_list_techniques(capsys):
    exit_code = main(["list-techniques"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "direct_override" in out
    assert "encoded_instruction" in out


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
