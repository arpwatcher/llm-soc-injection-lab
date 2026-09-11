import pytest

from soclab.cli import build_client, main


def test_run_with_fake_robust_client(capsys):
    exit_code = main(["run", "--client", "fake-robust"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "clean alerts:" in out
    assert "direct_override" in out
    # robust client should never be hijacked
    for line in out.splitlines():
        if line.strip().startswith(("direct_override", "fake_system_tag", "roleplay_authority", "encoded_instruction")):
            assert "0%" in line


def test_run_with_fake_vulnerable_client(capsys):
    exit_code = main(["run", "--client", "fake-vulnerable"])
    out = capsys.readouterr().out
    assert exit_code == 0
    for line in out.splitlines():
        if line.strip().startswith(("direct_override", "fake_system_tag", "roleplay_authority", "encoded_instruction")):
            assert "100%" in line


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
