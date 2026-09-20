"""OllamaClient is real code that talks to a real server, but that server
isn't reachable in this environment (network policy blocks ollama.com).
These tests mock requests.post instead of skipping coverage entirely -
the request payload it builds and the response parsing it does are both
plain code with room for bugs, independent of whether a real server is
listening on the other end."""

import pytest
import requests

from soclab.llm_client import OllamaClient


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")

    def json(self):
        return self._payload


def test_sends_correct_chat_request(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeResponse({"message": {"content": "ok"}})

    monkeypatch.setattr(requests, "post", fake_post)

    client = OllamaClient(model="llama3.2:3b", host="http://localhost:11434")
    client.complete("sys prompt", "user msg")

    assert captured["url"] == "http://localhost:11434/api/chat"
    assert captured["json"]["model"] == "llama3.2:3b"
    assert captured["json"]["stream"] is False
    assert captured["json"]["format"] == "json"
    assert captured["json"]["messages"] == [
        {"role": "system", "content": "sys prompt"},
        {"role": "user", "content": "user msg"},
    ]


def test_parses_message_content_from_response(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _FakeResponse({"message": {"content": "escalate this"}}))
    client = OllamaClient(model="llama3.2:3b")
    assert client.complete("s", "u") == "escalate this"


def _capture_url_post(captured):
    def fake_post(url, **kwargs):
        captured["url"] = url
        return _FakeResponse({"message": {"content": "x"}})
    return fake_post


def test_uses_explicit_host_over_default(monkeypatch):
    captured = {}
    monkeypatch.setattr(requests, "post", _capture_url_post(captured))
    client = OllamaClient(model="m", host="http://10.0.0.5:11434")
    client.complete("s", "u")
    assert captured["url"] == "http://10.0.0.5:11434/api/chat"


def test_uses_ollama_host_env_var_when_no_host_given(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://custom-host:9999")
    captured = {}
    monkeypatch.setattr(requests, "post", _capture_url_post(captured))
    client = OllamaClient(model="m")
    client.complete("s", "u")
    assert captured["url"] == "http://custom-host:9999/api/chat"


def test_defaults_to_localhost_when_no_host_or_env(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    captured = {}
    monkeypatch.setattr(requests, "post", _capture_url_post(captured))
    client = OllamaClient(model="m")
    client.complete("s", "u")
    assert captured["url"] == "http://localhost:11434/api/chat"


def test_raises_on_http_error_status(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _FakeResponse({}, status_code=500))
    client = OllamaClient(model="m")
    with pytest.raises(requests.HTTPError):
        client.complete("s", "u")
