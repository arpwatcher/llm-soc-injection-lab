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
    def __init__(self, payload, status_code=200, text=None):
        self._payload = payload
        self.status_code = status_code
        # only meaningful for the not-valid-json test below - a real
        # response's .text is what response.json() parses from.
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")

    def json(self):
        if self._payload is None:
            raise requests.exceptions.JSONDecodeError("bad json", self.text or "", 0)
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


def test_strips_a_trailing_slash_from_an_explicit_host(monkeypatch):
    """$OLLAMA_HOST or --host is often set with a trailing slash - without
    stripping it, the url below would come out as a double slash in
    front of /api/chat instead of a single one."""
    captured = {}
    monkeypatch.setattr(requests, "post", _capture_url_post(captured))
    client = OllamaClient(model="m", host="http://10.0.0.5:11434/")
    client.complete("s", "u")
    assert captured["url"] == "http://10.0.0.5:11434/api/chat"


def test_strips_a_trailing_slash_from_the_ollama_host_env_var(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://custom-host:9999/")
    captured = {}
    monkeypatch.setattr(requests, "post", _capture_url_post(captured))
    client = OllamaClient(model="m")
    client.complete("s", "u")
    assert captured["url"] == "http://custom-host:9999/api/chat"


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


def test_sends_sampling_options_only_when_set(monkeypatch):
    sent = []

    def fake_post(url, json, timeout):
        sent.append(json)
        return _FakeResponse({"message": {"content": "ok"}})

    monkeypatch.setattr(requests, "post", fake_post)
    OllamaClient(model="m").complete("s", "u")
    OllamaClient(model="m", temperature=0.0, seed=7).complete("s", "u")
    OllamaClient(model="m", seed=7).complete("s", "u")
    assert "options" not in sent[0]
    assert sent[1]["options"] == {"temperature": 0.0, "seed": 7}
    assert sent[2]["options"] == {"seed": 7}


def test_raises_on_http_error_status(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _FakeResponse({}, status_code=500))
    client = OllamaClient(model="m")
    with pytest.raises(requests.HTTPError):
        client.complete("s", "u")


def test_available_models_lists_pulled_model_names(monkeypatch):
    captured = {}

    def fake_get(url, timeout):
        captured["url"], captured["timeout"] = url, timeout
        return _FakeResponse({"models": [{"name": "llama3.2:3b", "size": 1}, {"name": "mistral:7b"}]})

    monkeypatch.setattr(requests, "get", fake_get)
    client = OllamaClient(model="llama3.2:3b", host="http://gpu-box:11434/", timeout=7.0)
    assert client.available_models() == ["llama3.2:3b", "mistral:7b"]
    assert captured == {"url": "http://gpu-box:11434/api/tags", "timeout": 7.0}


def test_available_models_raises_clean_error_on_unexpected_shape(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: _FakeResponse({"oops": []}, text='{"oops": []}'))
    client = OllamaClient(model="m")
    with pytest.raises(ValueError, match="unexpected response from ollama /api/tags"):
        client.available_models()


def test_error_status_passes_on_ollamas_own_reason(monkeypatch):
    """a model too big for the machine's memory - likely on a laptop -
    comes back as a 500 whose body says exactly that, but raise_for_status
    alone reduced it to "500 Server Error: Internal Server Error for url"."""
    reason = "model requires more system memory (8.0 GiB) than is available (4.0 GiB)"
    monkeypatch.setattr(requests, "post", lambda *a, **k: _FakeResponse({"error": reason}, status_code=500))
    client = OllamaClient(model="llama3.1:8b")
    with pytest.raises(ValueError) as excinfo:
        client.complete("s", "u")
    assert str(excinfo.value) == f"ollama returned 500 for model 'llama3.1:8b': {reason}"


def test_error_status_without_a_reason_still_raises_http_error(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _FakeResponse(None, status_code=502, text="<html>bad gateway"))
    client = OllamaClient(model="m")
    with pytest.raises(requests.HTTPError):
        client.complete("s", "u")


def test_error_status_with_a_non_object_body_still_raises_http_error(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _FakeResponse(["not", "an", "object"], status_code=500))
    client = OllamaClient(model="m")
    with pytest.raises(requests.HTTPError):
        client.complete("s", "u")


def test_404_names_the_model_and_the_fix(monkeypatch):
    """ollama answers /api/chat with a 404 for a model that was never
    pulled - raise_for_status alone said "404 Client Error: Not Found for
    url", which names neither the model nor what to do about it."""
    monkeypatch.setattr(
        requests, "post",
        lambda *a, **k: _FakeResponse({"error": "model 'mistral:7b' not found"}, status_code=404),
    )
    client = OllamaClient(model="mistral:7b", host="http://gpu-box:11434")
    with pytest.raises(ValueError) as excinfo:
        client.complete("s", "u")
    message = str(excinfo.value)
    assert "'mistral:7b'" in message
    assert "ollama pull mistral:7b" in message
    assert "http://gpu-box:11434/api/chat" in message


def test_raises_clean_error_on_missing_message_key(monkeypatch):
    """a 200 response with an unexpected shape (wrong ollama version, a
    proxy in the way, a future api change) should fail the same clean
    way as every other error path here - not a bare KeyError."""
    monkeypatch.setattr(requests, "post", lambda *a, **k: _FakeResponse({"error": "model not found"}))
    client = OllamaClient(model="m")
    with pytest.raises(ValueError, match="unexpected response shape"):
        client.complete("s", "u")


def test_raises_clean_error_on_missing_content_key(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _FakeResponse({"message": {"role": "assistant"}}))
    client = OllamaClient(model="m")
    with pytest.raises(ValueError, match="unexpected response shape"):
        client.complete("s", "u")


def test_raises_clean_error_when_message_is_not_a_dict(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _FakeResponse({"message": "not a dict"}))
    client = OllamaClient(model="m")
    with pytest.raises(ValueError, match="unexpected response shape"):
        client.complete("s", "u")


def test_raises_clean_error_on_a_200_that_is_not_valid_json(monkeypatch):
    """a 200 response that isn't even valid json at all (e.g. a reverse
    proxy's own HTML error page, served with a 200 instead of an error
    status) used to surface as a bare, technical JSONDecodeError instead
    of the same clean "error: ..." message every other failure here
    gets - response.json() raises before there's a body to inspect, so
    the message has to fall back to response.text instead."""
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _FakeResponse(None, text="<html>upstream error</html>"),
    )
    client = OllamaClient(model="m")
    with pytest.raises(ValueError, match="unexpected response from ollama"):
        client.complete("s", "u")
