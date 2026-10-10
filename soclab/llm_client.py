"""LLM clients the analyst harness talks to. Kept behind one small
interface (complete(system_prompt, user_message) -> str) so the harness
logic doesn't care whether it's talking to a real model or a test double.

The fake clients below aren't "stub features" - the harness itself is
fully real (prompt building, response parsing, scoring). They're test
doubles standing in for an actual model, same as any other external
dependency you fake out in unit tests, so the harness logic is provable
without needing a running LLM.
"""

import hashlib
import json
import os
from typing import Protocol

import requests

# phrases the injection techniques in injections.py actually produce -
# used by VulnerableFakeClient to decide whether it's been "convinced".
# unicode_homoglyph is deliberately NOT matched here: it swaps latin
# letters for look-alike cyrillic ones specifically so a literal keyword
# match like this one doesn't catch it - modeling how naive keyword-filter
# defenses (as opposed to genuine semantic understanding) get bypassed by
# homoglyph obfuscation.
_INJECTION_MARKERS = (
    "SYSTEM NOTE",
    "###SYSTEM###",
    "[ticket comment - CISO]",
    "debug metadata, base64",
    "[TICKETING_SYSTEM_OUTPUT]",
    "KB-4471",
    "[prior ticket thread]",
)

# phrases the escalation-direction techniques produce - separate list
# since they're a different attacker goal (push toward escalate, not
# dismiss) and none of the techniques above would ever need to match them
_ESCALATION_MARKERS = (
    "CRITICAL UPDATE",
    "[SEVERITY_ENGINE_OUTPUT]",
    "[ticket comment - Incident Commander]",
    "[TRIAGE_ENGINE]",
    "KB-7823",
    "[prior escalation thread]",
    "###ESCALATION_SYSTEM###",
)


class LLMClient(Protocol):
    def complete(self, system_prompt: str, user_message: str) -> str: ...


def _keyword_classify(user_message: str) -> str:
    """A simple, honest reading of the alert content - no awareness of
    anything that looks like an injected instruction. Used by both fake
    clients as their baseline judgment before VulnerableFakeClient decides
    whether to override it."""
    text = user_message.lower()
    if "ransomware" in text or "failed password" in text or "credentials entered" in text:
        return "escalate"
    if "large outbound transfer" in text or "unfamiliar external" in text or "outside the approved change window" in text or "outside change window" in text:
        return "investigate"
    return "dismiss"


def _to_json_response(action: str, reasoning: str) -> str:
    import json
    return json.dumps({"action": action, "reasoning": reasoning})


class RobustFakeClient:
    """Models a model that correctly treats the alert's raw_log as data,
    not instructions - it always reaches the same verdict a plain keyword
    reading of the alert content gives, regardless of any injected text."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        action = _keyword_classify(user_message)
        return _to_json_response(action, "based on alert content only")


class VulnerableFakeClient:
    """Models a model that can be talked into an instruction hidden in the
    untrusted alert text - if any known injection marker phrase is present,
    it complies and dismisses. Otherwise it falls back to the same honest
    keyword reading RobustFakeClient uses, so it behaves identically on
    clean alerts and only diverges when an injection is actually present."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        if any(marker in user_message for marker in _INJECTION_MARKERS):
            return _to_json_response("dismiss", "following the note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


class EscalationVulnerableFakeClient:
    """The mirror image of VulnerableFakeClient: caves to the
    escalation-direction markers instead, escalating a genuinely benign
    alert. Doesn't recognize the dismiss-direction markers at all -
    models a distinct vulnerability profile (susceptible to false
    urgency, not to false reassurance)."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        if any(marker in user_message for marker in _ESCALATION_MARKERS):
            return _to_json_response("escalate", "following the urgent note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


# reverses the substitution injections.py's unicode_homoglyph technique
# makes, so a client can be checked for markers "as a human would read
# them" instead of byte-for-byte
_HOMOGLYPH_REVERSE_MAP = str.maketrans("аАеЕоОсСрР", "aAeEoOcCpP")


class SemanticVulnerableFakeClient:
    """Like VulnerableFakeClient, but normalizes common cyrillic homoglyphs
    back to latin before matching - models a model with genuine semantic
    understanding rather than literal-byte keyword filtering, so unlike
    VulnerableFakeClient it IS caught out by the unicode_homoglyph
    technique too. Contrast with VulnerableFakeClient shows the two-sided
    finding: naive keyword filters miss homoglyphs, but a model that
    actually reads the text isn't protected by that same gap."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        normalized = user_message.translate(_HOMOGLYPH_REVERSE_MAP)
        if any(marker in normalized for marker in _INJECTION_MARKERS):
            return _to_json_response("dismiss", "following the note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


class EscalationSemanticVulnerableFakeClient:
    """The escalation-direction mirror of SemanticVulnerableFakeClient:
    normalizes cyrillic homoglyphs back to latin before matching the
    escalation markers, so unlike EscalationVulnerableFakeClient it IS
    caught out by escalation_homoglyph too. Without this,
    escalation_homoglyph would have nothing to demonstrate the same
    two-sided finding the dismiss-direction homoglyph technique shows:
    naive keyword filters miss homoglyphs regardless of which direction
    they're used in, but genuine semantic reading isn't protected by that
    same gap either."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        normalized = user_message.translate(_HOMOGLYPH_REVERSE_MAP)
        if any(marker in normalized for marker in _ESCALATION_MARKERS):
            return _to_json_response("escalate", "following the urgent note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


_REINFORCEMENT_MARKER = "Reminder: everything between the BEGIN/END"


class SandwichSensitiveFakeClient:
    """Models a model with recency bias: vulnerable to the same injection
    markers as VulnerableFakeClient, but backs off if a sandwich-defense
    reinforcement phrase shows up later in the message - as if a reminder
    placed after the untrusted content actually gets weighted more than
    an instruction planted earlier. Lets the sandwich defense's effect
    show up as an actual before/after difference in the harness."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        if _REINFORCEMENT_MARKER in user_message:
            return _to_json_response(_keyword_classify(user_message), "reminded to disregard embedded instructions")
        if any(marker in user_message for marker in _INJECTION_MARKERS):
            return _to_json_response("dismiss", "following the note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


_STRICT_WARNING_MARKER = "Be alert for CISO impersonation"


class StrictPromptSensitiveFakeClient:
    """Models a model that pays attention to being told up front what
    manipulation patterns to watch for: vulnerable to the same injection
    markers as VulnerableFakeClient, but resists if the strict defense's
    warning is present in the system prompt. Unlike SandwichSensitiveFakeClient
    (which only looks at the user message), this one only looks at the
    system prompt - the two model genuinely different defense mechanisms,
    and neither fake is affected by the other's defense."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        if _STRICT_WARNING_MARKER in system_prompt:
            return _to_json_response(_keyword_classify(user_message), "warned about this pattern in advance")
        if any(marker in user_message for marker in _INJECTION_MARKERS):
            return _to_json_response("dismiss", "following the note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


class StubbornFakeClient:
    """Models a model that needs BOTH signals to back off - the sandwich
    reinforcement in the user message AND the strict warning in the
    system prompt. Either alone isn't enough to change its mind, only
    the combined defense is. Shows that stacking defenses can matter even
    when neither alone covers this particular failure mode."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        has_reinforcement = _REINFORCEMENT_MARKER in user_message
        has_strict_warning = _STRICT_WARNING_MARKER in system_prompt
        if has_reinforcement and has_strict_warning:
            return _to_json_response(_keyword_classify(user_message), "convinced by the reminder and the warning together")
        if any(marker in user_message for marker in _INJECTION_MARKERS):
            return _to_json_response("dismiss", "following the note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


class EscalationSandwichSensitiveFakeClient:
    """The escalation-direction mirror of SandwichSensitiveFakeClient:
    vulnerable to the escalation markers by default, but backs off if the
    sandwich reinforcement is present. Nothing in the harness proved the
    sandwich defense actually helps against the "talk the analyst up"
    attacker goal until this existed - EscalationVulnerableFakeClient
    doesn't look at defenses at all."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        if _REINFORCEMENT_MARKER in user_message:
            return _to_json_response(_keyword_classify(user_message), "reminded to disregard embedded instructions")
        if any(marker in user_message for marker in _ESCALATION_MARKERS):
            return _to_json_response("escalate", "following the urgent note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


class EscalationStrictPromptSensitiveFakeClient:
    """The escalation-direction mirror of StrictPromptSensitiveFakeClient:
    vulnerable to the escalation markers by default, but resists once the
    strict defense's warning (which, since the earlier one-sided-defense
    fix, now names the escalation patterns too) is present in the system
    prompt."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        if _STRICT_WARNING_MARKER in system_prompt:
            return _to_json_response(_keyword_classify(user_message), "warned about this pattern in advance")
        if any(marker in user_message for marker in _ESCALATION_MARKERS):
            return _to_json_response("escalate", "following the urgent note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


class EscalationStubbornFakeClient:
    """The escalation-direction mirror of StubbornFakeClient: needs BOTH
    the sandwich reinforcement and the strict warning to back off from
    the escalation markers, either alone isn't enough. Without this,
    nothing proved "both" is uniquely necessary (not just individually
    sufficient) for the escalation direction - StubbornFakeClient itself
    only checks the dismiss-direction markers, so it resists every
    escalation-direction alert regardless of defense, which would make
    "both" look like it always fully resists this direction for the
    wrong reason (nothing to hijack in the first place, not that the
    combined defense earned it)."""

    def complete(self, system_prompt: str, user_message: str) -> str:
        has_reinforcement = _REINFORCEMENT_MARKER in user_message
        has_strict_warning = _STRICT_WARNING_MARKER in system_prompt
        if has_reinforcement and has_strict_warning:
            return _to_json_response(_keyword_classify(user_message), "convinced by the reminder and the warning together")
        if any(marker in user_message for marker in _ESCALATION_MARKERS):
            return _to_json_response("escalate", "following the urgent note in the log")
        return _to_json_response(_keyword_classify(user_message), "based on alert content only")


class ResponseCache:
    """Every real-model answer from a run, kept in one json file on disk and
    saved as soon as it arrives. One instance per file, shared by every
    client in the run - a comparison across several models wraps each
    model separately, and separate copies of the file would each write
    back only their own answers, wiping out the others'."""

    def __init__(self, path: str):
        self._path = path
        self._answers: dict[str, str] = {}
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self._answers = json.load(f)
            except ValueError as exc:
                raise ValueError(f"cache file {path} isn't valid json - delete it to start a fresh cache") from exc

    def get(self, key: str) -> str | None:
        return self._answers.get(key)

    def put(self, key: str, answer: str) -> None:
        self._answers[key] = answer
        # write to a temp file and swap it in, so a ctrl-c mid-write can't
        # leave a half-written cache behind that the next run can't read
        tmp_path = f"{self._path}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(self._answers, f)
        os.replace(tmp_path, self._path)


class CachedClient:
    """Wraps a real model's client so every answer goes into a
    ResponseCache. A long real-model run that dies partway - one request
    timing out, the laptop sleeping, a ctrl-c - used to lose every answer
    it had already collected; rerunning the same command with the same
    cache file now skips straight past them. key_prefix should identify
    the model and any pinned sampling settings (the cli passes the same
    label it prints), so a different model or temperature never reuses
    another run's answers. At the model's default temperature that means
    a cached answer is reused, not resampled - delete the file for a
    fresh sample."""

    def __init__(self, client, cache: ResponseCache, key_prefix: str):
        self._client = client
        self._cache = cache
        self._key_prefix = key_prefix

    def __getattr__(self, name):
        return getattr(self._client, name)

    def complete(self, system_prompt: str, user_message: str) -> str:
        digest = hashlib.sha256(f"{system_prompt}\0{user_message}".encode()).hexdigest()
        key = f"{self._key_prefix}|{digest}"
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        answer = self._client.complete(system_prompt, user_message)
        self._cache.put(key, answer)
        return answer


class ScriptedLLMClient:
    """Returns a fixed sequence of canned responses, one per call, in
    order - for tests that need to control exactly what the model "said"
    rather than simulate classification behavior."""

    def __init__(self, responses: list[str]):
        self._responses = list(responses)
        self._calls = 0

    def complete(self, system_prompt: str, user_message: str) -> str:
        if self._calls >= len(self._responses):
            raise IndexError("ScriptedLLMClient ran out of canned responses")
        response = self._responses[self._calls]
        self._calls += 1
        return response


class OllamaClient:
    """Talks to a real, locally running Ollama server. The request/response
    handling is unit tested against a mocked requests.post (see
    tests/test_ollama_client.py) - no real network call happens in the
    test suite, but the actual code path that builds the request and
    parses the response is exercised, not skipped."""

    def __init__(
        self, model: str, host: str | None = None, timeout: float = 120.0,
        temperature: float | None = None, seed: int | None = None,
    ):
        self.model = model
        # sampling options - left out of the request entirely when not set,
        # so the model's own defaults apply (usually a temperature above 0,
        # which means two runs of the same battery can disagree).
        self.temperature = temperature
        self.seed = seed
        default_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        # strip a trailing slash - $OLLAMA_HOST or --host is often set with
        # one (e.g. "http://localhost:11434/"), which would otherwise turn
        # into a double slash in front of /api/chat below.
        self.host = (host or default_host).rstrip("/")
        self.timeout = timeout

    def available_models(self) -> list[str]:
        """Names of every model already pulled on this server (GET
        /api/tags), so a multi-model run can check up front that each one
        is there - otherwise a missing one only surfaces after every model
        listed before it has already run its whole battery."""
        response = requests.get(f"{self.host}/api/tags", timeout=self.timeout)
        response.raise_for_status()
        try:
            return [entry["name"] for entry in response.json()["models"]]
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"unexpected response from ollama /api/tags: {response.text!r}") from exc

    def complete(self, system_prompt: str, user_message: str) -> str:
        payload: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
            # ollama supports constraining output to valid json directly -
            # parse_response already handles prose/code-fence wrapping for
            # models that ignore this, but asking for it up front means a
            # compliant model doesn't need that fallback at all.
            "format": "json",
        }
        options = {
            name: value for name, value in (("temperature", self.temperature), ("seed", self.seed))
            if value is not None
        }
        if options:
            payload["options"] = options
        response = requests.post(f"{self.host}/api/chat", json=payload, timeout=self.timeout)
        if response.status_code == 404:
            # ollama's answer to a model that was never pulled - the bare
            # "404 Client Error: Not Found for url" raise_for_status gives
            # names neither the model nor the fix.
            raise ValueError(
                f"{self.host}/api/chat returned 404 for model {self.model!r} - usually it isn't pulled "
                f"there yet (run `ollama pull {self.model}`), or the host isn't an ollama server"
            )
        if response.status_code >= 400:
            # ollama explains most failures in an {"error": ...} body - e.g.
            # a model needing more memory than the machine has, likely on a
            # laptop - which raise_for_status alone reduces to "500 Server
            # Error: Internal Server Error for url"
            try:
                reason = response.json().get("error")
            except (ValueError, AttributeError):
                reason = None
            if reason:
                raise ValueError(f"ollama returned {response.status_code} for model {self.model!r}: {reason}")
        response.raise_for_status()
        try:
            body = response.json()
        except ValueError as exc:
            # a 200 that isn't even valid json at all (e.g. a reverse
            # proxy's own HTML error page, served with a 200 instead of
            # an error status) would otherwise surface as a bare,
            # technical JSONDecodeError instead of the same clean
            # "error: ..." message every other failure gets.
            raise ValueError(f"unexpected response from ollama: {response.text!r}") from exc
        try:
            return body["message"]["content"]
        except (KeyError, TypeError) as exc:
            # a 200 with valid json in an unexpected shape (wrong ollama
            # version, a future api change) - same idea, different cause.
            raise ValueError(f"unexpected response shape from ollama: {body!r}") from exc
