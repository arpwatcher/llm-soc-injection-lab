"""LLM clients the analyst harness talks to. Kept behind one small
interface (complete(system_prompt, user_message) -> str) so the harness
logic doesn't care whether it's talking to a real model or a test double.

The fake clients below aren't "stub features" - the harness itself is
fully real (prompt building, response parsing, scoring). They're test
doubles standing in for an actual model, same as any other external
dependency you fake out in unit tests, so the harness logic is provable
without needing a running LLM.
"""

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

    def __init__(self, model: str, host: str | None = None, timeout: float = 120.0):
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.timeout = timeout

    def complete(self, system_prompt: str, user_message: str) -> str:
        response = requests.post(
            f"{self.host}/api/chat",
            json={
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
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()["message"]["content"]
