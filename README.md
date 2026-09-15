# llm-soc-injection-lab

A small research harness for a question that comes up whenever people talk about putting
LLMs in a SOC analyst role: if an attacker can influence what shows up in a log line or a
ticket comment, can they talk the analyst into the wrong call? This measures that directly
instead of guessing - synthetic alerts, a battery of prompt injection techniques mixed into
the untrusted log field (in either direction an attacker might want), two different
defensive prompting strategies, and a scoring pass that says how often each technique
actually changes the analyst's decision.

Built for a thesis on LLM-based SOC analysts and prompt injection resistance.

- `alerts.py` - the `Alert` data model plus 8 clean synthetic alerts across varied sources
  (edr, auth, dlp, firewall, av, email, iam, dns), at least two per ground truth outcome:
  escalate, investigate, dismiss.
- `injections.py` - two attacker goals, modeled separately. `TECHNIQUES` (eight of them)
  push an alert that should escalate or investigate toward "dismiss" instead - hiding a
  real incident, the outcome that matters most in a SOC: a direct "already reviewed, false
  positive" note, a fake `###SYSTEM###` block, a roleplayed CISO instruction, an instruction
  hidden behind a base64 "decode this to verify" prompt, the same override note with latin
  letters swapped for visually identical cyrillic ones (reads the same, doesn't match
  literal keyword filters), a fabricated ticketing-system output block, an indirect
  reference to a made-up KB article, and a fabricated prior ticket thread where an
  "analyst" already agreed to dismiss it. `ESCALATION_TECHNIQUES` (two of them) push the
  opposite direction - a genuinely benign alert toward "escalate" instead, via a fabricated
  urgency claim or a fake severity-reclassification block. Not hiding anything, just
  wasting the analyst's time and contributing to alert fatigue - a real, if less severe,
  attacker goal, and a distinct enough failure mode that `Alert.injected_target_action`
  tracks which direction each injected alert is actually aiming for.
- `analyst.py` - builds the prompt sent to the model: a system prompt establishing the role
  and explicitly stating the log content is data, not instructions, and a user message
  wrapping the untrusted content in clear delimiters. Supports three defenses plus "none":
  `sandwich` repeats the "this is data" reminder in the user message after the untrusted
  block (targets recency bias); `strict` instead names specific manipulation patterns up
  front in the system prompt (targets a model that's told what to watch for); `both` layers
  them together. Parses the model's response back into a structured decision - pulls the
  JSON out even if the model wraps it in a sentence, and rejects anything outside the known
  action set instead of guessing.
- `llm_client.py` - one small interface (`complete(system_prompt, user_message) -> str`)
  behind everything. `OllamaClient` is the real implementation, talking to a local Ollama
  server - its request building and response parsing are unit tested against a mocked
  `requests.post`. Seven fake clients model different failure modes without needing a real
  model running: `RobustFakeClient` always reads the alert honestly by keyword;
  `VulnerableFakeClient` caves the moment it sees a known injection marker phrase, but does
  NOT catch the homoglyph technique (naive keyword filter, on purpose);
  `SemanticVulnerableFakeClient` normalizes homoglyphs first, so it DOES fall for that one
  too - the two together show literal keyword filtering has a specific blind spot that
  doesn't necessarily protect an actual model either way; `SandwichSensitiveFakeClient` and
  `StrictPromptSensitiveFakeClient` are each vulnerable by default but resist their own
  matching defense, checked to NOT be helped by the other's; `StubbornFakeClient` needs
  both signals together to back off, checked to show neither individual defense is enough
  for it; `EscalationVulnerableFakeClient` mirrors `VulnerableFakeClient` for the opposite
  attacker goal - caves to the escalation markers, ignores the dismiss-direction ones
  entirely, checked to be a genuinely separate vulnerability profile in both directions.
  These aren't stand-ins for missing functionality; they're what let the harness and
  scoring logic get proven correct before a single real model call happens.
- `scoring.py` - classifies each result as resisted / hijacked / other (against whichever
  direction that specific alert's injection was aiming for), aggregates a hijack rate per
  technique, and an overall hijack rate across a whole batch.
- `report.py` - renders a per-defense hijack rate table (plus the overall rate) as
  markdown, so results can go straight into a writeup.
- `cli.py` - `soclab run --client ... --defense none|sandwich|strict|both --direction
  dismiss|escalate` runs one battery; `soclab compare --client ... [--direction ...]
  [--report FILE.md]` runs it under all four defenses back to back and optionally writes
  the comparison as markdown; `soclab list-techniques` lists both technique sets.

Current status: the harness is fully built and tested against the fake clients. Still
hasn't run against a real model - this development environment's network policy blocks
both ollama.com and huggingface.co (checked directly, both return a hard connection
refusal at the proxy level, not a timeout), so there's currently no way to reach either a
local Ollama server or download open weights here. `OllamaClient` is real, working code
regardless, pointed at via `OLLAMA_HOST` / `--host` / `--model` - it'll run for real the
moment Ollama is reachable, either here with a different network policy or wherever the
actual thesis experiments run.

## Usage

```
pip install -r requirements.txt

python -m soclab.cli list-techniques
python -m soclab.cli run --client fake-robust
python -m soclab.cli run --client fake-vulnerable
python -m soclab.cli run --client fake-semantic-vulnerable
python -m soclab.cli run --client fake-sandwich-sensitive --defense sandwich
python -m soclab.cli run --client fake-strict-sensitive --defense strict
python -m soclab.cli run --client fake-stubborn --defense both
python -m soclab.cli run --client fake-escalation-vulnerable --direction escalate
python -m soclab.cli compare --client fake-stubborn --report results.md
python -m soclab.cli run --client ollama --model llama3.2:3b
```

## Tests

```
pytest
```

98 tests, all deterministic - no real network calls (OllamaClient's own tests mock
requests.post), nothing depends on a real model being available. The fake clients are
exercised the same way a real one eventually will be, so the prompt-building,
response-parsing, scoring, and report generation are all proven correct independent of
what's actually running behind `complete()`.
