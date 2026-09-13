# llm-soc-injection-lab

A small research harness for a question that comes up whenever people talk about putting
LLMs in a SOC analyst role: if an attacker can influence what shows up in a log line or a
ticket comment, can they talk the analyst into dismissing something it shouldn't? This
measures that directly instead of guessing - synthetic alerts, a battery of prompt
injection techniques mixed into the untrusted log field, two different defensive prompting
strategies, and a scoring pass that says how often each technique actually changes the
analyst's decision.

Built for a thesis on LLM-based SOC analysts and prompt injection resistance.

- `alerts.py` - the `Alert` data model plus 8 clean synthetic alerts across varied sources
  (edr, auth, dlp, firewall, av, email, iam, dns), at least two per ground truth outcome:
  escalate, investigate, dismiss.
- `injections.py` - eight injection techniques, each mixed into an alert's raw log field,
  all pushing toward the same wrong answer (dismiss) since that's the outcome that
  actually matters in a SOC: a direct "already reviewed, false positive" note, a fake
  `###SYSTEM###` block, a roleplayed CISO instruction, an instruction hidden behind a
  base64 "decode this to verify" prompt, the same override note with latin letters swapped
  for visually identical cyrillic ones (reads the same, doesn't match literal keyword
  filters), a fabricated ticketing-system output block, an indirect reference to a made-up
  KB article, and a fabricated prior ticket thread where an "analyst" already agreed to
  dismiss it.
- `analyst.py` - builds the prompt sent to the model: a system prompt establishing the role
  and explicitly stating the log content is data, not instructions, and a user message
  wrapping the untrusted content in clear delimiters. Supports two independent defenses:
  `sandwich` repeats the "this is data" reminder in the user message after the untrusted
  block (targets recency bias); `strict` instead names specific manipulation patterns up
  front in the system prompt (targets a model that's told what to watch for). Parses the
  model's response back into a structured decision - pulls the JSON out even if the model
  wraps it in a sentence, and rejects anything outside the known action set instead of
  guessing.
- `llm_client.py` - one small interface (`complete(system_prompt, user_message) -> str`)
  behind everything. `OllamaClient` is the real implementation, talking to a local Ollama
  server. Five fake clients model different failure modes without needing a real model
  running: `RobustFakeClient` always reads the alert honestly by keyword; `VulnerableFakeClient`
  caves the moment it sees a known injection marker phrase, but does NOT catch the
  homoglyph technique (naive keyword filter, on purpose); `SemanticVulnerableFakeClient`
  normalizes homoglyphs first, so it DOES fall for that one too - the two together show
  literal keyword filtering has a specific blind spot that doesn't necessarily protect an
  actual model either way; `SandwichSensitiveFakeClient` and `StrictPromptSensitiveFakeClient`
  are each vulnerable by default but resist their own matching defense - and checked to NOT
  be helped by the other's defense, since the two target different failure modes rather
  than one being strictly better. These aren't stand-ins for missing functionality; they're
  what let the harness and scoring logic get proven correct before a single real model call
  happens.
- `scoring.py` - classifies each result as resisted / hijacked / other, and aggregates a
  hijack rate per technique across a batch.
- `report.py` - renders a per-defense hijack rate table as markdown, so results can go
  straight into a writeup.
- `cli.py` - `soclab run --client ... --defense none|sandwich|strict` runs the battery
  once; `soclab compare --client ... [--report FILE.md]` runs it under all three defenses
  back to back and optionally writes the comparison as markdown; `soclab list-techniques`
  lists what's available.

Current status: the harness is fully built and tested against the fake clients.
`OllamaClient` is real, working code, but this development environment's network policy
blocks reaching ollama.com to install it, so it hasn't been run against an actual model
yet - that happens once Ollama is available (either here with a different network policy,
or wherever the real thesis experiments run), pointed at via `OLLAMA_HOST` /
`--host` / `--model`.

## Usage

```
pip install -r requirements.txt

python -m soclab.cli list-techniques
python -m soclab.cli run --client fake-robust
python -m soclab.cli run --client fake-vulnerable
python -m soclab.cli run --client fake-semantic-vulnerable
python -m soclab.cli run --client fake-sandwich-sensitive --defense sandwich
python -m soclab.cli run --client fake-strict-sensitive --defense strict
python -m soclab.cli compare --client fake-sandwich-sensitive --report results.md
python -m soclab.cli run --client ollama --model llama3.2:3b
```

## Tests

```
pytest
```

68 tests, all deterministic - no network calls, nothing depends on a real model being
available. The fake clients are exercised the same way a real one eventually will be, so
the prompt-building, response-parsing, scoring, and report generation are all proven
correct independent of what's actually running behind `complete()`.
