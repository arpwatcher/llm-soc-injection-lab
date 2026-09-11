# llm-soc-injection-lab

A small research harness for a question that comes up whenever people talk about putting
LLMs in a SOC analyst role: if an attacker can influence what shows up in a log line or a
ticket comment, can they talk the analyst into dismissing something it shouldn't? This
measures that directly instead of guessing - synthetic alerts, a battery of prompt
injection techniques mixed into the untrusted log field, and a scoring pass that says how
often each technique actually changes the analyst's decision.

Built for a thesis on LLM-based SOC analysts and prompt injection resistance.

- `alerts.py` - the `Alert` data model plus a small battery of clean synthetic alerts
  (ransomware hash hit, ssh brute force, large off-hours transfer, a low-severity port
  scan, an av false-positive-shaped quarantine) covering all three ground truth outcomes:
  escalate, investigate, dismiss.
- `injections.py` - four injection techniques, each mixed into an alert's raw log field,
  all pushing toward the same wrong answer (dismiss) since that's the outcome that
  actually matters in a SOC: a direct "already reviewed, false positive" note, a fake
  `###SYSTEM###` block, a roleplayed CISO instruction, and an instruction hidden behind a
  base64 "decode this to verify" prompt.
- `analyst.py` - builds the actual prompt sent to the model (system prompt establishes the
  role and explicitly states the log content is data, not instructions; user message wraps
  the untrusted content in clear delimiters), and parses the model's response back into a
  structured decision - pulls the JSON out even if the model wraps it in a sentence, and
  rejects anything outside the known action set instead of guessing.
- `llm_client.py` - one small interface (`complete(system_prompt, user_message) -> str`)
  behind everything. `OllamaClient` is the real implementation, talking to a local Ollama
  server. `RobustFakeClient` and `VulnerableFakeClient` model a resistant vs. a hijacked
  analyst without needing a real model running - both read the alert honestly by keyword,
  the vulnerable one additionally caves the moment it sees a known injection marker phrase.
  These aren't stand-ins for missing functionality; they're what let the harness and
  scoring logic get proven correct before a single real model call happens.
- `scoring.py` - classifies each result as resisted / hijacked / other, and aggregates a
  hijack rate per technique across a batch. Checked end to end against both fake clients:
  the robust one scores 0% hijack rate on everything, the vulnerable one scores 100%.
- `cli.py` - `soclab run --client ...` runs the full battery and prints a per-technique
  report; `soclab list-techniques` lists what's available.

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
python -m soclab.cli run --client ollama --model llama3.2:3b
```

## Tests

```
pytest
```

41 tests, all deterministic - no network calls, nothing depends on a real model being
available. The fake clients are exercised the same way a real one eventually will be, so
the prompt-building, response-parsing, and scoring logic are all proven correct
independent of what's actually running behind `complete()`.
