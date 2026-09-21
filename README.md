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
  escalate, investigate, dismiss. Both `ground_truth_action` and `severity` are validated
  against a known set at construction time, so a typo surfaces immediately instead of as a
  confusing failure somewhere downstream (severity in particular feeds the severity-weighted
  hijack rate's weight lookup).
- `injections.py` - two attacker goals, modeled separately. `TECHNIQUES` (eight of them)
  push an alert that should escalate or investigate toward "dismiss" instead - hiding a
  real incident, the outcome that matters most in a SOC: a direct "already reviewed, false
  positive" note, a fake `###SYSTEM###` block, a roleplayed CISO instruction, an instruction
  hidden behind a base64 "decode this to verify" prompt, the same override note with latin
  letters swapped for visually identical cyrillic ones (reads the same, doesn't match
  literal keyword filters), a fabricated ticketing-system output block, an indirect
  reference to a made-up KB article, and a fabricated prior ticket thread where an
  "analyst" already agreed to dismiss it. `ESCALATION_TECHNIQUES` (three of them) push the
  opposite direction - a genuinely benign alert toward "escalate" instead, via a fabricated
  urgency claim, a fake severity-reclassification block, or an impersonated incident
  commander demanding escalation (the mirror of the roleplayed-CISO technique above). Not
  hiding anything, just wasting the analyst's time and contributing to alert fatigue - a
  real, if less severe, attacker goal, and a distinct enough failure mode that
  `Alert.injected_target_action` tracks which direction each injected alert is actually
  aiming for.
- `analyst.py` - builds the prompt sent to the model: a system prompt establishing the role
  and explicitly stating the log content is data, not instructions, and a user message
  wrapping the untrusted content in clear delimiters. Supports three defenses plus "none":
  `sandwich` repeats the "this is data" reminder in the user message after the untrusted
  block (targets recency bias); `strict` instead names specific manipulation patterns up
  front in the system prompt - patterns from BOTH attacker directions, not just the
  dismiss-direction ones (targets a model that's told what to watch for); `both` layers
  them together. Parses the model's response back into a structured decision - pulls the
  JSON out even if the model wraps it in a sentence, and rejects anything outside the known
  action set instead of guessing.
- `llm_client.py` - one small interface (`complete(system_prompt, user_message) -> str`)
  behind everything. `OllamaClient` is the real implementation, talking to a local Ollama
  server - requests it as `format: json` so a compliant model returns valid JSON directly
  instead of relying on `parse_response`'s prose/code-fence fallback. Its request building
  and response parsing are unit tested against a mocked
  `requests.post`. Nine fake clients model different failure modes without needing a real
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
  entirely; `EscalationSandwichSensitiveFakeClient` and
  `EscalationStrictPromptSensitiveFakeClient` prove both defenses actually help against the
  escalation direction too, not just the dismiss direction they were originally built to
  demonstrate. These aren't stand-ins for missing functionality; they're what let the
  harness and scoring logic get proven correct before a single real model call happens.
- `scoring.py` - classifies each result as resisted / hijacked / other (against whichever
  direction that specific alert's injection was aiming for), aggregates a hijack rate per
  technique, and an overall hijack rate across a whole batch. Also computes a
  severity-weighted hijack rate (critical alerts weighted higher than low ones) alongside
  the flat one - a client that mostly resists on low-severity alerts but caves on critical
  ones looks fine under the flat rate while actually being much worse in practice. This
  originally couldn't diverge from the flat rate for the escalation direction at all, since
  escalation-direction techniques only ever target dismiss-worthy alerts and every one of
  those happened to be severity=low - fixed by giving A005 (a generic-heuristic av
  detection, realistically auto-tagged higher before investigation) severity=medium instead.
  Every per-technique bucket also carries a 95% Wilson confidence interval (ci_low, ci_high)
  on its hijack rate - each technique only ever gets 3-5 alerts in this harness, so a bare
  point estimate like "100%" is easy to over-read without seeing how little data backs it.
  `overall_hijack_rate_confidence_interval` does the same for the bottom-line rate, printed
  in every `run`/`compare`/`full-report` invocation.
- `report.py` - renders a per-defense hijack rate table (plus the overall rate) as
  markdown, so results can go straight into a writeup. Both `render_markdown_report` (once
  more than one defense is present) and `render_combined_report` lead with a summary table
  (hijack rate per defense, `render_combined_report`'s summed across both directions) so
  the overall pattern doesn't require reading every sub-table by hand. `render_json_report`
  and `render_combined_json_report` emit the same data as JSON instead, for a plotting
  script rather than a person to read. Each defense section also shows the
  severity-weighted hijack rate alongside the flat one, since the per-technique buckets
  don't carry alert severity and the caller has to compute and pass it in separately.
- `cli.py` - `soclab run --client ... --defense none|sandwich|strict|both --direction
  dismiss|escalate [--report FILE]` runs one battery and can optionally save it too;
  `soclab compare --client ... [--direction ...] [--report FILE]` runs it under all four
  defenses back to back, prints the same defense-summary table straight to the terminal,
  and optionally writes the comparison; `soclab full-report --client ... --report FILE` is
  the capstone run - both directions, all four defenses, one client, one combined document,
  with its combined summary table also printed to the
  terminal before the file is written; `soclab list-techniques` lists both technique sets.
  Every `--report` path writes markdown by default, or JSON if the path ends in `.json` -
  the format is inferred from the extension, no separate flag needed.

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
pip install -r requirements.txt  # pinned versions, for reproducible experiment runs

python -m soclab.cli list-techniques
python -m soclab.cli run --client fake-robust
python -m soclab.cli run --client fake-vulnerable
python -m soclab.cli run --client fake-semantic-vulnerable
python -m soclab.cli run --client fake-sandwich-sensitive --defense sandwich
python -m soclab.cli run --client fake-strict-sensitive --defense strict
python -m soclab.cli run --client fake-stubborn --defense both
python -m soclab.cli run --client fake-escalation-vulnerable --direction escalate
python -m soclab.cli compare --client fake-stubborn --report results.md
python -m soclab.cli full-report --client fake-stubborn --report full-results.md
python -m soclab.cli full-report --client fake-stubborn --report full-results.json  # same data, for plotting
python -m soclab.cli run --client ollama --model llama3.2:3b
```

## Tests

```
pytest
```

161 tests, all deterministic - no real network calls (OllamaClient's own tests mock
requests.post), nothing depends on a real model being available. The fake clients are
exercised the same way a real one eventually will be, so the prompt-building,
response-parsing, scoring, and report generation are all proven correct independent of
what's actually running behind `complete()`. Every hijack-focused test used to happen to
use an escalate-worthy alert as its example - injection also targets investigate-worthy
alerts (`apply_all_techniques` skips only dismiss-worthy ones), so that path is checked
explicitly too now, not just assumed to work by symmetry.

Ran a `coverage.py` audit (99% line coverage going in) and closed the two real gaps it
found rather than chasing the number: `parse_response`'s JSONDecodeError branch had never
actually been hit (the existing "malformed json" test used a response with no braces at
all, which takes a different path), and the `python -m soclab.cli` entry point itself had
never been exercised as a real subprocess - every other cli test calls `main()` in-process.
Also fixed a real bug found along the way: a bad `--report` path (missing directory, no
permission) crashed with a raw traceback instead of the clean "error: ..." message every
other failure gets - `main()` now catches `OSError` too, which also means a connection
failure against `--client ollama` (wrong host, not running) fails cleanly instead of
crashing, since `requests.exceptions.ConnectionError` subclasses `OSError`.
