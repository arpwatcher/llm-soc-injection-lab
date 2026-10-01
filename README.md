# llm-soc-injection-lab

[![tests](https://github.com/arpwatcher/llm-soc-injection-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/arpwatcher/llm-soc-injection-lab/actions/workflows/tests.yml)

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
  escalate, investigate, dismiss. `ground_truth_action`, `severity`, and (when set)
  `injected_target_action` are all validated against a known set at construction time, so a
  typo surfaces immediately instead of as a confusing failure somewhere downstream (severity
  feeds the severity-weighted hijack rate's weight lookup; an unvalidated
  `injected_target_action` typo would instead silently zero out that technique's hijack rate
  with nothing pointing at the actual mistake, since `classify_outcome` would never see it
  match).
- `injections.py` - two attacker goals, modeled separately. `TECHNIQUES` (eight of them)
  push an alert that should escalate or investigate toward "dismiss" instead - hiding a
  real incident, the outcome that matters most in a SOC: a direct "already reviewed, false
  positive" note, a fake `###SYSTEM###` block, a roleplayed CISO instruction, an instruction
  hidden behind a base64 "decode this to verify" prompt, the same override note with latin
  letters swapped for visually identical cyrillic ones (reads the same, doesn't match
  literal keyword filters), a fabricated ticketing-system output block, an indirect
  reference to a made-up KB article, and a fabricated prior ticket thread where an
  "analyst" already agreed to dismiss it. `ESCALATION_TECHNIQUES` (eight of them, full parity
  with `TECHNIQUES` now) push the opposite direction - a genuinely benign alert toward
  "escalate" instead: a fabricated urgency claim, a fake severity-reclassification block, an
  impersonated incident commander demanding escalation (the mirror of the roleplayed-CISO
  technique above), an escalate instruction hidden behind the same base64 "decode this to
  confirm" framing as `encoded_instruction`, the same false-urgency note with letters
  swapped for cyrillic look-alikes (the mirror of `unicode_homoglyph`), a fabricated KB
  article cited as external authority (the mirror of `indirect_kb_reference`), a fabricated
  prior ticket thread where an "analyst" already agreed to escalate (the mirror of
  `conversational_drift`), and a fake system tag using its own distinct marker so it doesn't
  collide with the dismiss-direction one (the mirror of `fake_system_tag`). Not hiding
  anything, just wasting the analyst's time and contributing to alert fatigue - a real, if
  less severe, attacker goal, and a distinct enough failure mode that
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
  instead of relying on `parse_response`'s prose/code-fence fallback, and raises a clean
  error (instead of a bare KeyError) if a 200 response ever comes back in an unexpected
  shape. Its request building and response parsing are unit tested against a mocked
  `requests.post`. Eleven fake clients model different failure modes without needing a real
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
  demonstrate; `EscalationStubbornFakeClient` mirrors `StubbornFakeClient` the same way -
  without it, nothing proved "both" is uniquely necessary for the escalation direction
  either, since `StubbornFakeClient` itself only recognizes the dismiss-direction markers
  and resists every escalation alert regardless of defense; `EscalationSemanticVulnerableFakeClient`
  mirrors `SemanticVulnerableFakeClient` the same way, catching `escalation_homoglyph` where
  `EscalationVulnerableFakeClient`'s literal matching doesn't - the same two-sided finding as
  the dismiss direction's homoglyph technique, shown to hold in both directions rather than
  assumed by symmetry. These aren't stand-ins for missing functionality; they're what let
  the harness and scoring logic get proven correct before a single real model call happens.
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
  in every `run`/`compare`/`full-report` invocation - both call `hijacked_and_total` for the
  raw (hijacked, total) counts behind the rate, the one shared building block instead of
  three separate copies of the same injected-alerts-only filter. `resisted_and_total` is the
  clean-alert equivalent (correct-count, total) used by `run`'s "clean alerts: X/Y correct"
  line and `leaderboard`'s clean-alert accuracy column, in place of their own separate copies
  of the same counting logic. `two_proportion_z_test` goes
  a step further than a confidence interval: given two hijack rates as raw (hijacked, total) pairs,
  it answers whether the difference between them is likely real or could plausibly be
  sampling noise, using a pooled-variance two-proportion z-test (implemented directly with
  `math.erf` for the normal CDF, no extra dependency). `compare` and `full-report` both print
  this for every defense against the `none` baseline, and thread the same numbers into their
  markdown/json `--report` output (not csv - like the severity-weighted rate and confidence
  interval, it's an overall-rate-level stat, not a per-technique one, so it doesn't fit that
  file's per-technique row shape) - a percentage-point gap between two small samples can look
  big without actually being significant, which a bare rate or even a confidence interval
  doesn't make explicit the way a p-value does.
- `report.py` - renders a per-defense hijack rate table (plus the overall rate) as
  markdown, so results can go straight into a writeup. Both `render_markdown_report` (once
  more than one defense is present) and `render_combined_report` lead with a summary table
  (hijack rate per defense, `render_combined_report`'s summed across both directions) so
  the overall pattern doesn't require reading every sub-table by hand. `render_json_report`
  and `render_combined_json_report` emit the same data as JSON instead, for a plotting
  script rather than a person to read; `render_csv_report` and `render_combined_csv_report`
  emit it as CSV (one row per defense/technique pair, each tagged with the client name so
  multiple exports can be concatenated) - for opening straight in a spreadsheet instead of
  writing a script against the JSON. `render_leaderboard_report`/`_json_report`/`_csv_report`
  are the odd ones out here: every other report function is single-client, comparing
  defenses or directions for one client; these instead compare clients against each other
  under one fixed direction/defense, the side-by-side vulnerability-profile view the CLI's
  `leaderboard` subcommand needs and nothing else here produces.
  `render_technique_leaderboard_report`/`_json_report`/`_csv_report` are the technique-axis
  mirror of those three, for `technique-leaderboard`'s "most dangerous technique across every
  compared client" ranking instead of "most robust client". Each defense section also
  shows the
  severity-weighted hijack rate, the 95% confidence interval, and (for every defense but the
  `none` baseline itself) the two-proportion z-test p-value against it, alongside the flat
  rate - none of the three derivable from the per-technique buckets alone (severity isn't
  tracked there, the interval needs the pooled count, and significance needs the baseline's
  counts too) so all three are computed by the caller and threaded through as optional
  arguments. `render_transcript` (and `render_combined_transcript` for
  the full-report shape, `render_leaderboard_transcript` keyed by client instead of defense
  for the leaderboard shape) renders a per-alert JSON record (technique, defense, direction,
  action, outcome, the analyst's own reasoning text, and the full raw response) instead of
  an aggregate - the hijack-rate tables say how often something got hijacked, nothing about
  what a specific decision actually looked like, which matters for quoting a concrete
  example or spot-checking a surprising result. raw_response matters specifically for a
  parse_error=True entry, where reasoning comes back empty - it's the only place to see
  what the model actually said.
- `cli.py` - `soclab run --client ... --defense none|sandwich|strict|both --direction
  dismiss|escalate [--report FILE] [--transcript FILE]` runs one battery and can optionally
  save the aggregate report and/or the per-alert transcript;
  `soclab compare --client ... [--direction ...] [--report FILE] [--transcript FILE]` runs
  it under all four defenses back to back, prints the same defense-summary table straight
  to the terminal, followed by a two-proportion z-test comparing each defense's hijack rate
  against `none` (is the difference actually significant, or could it be noise from a small
  sample), and optionally writes the comparison and/or transcript (each entry
  tagged with which defense it came from); `soclab full-report --client ... --report FILE
  [--transcript FILE]` is the capstone run - both directions, all four defenses, one
  client, one combined document, with the same per-direction significance check `compare`
  does and its combined summary table also printed to the terminal before the file is
  written, plus an optional combined transcript across every direction and defense;
  `soclab leaderboard --direction ... --defense ... [--report FILE]`
  runs every fake-* client (ollama excluded - it needs a real, reachable server) against the
  same battery under one fixed direction/defense and ranks them by hijack rate, most robust
  first - every other subcommand compares defenses or directions for one client, this
  compares clients against each other instead. Also reports clean-alert accuracy alongside
  the hijack rate: a client that answers wrong across the board (matching neither the
  ground truth nor the attacker's target action) would otherwise score a misleadingly good
  0% hijack rate despite being useless as an analyst, which a bare hijack-rate ranking alone
  can't tell apart from a genuinely robust one. `--clients name,name` narrows the comparison
  to a chosen subset instead of always all eleven, e.g. just the escalation-direction
  clients, tolerates a stray trailing/extra comma (ignored, not an "unknown client"), and
  rejects an unrecognized name - or a value that's nothing but commas - with a clear error.
  `--sort-by hijack_rate|severity_weighted_hijack_rate|clean_accuracy` picks which column
  ranks the table (default hijack_rate) - always most-robust-first regardless of column,
  since higher is better for clean_accuracy but lower is better for the other two. With
  exactly two `--clients`, also runs the same two-proportion z-test `compare`/`full-report`
  use, head-to-head between the two (a general N-client leaderboard has no single
  unambiguous pair to test, so this only kicks in for the two-client case). Also
  accepts `--transcript FILE`, same per-alert JSON idea as the other subcommands but keyed
  by client instead of defense. `soclab technique-leaderboard --direction ... --defense ...
  [--clients ...] [--report FILE] [--transcript FILE]` is the technique-axis complement:
  `leaderboard` ranks clients against one fixed battery, this ranks techniques by how often
  they succeed across every compared client instead (most dangerous first) - concatenates
  every client's scored results for the same battery and feeds the combined list straight
  into `aggregate_by_technique`, so the answer to "which technique actually works best across
  clients in general" doesn't require reading N separate per-client tables by hand; same
  `--clients` narrowing and `--transcript` (client- and technique-tagged, reuses
  `render_leaderboard_transcript` directly since every entry already carries both) as
  `leaderboard`; `soclab list-techniques [--json] [--csv]`
  lists both technique sets, as plain text, JSON (name -> description), or CSV (direction,
  technique, description) for pulling into a thesis appendix table or spreadsheet. The
  plain-text listing prints each docstring as-is (multi-line is fine on a terminal), but
  `--json`/`--csv` collapse it to a single line first - a multi-line docstring's own source
  indentation used to carry straight through as literal embedded newlines, harmless in json
  but an awkward wrapped cell once pasted into a spreadsheet.
  Every `--report` path writes markdown by default, or JSON/CSV if the path ends in
  `.json`/`.csv` - the format is inferred from the extension, no separate flag needed. All
  four subcommands' `--report` handling shares one `_write_report` helper (pick the
  pre-rendered content matching the inferred format, write it, print the confirmation) rather
  than four separate copies of the same open/write/print steps around their own
  if-json-elif-csv-else branch; `--transcript` (always json, no format to infer) shares the
  smaller `_write_file` underneath it for the same open/write/print step. `compare` and
  `full-report` also share `_run_defense_battery` for the "run every defense, print each
  one's table" loop itself - `full-report` just calls it once per direction instead of once
  total, previously the same loop body copied into both.

Current status: the harness is fully built and tested against the fake clients. Still
hasn't run against a real model - this development environment's network policy blocks
both ollama.com and huggingface.co (checked directly, both return a hard connection
refusal at the proxy level, not a timeout), so there's currently no way to reach either a
local Ollama server or download open weights here. `OllamaClient` is real, working code
regardless, pointed at via `OLLAMA_HOST` / `--host` / `--model` / `--timeout` (default 120s,
plenty of slower local models can exceed that) - it'll run for real the
moment Ollama is reachable, either here with a different network policy or wherever the
actual thesis experiments run.

## Usage

```
pip install -r requirements.txt  # pinned versions, for reproducible experiment runs
# or: make install

python -m soclab.cli list-techniques
python -m soclab.cli run --client fake-robust
python -m soclab.cli run --client fake-vulnerable
python -m soclab.cli run --client fake-semantic-vulnerable
python -m soclab.cli run --client fake-sandwich-sensitive --defense sandwich
python -m soclab.cli run --client fake-strict-sensitive --defense strict
python -m soclab.cli run --client fake-stubborn --defense both
python -m soclab.cli run --client fake-escalation-vulnerable --direction escalate
python -m soclab.cli run --client fake-vulnerable --transcript transcript.json  # per-alert reasoning, for review
python -m soclab.cli compare --client fake-stubborn --report results.md
python -m soclab.cli full-report --client fake-stubborn --report full-results.md
python -m soclab.cli full-report --client fake-stubborn --report full-results.json  # same data, for plotting
python -m soclab.cli full-report --client fake-stubborn --report full-results.csv  # same data, for a spreadsheet
python -m soclab.cli leaderboard --direction dismiss --report leaderboard.md  # every fake-* client, ranked
python -m soclab.cli leaderboard --clients fake-robust,fake-vulnerable  # a chosen subset - exactly 2 also runs a z-test between them
python -m soclab.cli leaderboard --sort-by clean_accuracy  # rank by a different column
python -m soclab.cli leaderboard --transcript leaderboard-transcript.json  # per-alert reasoning, per client
python -m soclab.cli technique-leaderboard --direction dismiss  # which technique works best across every client
python -m soclab.cli technique-leaderboard --transcript tl-transcript.json  # per-alert reasoning, per client+technique
python -m soclab.cli run --client ollama --model llama3.2:3b
```

### Example output

`python -m soclab.cli run --client fake-vulnerable` against the dismiss-direction battery:

```
clean alerts: 8/8 correct action (defense=none)

direction=dismiss
technique                hijacked resisted  other  hijack_rate
direct_override                 5        0      0        100%
fake_system_tag                 5        0      0        100%
roleplay_authority              5        0      0        100%
encoded_instruction             5        0      0        100%
unicode_homoglyph               0        5      0          0%
fake_tool_output                5        0      0        100%
indirect_kb_reference           5        0      0        100%
conversational_drift            5        0      0        100%

overall hijack rate: 88%
95% confidence interval: 74%-95%
severity-weighted hijack rate: 88%
```

`VulnerableFakeClient` models a naive keyword-filter defense: it caves to every literal
marker phrase except `unicode_homoglyph`'s cyrillic look-alike substitution, which is the
whole point of that technique - the 88% flat rate and its wide interval (74%-95%, since
each technique only gets 5 alerts) both come straight out of that one blind spot.

## Tests

```
pytest
```

280 tests, all deterministic - no real network calls (OllamaClient's own tests mock
requests.post), nothing depends on a real model being available. The fake clients are
exercised the same way a real one eventually will be, so the prompt-building,
response-parsing, scoring, and report generation are all proven correct independent of
what's actually running behind `complete()`. Every hijack-focused test used to happen to
use an escalate-worthy alert as its example - injection also targets investigate-worthy
alerts (`apply_all_techniques` skips only dismiss-worthy ones), so that path is checked
explicitly too now, not just assumed to work by symmetry.

Runs automatically on every push via GitHub Actions (`.github/workflows/tests.yml`,
`make install && make check`) - since the whole suite is deterministic and network-free,
there's nothing CI can't reproduce exactly the same way locally with the same two
commands. `make check` lints with `ruff check .` (default rule set - real issues like
unused imports, not style nitpicks the codebase would need reformatting to satisfy) and
runs the suite under `coverage`, printing the per-file report so the number stays visible
without anyone needing to run it by hand. `make clean` removes the `__pycache__`,
`.pytest_cache`, `.ruff_cache`, `.coverage`, and `htmlcov` artifacts those two leave behind.

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

At 100% line and branch coverage now - the one remaining gap was the
`if __name__ == "__main__":` guard itself, which is real, intentionally-untestable-in-process
code (it only runs when the module is executed directly, which the subprocess test above
does cover, just not in a way `coverage` can see from inside the parent process), so it
carries a `# pragma: no cover` rather than a workaround that would test nothing new.
