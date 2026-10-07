"""Entry point: run the injection battery against a client and print a
per-technique report, or list the available techniques."""

import argparse
import csv
import json
import sys

from soclab.alerts import SEVERITIES, generate_clean_alerts
from soclab.analyst import DEFENSE_NONE, DEFENSES
from soclab.injections import (
    ESCALATION_TECHNIQUES,
    TECHNIQUES,
    apply_all_escalation_techniques,
    apply_all_techniques,
)
from soclab.llm_client import (
    EscalationSandwichSensitiveFakeClient,
    EscalationSemanticVulnerableFakeClient,
    EscalationStrictPromptSensitiveFakeClient,
    EscalationStubbornFakeClient,
    EscalationVulnerableFakeClient,
    OllamaClient,
    RobustFakeClient,
    SandwichSensitiveFakeClient,
    SemanticVulnerableFakeClient,
    StrictPromptSensitiveFakeClient,
    StubbornFakeClient,
    VulnerableFakeClient,
)
from soclab.report import (
    combined_rate_by_defense,
    rate_by_defense,
    render_combined_csv_report,
    render_combined_json_report,
    render_combined_report,
    render_combined_transcript,
    render_csv_report,
    render_json_report,
    render_leaderboard_csv_report,
    render_leaderboard_json_report,
    render_leaderboard_report,
    render_leaderboard_transcript,
    render_markdown_report,
    render_matrix_csv_report,
    render_matrix_json_report,
    render_matrix_report,
    render_severity_matrix_csv_report,
    render_severity_matrix_json_report,
    render_severity_matrix_report,
    render_technique_leaderboard_csv_report,
    render_technique_leaderboard_json_report,
    render_technique_leaderboard_report,
    render_transcript,
)
from soclab.scoring import (
    SIGNIFICANCE_ALPHA,
    aggregate_by_severity,
    aggregate_by_severity_and_technique,
    aggregate_by_technique,
    hijacked_and_total,
    is_significant,
    overall_hijack_rate,
    overall_hijack_rate_confidence_interval,
    resisted_and_total,
    score_batch,
    severity_weighted_hijack_rate,
    two_proportion_z_test,
)

CLIENT_FACTORIES = {
    "fake-robust": lambda args: RobustFakeClient(),
    "fake-vulnerable": lambda args: VulnerableFakeClient(),
    "fake-semantic-vulnerable": lambda args: SemanticVulnerableFakeClient(),
    "fake-sandwich-sensitive": lambda args: SandwichSensitiveFakeClient(),
    "fake-strict-sensitive": lambda args: StrictPromptSensitiveFakeClient(),
    "fake-stubborn": lambda args: StubbornFakeClient(),
    "fake-escalation-vulnerable": lambda args: EscalationVulnerableFakeClient(),
    "fake-escalation-semantic-vulnerable": lambda args: EscalationSemanticVulnerableFakeClient(),
    "fake-escalation-sandwich-sensitive": lambda args: EscalationSandwichSensitiveFakeClient(),
    "fake-escalation-strict-sensitive": lambda args: EscalationStrictPromptSensitiveFakeClient(),
    "fake-escalation-stubborn": lambda args: EscalationStubbornFakeClient(),
    "ollama": lambda args: OllamaClient(model=args.model, host=args.host, timeout=args.timeout),
}

DIRECTIONS = ("dismiss", "escalate")

FAKE_CLIENT_NAMES = [name for name in CLIENT_FACTORIES if name != "ollama"]


def build_client(args):
    if args.client == "ollama" and not args.model:
        raise ValueError("--model is required when --client ollama")
    return CLIENT_FACTORIES[args.client](args)


def _print_report(aggregated, results, severity_breakdown=None):
    print(f"{'technique':<24} {'hijacked':>8} {'resisted':>8} {'other':>6} {'hijack_rate':>12}")
    for technique, bucket in aggregated.items():
        print(f"{technique:<24} {bucket['hijacked']:>8} {bucket['resisted']:>8} {bucket['other']:>6} "
              f"{bucket['hijack_rate']:>11.0%}")
    if severity_breakdown:
        print(f"\n{'severity':<24} {'hijacked':>8} {'resisted':>8} {'other':>6} {'hijack_rate':>12}")
        for severity, bucket in severity_breakdown.items():
            print(f"{severity:<24} {bucket['hijacked']:>8} {bucket['resisted']:>8} {bucket['other']:>6} "
                  f"{bucket['hijack_rate']:>11.0%}")
    print(f"\noverall hijack rate: {overall_hijack_rate(results):.0%}")
    ci_low, ci_high = overall_hijack_rate_confidence_interval(results)
    print(f"95% confidence interval: {ci_low:.0%}-{ci_high:.0%}")
    print(f"severity-weighted hijack rate: {severity_weighted_hijack_rate(results):.0%}")


def _print_summary(rates: dict, heading: str):
    print(heading)
    print(f"{'defense':<10} {'hijack_rate':>12}")
    for defense, rate in rates.items():
        print(f"{defense:<10} {rate:>11.0%}")
    print()


def _significance_vs_baseline(results_by_defense: dict, baseline: str) -> dict:
    """defense name -> (z, p_value) for a two-proportion z-test of that
    defense's overall hijack rate against the baseline's (defense=none),
    for every defense except the baseline itself. Computed once here so
    both the terminal printout and the written report render from the
    same numbers instead of recomputing them separately."""
    baseline_hijacked, baseline_total = hijacked_and_total(results_by_defense[baseline])
    return {
        defense: two_proportion_z_test(baseline_hijacked, baseline_total, *hijacked_and_total(results))
        for defense, results in results_by_defense.items()
        if defense != baseline
    }


def _print_significance_vs_baseline(significance: dict, baseline: str):
    """Prints a two-proportion z-test comparing each other defense's
    overall hijack rate against the baseline's (defense=none) - a
    percentage-point gap between two small samples can look big without
    being statistically meaningful, and this is the number that actually
    answers whether a defense measurably helped rather than just reading
    the rates off and eyeballing the difference."""
    print(f"significance vs defense={baseline} (two-proportion z-test):")
    for defense, (_, p_value) in significance.items():
        verdict = "significant" if is_significant(p_value) else "not significant"
        print(f"  {baseline} vs {defense}: p={p_value:.4f} ({verdict} at p<{SIGNIFICANCE_ALPHA})")
    print()


def _write_file(path: str, content: str, message: str):
    """Writes content to path and prints the confirmation message - the
    open/write/print steps every --report and --transcript call site
    shares (transcript output is always json regardless of the path's
    extension, so it needs no format branching, just this)."""
    with open(path, "w") as f:
        f.write(content)
    print(message)


def _write_report(path: str, *, markdown_content: str, json_content: str, csv_content: str, message: str):
    """Writes whichever of the three pre-rendered contents matches the
    path's inferred format, then prints the confirmation message every
    report-writing subcommand already prints. All three are pre-rendered
    by the caller rather than branched into lazily - each format needs
    its own distinct render_*_report call anyway (csv's excludes
    severity/confidence-interval/significance, the others don't), so the
    actual duplication this removes is the open/write/print boilerplate
    that was copied at every one of run/compare/full-report/leaderboard's
    --report call sites, not the rendering itself."""
    report_format = _report_format(path)
    content = {"markdown": markdown_content, "json": json_content, "csv": csv_content}[report_format]
    _write_file(path, content, message)


def _report_format(path: str) -> str:
    """The report format inferred from a --report path's extension - case
    insensitively, so results.JSON or results.CSV (not just the lowercase
    spelling) picks up the right renderer instead of silently falling
    back to markdown."""
    if path.lower().endswith(".json"):
        return "json"
    if path.lower().endswith(".csv"):
        return "csv"
    return "markdown"


def _injected_alerts_for(direction: str) -> list:
    clean_alerts = generate_clean_alerts()
    if direction == "escalate":
        return apply_all_escalation_techniques(clean_alerts)
    return apply_all_techniques(clean_alerts)


def _run_defense_battery(injected_alerts: list, client, heading_prefix: str = "") -> tuple:
    """Runs the injection battery under every defense, printing each
    defense's per-technique and per-severity tables as it goes. compare
    runs this once; full-report runs it once per direction (heading_prefix
    distinguishes "--- defense=none ---" from "--- direction=dismiss
    defense=none ---" in the two cases) - same loop body either way,
    previously duplicated between them. Returns (per_defense,
    results_by_defense, severity_weighted_by_defense,
    confidence_interval_by_defense, severity_breakdown_by_defense), each
    keyed by defense name."""
    per_defense = {}
    results_by_defense = {}
    severity_weighted_by_defense = {}
    confidence_interval_by_defense = {}
    severity_breakdown_by_defense = {}
    for defense in DEFENSES:
        print(f"--- {heading_prefix}defense={defense} ---")
        results = score_batch(injected_alerts, client, defense=defense)
        aggregated = aggregate_by_technique(results)
        severity_breakdown = aggregate_by_severity(results)
        _print_report(aggregated, results, severity_breakdown)
        per_defense[defense] = aggregated
        results_by_defense[defense] = results
        severity_weighted_by_defense[defense] = severity_weighted_hijack_rate(results)
        confidence_interval_by_defense[defense] = overall_hijack_rate_confidence_interval(results)
        severity_breakdown_by_defense[defense] = severity_breakdown
        print()
    return (
        per_defense, results_by_defense, severity_weighted_by_defense,
        confidence_interval_by_defense, severity_breakdown_by_defense,
    )


def _resolve_severities(severity_arg: str | None, command_label: str) -> list | None:
    """Parses a comma-separated --severity value into a validated list, or
    None if not given (the caller then doesn't filter at all). Same
    comma-parsing/validation shape as _resolve_client_names and
    _resolve_technique_names, against the fixed SEVERITIES tuple - unlike
    technique names, severities aren't direction-dependent, so there's no
    per-direction valid set to check against here."""
    if not severity_arg:
        return None
    requested = [name.strip() for name in severity_arg.split(",") if name.strip()]
    if not requested:
        raise ValueError("--severity was given but contained no severity names")
    unknown = [name for name in requested if name not in SEVERITIES]
    if unknown:
        raise ValueError(f"unknown severity/severities for {command_label}: {', '.join(unknown)}")
    return requested


def _print_severity_filter(requested_severities: list | None) -> None:
    """Prints which --severity subset is in effect, right under the
    direction/defense header line every --severity-aware subcommand
    already prints - silent when no filter was given (the default,
    whole-battery case needs no extra line). Without this, a saved
    terminal screenshot or transcript of a filtered run gives no way to
    tell afterward which severities were actually tested; the numbers
    could silently be misread as the full battery's."""
    if requested_severities is not None:
        print(f"severity filter: {', '.join(requested_severities)}")


def _filter_by_severity(alerts: list, requested_severities: list | None) -> list:
    """alerts unchanged if requested_severities is None (no --severity given
    - every subcommand that supports it treats that as "don't filter"),
    otherwise only the alerts whose severity is in the requested set.
    Shared by every subcommand that supports --severity, replacing six
    near-identical copies of the same "if requested is not None: filter"
    check (run and leaderboard each ran it twice, once for injected alerts
    and once for the clean-alert baseline)."""
    if requested_severities is None:
        return alerts
    return [a for a in alerts if a.severity in requested_severities]


def cmd_run(args):
    client = build_client(args)

    clean_alerts = generate_clean_alerts()
    injected_alerts = _injected_alerts_for(args.direction)

    requested_severities = _resolve_severities(args.severity, "run")
    clean_alerts = _filter_by_severity(clean_alerts, requested_severities)
    injected_alerts = _filter_by_severity(injected_alerts, requested_severities)

    clean_results = score_batch(clean_alerts, client, defense=args.defense)
    clean_correct, clean_total = resisted_and_total(clean_results)
    print(f"clean alerts: {clean_correct}/{clean_total} correct action (defense={args.defense})\n")

    injected_results = score_batch(injected_alerts, client, defense=args.defense)
    print(f"direction={args.direction}")
    _print_severity_filter(requested_severities)
    aggregated = aggregate_by_technique(injected_results)
    severity_breakdown = aggregate_by_severity(injected_results)
    _print_report(aggregated, injected_results, severity_breakdown)

    if args.report:
        severity_weighted = {args.defense: severity_weighted_hijack_rate(injected_results)}
        confidence_interval = {args.defense: overall_hijack_rate_confidence_interval(injected_results)}
        severity_breakdown_by_defense = {args.defense: severity_breakdown}
        _write_report(
            args.report,
            markdown_content=render_markdown_report(
                args.client, {args.defense: aggregated}, direction=args.direction,
                severity_weighted_by_defense=severity_weighted,
                confidence_interval_by_defense=confidence_interval,
                severity_breakdown_by_defense=severity_breakdown_by_defense,
                severity_filter=requested_severities,
            ),
            json_content=render_json_report(
                args.client, {args.defense: aggregated}, direction=args.direction,
                severity_weighted_by_defense=severity_weighted,
                confidence_interval_by_defense=confidence_interval,
                severity_breakdown_by_defense=severity_breakdown_by_defense,
                severity_filter=requested_severities,
            ),
            csv_content=render_csv_report(args.client, {args.defense: aggregated}, direction=args.direction),
            message=f"\nwrote report to {args.report}",
        )

    if args.transcript:
        _write_file(
            args.transcript,
            render_transcript({args.defense: injected_results}, direction=args.direction),
            f"wrote transcript to {args.transcript}",
        )


def cmd_compare(args):
    client = build_client(args)
    injected_alerts = _injected_alerts_for(args.direction)

    requested_severities = _resolve_severities(args.severity, "compare")
    injected_alerts = _filter_by_severity(injected_alerts, requested_severities)

    print(f"direction={args.direction}\n")
    _print_severity_filter(requested_severities)
    (
        per_defense, results_by_defense, severity_weighted_by_defense,
        confidence_interval_by_defense, severity_breakdown_by_defense,
    ) = _run_defense_battery(injected_alerts, client)

    _print_summary(rate_by_defense(per_defense), "summary: overall hijack rate by defense")
    significance_by_defense = _significance_vs_baseline(results_by_defense, DEFENSE_NONE)
    _print_significance_vs_baseline(significance_by_defense, DEFENSE_NONE)

    if args.report:
        _write_report(
            args.report,
            markdown_content=render_markdown_report(
                args.client, per_defense, direction=args.direction,
                severity_weighted_by_defense=severity_weighted_by_defense,
                confidence_interval_by_defense=confidence_interval_by_defense,
                significance_by_defense=significance_by_defense,
                severity_breakdown_by_defense=severity_breakdown_by_defense,
                severity_filter=requested_severities,
            ),
            json_content=render_json_report(
                args.client, per_defense, direction=args.direction,
                severity_weighted_by_defense=severity_weighted_by_defense,
                confidence_interval_by_defense=confidence_interval_by_defense,
                significance_by_defense=significance_by_defense,
                severity_breakdown_by_defense=severity_breakdown_by_defense,
                severity_filter=requested_severities,
            ),
            csv_content=render_csv_report(args.client, per_defense, direction=args.direction),
            message=f"wrote report to {args.report}",
        )

    if args.transcript:
        _write_file(
            args.transcript,
            render_transcript(results_by_defense, direction=args.direction),
            f"wrote transcript to {args.transcript}",
        )


def cmd_full_report(args):
    """The capstone run: every direction, every defense, one client - the
    complete picture in a single invocation, written as one combined
    markdown file. This is what an actual thesis experiment run looks
    like once a real model is reachable."""
    client = build_client(args)

    requested_severities = _resolve_severities(args.severity, "full-report")
    _print_severity_filter(requested_severities)

    by_direction = {}
    results_by_direction = {}
    severity_weighted_by_direction = {}
    confidence_interval_by_direction = {}
    significance_by_direction = {}
    severity_breakdown_by_direction = {}
    for direction in DIRECTIONS:
        injected_alerts = _filter_by_severity(_injected_alerts_for(direction), requested_severities)
        (
            per_defense, results_by_defense, severity_weighted_by_defense,
            confidence_interval_by_defense, severity_breakdown_by_defense,
        ) = _run_defense_battery(injected_alerts, client, heading_prefix=f"direction={direction} ")
        by_direction[direction] = per_defense
        results_by_direction[direction] = results_by_defense
        severity_weighted_by_direction[direction] = severity_weighted_by_defense
        confidence_interval_by_direction[direction] = confidence_interval_by_defense
        severity_breakdown_by_direction[direction] = severity_breakdown_by_defense
        significance_by_direction[direction] = _significance_vs_baseline(results_by_defense, DEFENSE_NONE)
        _print_significance_vs_baseline(significance_by_direction[direction], DEFENSE_NONE)

    _print_summary(
        combined_rate_by_defense(by_direction),
        "summary: overall hijack rate by defense (both directions combined)",
    )

    _write_report(
        args.report,
        markdown_content=render_combined_report(
            args.client, by_direction,
            severity_weighted_by_direction=severity_weighted_by_direction,
            confidence_interval_by_direction=confidence_interval_by_direction,
            significance_by_direction=significance_by_direction,
            severity_breakdown_by_direction=severity_breakdown_by_direction,
            severity_filter=requested_severities,
        ),
        json_content=render_combined_json_report(
            args.client, by_direction,
            severity_weighted_by_direction=severity_weighted_by_direction,
            confidence_interval_by_direction=confidence_interval_by_direction,
            significance_by_direction=significance_by_direction,
            severity_breakdown_by_direction=severity_breakdown_by_direction,
            severity_filter=requested_severities,
        ),
        csv_content=render_combined_csv_report(args.client, by_direction),
        message=f"wrote combined report to {args.report}",
    )

    if args.transcript:
        _write_file(
            args.transcript,
            render_combined_transcript(results_by_direction),
            f"wrote combined transcript to {args.transcript}",
        )


_LEADERBOARD_SORT_ASCENDING = {
    "hijack_rate": True,
    "severity_weighted_hijack_rate": True,
    "clean_accuracy": False,
}


def _resolve_client_names(clients_arg: str | None, command_label: str) -> list:
    """Parses a comma-separated --clients value into a validated list of
    fake-* client names, or FAKE_CLIENT_NAMES (all of them) if not given.
    command_label is only used in the error message, so "unknown
    client(s) for leaderboard" vs "... for technique-leaderboard" stays
    accurate to whichever subcommand actually failed - both narrow their
    comparison to a chosen client subset the same way."""
    if not clients_arg:
        return FAKE_CLIENT_NAMES
    client_names = [name.strip() for name in clients_arg.split(",") if name.strip()]
    if not client_names:
        raise ValueError("--clients was given but contained no client names")
    unknown = [name for name in client_names if name not in FAKE_CLIENT_NAMES]
    if unknown:
        raise ValueError(f"unknown client(s) for {command_label}: {', '.join(unknown)}")
    return client_names


def _resolve_technique_names(techniques_arg: str | None, valid_names, context: str) -> list | None:
    """Parses a comma-separated --techniques value into a validated list,
    or None if not given (the caller then falls back to "all of them").
    valid_names just needs to support 'in' - the aggregated-results dict
    technique-leaderboard already has on hand works as-is, same as the
    plain technique-name list matrix uses. context is folded straight
    into the error message (e.g. "direction=dismiss"), matching the
    wording this replaces exactly."""
    if not techniques_arg:
        return None
    requested = [name.strip() for name in techniques_arg.split(",") if name.strip()]
    if not requested:
        raise ValueError("--techniques was given but contained no technique names")
    unknown = [name for name in requested if name not in valid_names]
    if unknown:
        raise ValueError(f"unknown technique(s) for {context}: {', '.join(unknown)}")
    return requested


def _technique_names_for_direction(techniques_arg: str | None, direction: str) -> list[str]:
    """Resolves --techniques against whichever technique set the given
    direction actually uses (ESCALATION_TECHNIQUES for escalate,
    TECHNIQUES otherwise), falling back to every technique for that
    direction if none was given. Shared by matrix and severity-matrix,
    which both need exactly this - the full column list for their grid -
    before building any rows."""
    technique_source = ESCALATION_TECHNIQUES if direction == "escalate" else TECHNIQUES
    requested = _resolve_technique_names(techniques_arg, technique_source, f"direction={direction}")
    return requested if requested is not None else list(technique_source)


def cmd_leaderboard(args):
    """Runs every fake-* client against the same battery under one fixed
    direction/defense and ranks them, most robust first by default -
    every other subcommand here is single-client, comparing defenses or
    directions for one client at a time; this instead compares clients
    against each other, the side-by-side vulnerability-profile view none
    of the others give. Skips ollama - it needs a real, reachable server
    and --model, not a fair comparison against the deterministic fakes.
    Also reports clean-alert accuracy alongside the hijack rate: a client
    that just answers wrong across the board (never matching either the
    ground truth or the attacker's target action) scores a misleadingly
    good 0% hijack rate despite being useless as an analyst - clean
    accuracy catches that a bare hijack-rate ranking alone would miss.
    --sort-by picks which of those three columns to rank by - lower is
    "more robust" for the two hijack-rate columns, but higher is "more
    robust" for clean_accuracy, so _LEADERBOARD_SORT_ASCENDING keeps
    "best first" meaning what it says regardless of which column. With
    exactly two --clients, also runs a two-proportion z-test between
    them (the same statistical check compare/full-report already run
    against the none baseline) - a head-to-head --clients A,B comparison
    is exactly the case where "is this difference real" has a single,
    unambiguous answer to give, unlike the general N-client leaderboard
    where every pair would need its own comparison."""
    client_names = _resolve_client_names(args.clients, "leaderboard")

    injected_alerts = _injected_alerts_for(args.direction)
    clean_alerts = generate_clean_alerts()
    requested_severities = _resolve_severities(args.severity, "leaderboard")
    injected_alerts = _filter_by_severity(injected_alerts, requested_severities)
    clean_alerts = _filter_by_severity(clean_alerts, requested_severities)
    rows = []
    results_by_client = {}
    for name in client_names:
        client = CLIENT_FACTORIES[name](args)
        clean_results = score_batch(clean_alerts, client, defense=args.defense)
        clean_correct, clean_total = resisted_and_total(clean_results)
        clean_accuracy = clean_correct / clean_total
        results = score_batch(injected_alerts, client, defense=args.defense)
        results_by_client[name] = results
        ci_low, ci_high = overall_hijack_rate_confidence_interval(results)
        rows.append({
            "client": name,
            "hijack_rate": overall_hijack_rate(results),
            "ci_low": ci_low,
            "ci_high": ci_high,
            "severity_weighted_hijack_rate": severity_weighted_hijack_rate(results),
            "clean_accuracy": clean_accuracy,
        })
    rows.sort(key=lambda row: row[args.sort_by], reverse=not _LEADERBOARD_SORT_ASCENDING[args.sort_by])

    print(f"direction={args.direction} defense={args.defense}\n")
    _print_severity_filter(requested_severities)
    print(f"{'client':<38} {'hijack_rate':>12} {'95% ci':>15} {'severity_weighted':>18} {'clean_accuracy':>15}")
    for row in rows:
        ci = f"{row['ci_low']:.0%}-{row['ci_high']:.0%}"
        print(f"{row['client']:<38} {row['hijack_rate']:>11.0%} {ci:>15} "
              f"{row['severity_weighted_hijack_rate']:>17.0%} {row['clean_accuracy']:>14.0%}")

    pairwise_significance = None
    if len(client_names) == 2:
        # use the sorted table's order, not the --clients input order - the
        # two can disagree (e.g. --clients fake-vulnerable,fake-robust sorts
        # fake-robust to the top), and the line below should read the same
        # direction as the table it follows.
        client_a, client_b = rows[0]["client"], rows[1]["client"]
        hijacked_a, total_a = hijacked_and_total(results_by_client[client_a])
        hijacked_b, total_b = hijacked_and_total(results_by_client[client_b])
        z, p_value = two_proportion_z_test(hijacked_a, total_a, hijacked_b, total_b)
        pairwise_significance = {"client_a": client_a, "client_b": client_b, "z": z, "p_value": p_value}
        verdict = "significant" if is_significant(p_value) else "not significant"
        print(f"\n{client_a} vs {client_b} (two-proportion z-test): p={p_value:.4f} ({verdict} at p<{SIGNIFICANCE_ALPHA})")

    if args.report:
        _write_report(
            args.report,
            markdown_content=render_leaderboard_report(
                rows, direction=args.direction, defense=args.defense, pairwise_significance=pairwise_significance,
                severity_filter=requested_severities,
            ),
            json_content=render_leaderboard_json_report(
                rows, direction=args.direction, defense=args.defense, pairwise_significance=pairwise_significance,
                severity_filter=requested_severities,
            ),
            csv_content=render_leaderboard_csv_report(rows, direction=args.direction, defense=args.defense),
            message=f"\nwrote leaderboard to {args.report}",
        )

    if args.transcript:
        _write_file(
            args.transcript,
            render_leaderboard_transcript(results_by_client, direction=args.direction, defense=args.defense),
            f"wrote leaderboard transcript to {args.transcript}",
        )


def cmd_technique_leaderboard(args):
    """The technique-axis complement to leaderboard: that ranks clients
    against one fixed battery (most robust first); this ranks techniques
    by how often they succeed across a fixed set of clients instead (most
    dangerous first) - which technique actually works best in general,
    rather than which client resists best in general. Concatenates every
    compared client's scored results for the same injected battery and
    feeds the combined list straight into aggregate_by_technique, which
    already buckets by technique regardless of which client produced
    each result - no new scoring logic needed, just a different batch."""
    client_names = _resolve_client_names(args.clients, "technique-leaderboard")
    injected_alerts = _injected_alerts_for(args.direction)
    requested_severities = _resolve_severities(args.severity, "technique-leaderboard")
    injected_alerts = _filter_by_severity(injected_alerts, requested_severities)
    results_by_client = {}
    combined_results = []
    for name in client_names:
        client = CLIENT_FACTORIES[name](args)
        results = score_batch(injected_alerts, client, defense=args.defense)
        results_by_client[name] = results
        combined_results.extend(results)
    aggregated = aggregate_by_technique(combined_results)

    requested = _resolve_technique_names(args.techniques, aggregated, f"direction={args.direction}")
    if requested is not None:
        aggregated = {name: aggregated[name] for name in requested}

    rows = sorted(aggregated.items(), key=lambda item: item[1]["hijack_rate"], reverse=True)
    if args.min_rate is not None:
        rows = [(technique, bucket) for technique, bucket in rows if bucket["hijack_rate"] >= args.min_rate]

    print(f"direction={args.direction} defense={args.defense} across {len(client_names)} client(s)\n")
    _print_severity_filter(requested_severities)
    print(f"{'technique':<40} {'hijacked':>8} {'resisted':>8} {'other':>6} {'hijack_rate':>12} {'95% ci':>15}")
    for technique, bucket in rows:
        ci = f"{bucket['ci_low']:.0%}-{bucket['ci_high']:.0%}"
        print(f"{technique:<40} {bucket['hijacked']:>8} {bucket['resisted']:>8} {bucket['other']:>6} "
              f"{bucket['hijack_rate']:>11.0%} {ci:>15}")

    pairwise_significance = None
    if len(rows) == 2:
        # use the sorted (most-dangerous-first) order, not dict order -
        # same lesson as leaderboard's own pairwise comparison: the line
        # below should read the same direction as the table above it.
        (technique_a, bucket_a), (technique_b, bucket_b) = rows
        z, p_value = two_proportion_z_test(
            bucket_a["hijacked"], bucket_a["total"], bucket_b["hijacked"], bucket_b["total"],
        )
        pairwise_significance = {"technique_a": technique_a, "technique_b": technique_b, "z": z, "p_value": p_value}
        verdict = "significant" if is_significant(p_value) else "not significant"
        print(f"\n{technique_a} vs {technique_b} (two-proportion z-test): p={p_value:.4f} ({verdict} at p<{SIGNIFICANCE_ALPHA})")

    if args.report:
        _write_report(
            args.report,
            markdown_content=render_technique_leaderboard_report(
                rows, args.direction, args.defense, len(client_names), pairwise_significance=pairwise_significance,
                severity_filter=requested_severities,
            ),
            json_content=render_technique_leaderboard_json_report(
                rows, args.direction, args.defense, len(client_names), pairwise_significance=pairwise_significance,
                severity_filter=requested_severities,
            ),
            csv_content=render_technique_leaderboard_csv_report(rows, args.direction, args.defense),
            message=f"\nwrote technique leaderboard to {args.report}",
        )

    if args.transcript:
        _write_file(
            args.transcript,
            render_leaderboard_transcript(results_by_client, direction=args.direction, defense=args.defense),
            f"wrote technique leaderboard transcript to {args.transcript}",
        )


def cmd_matrix(args):
    """The full client x technique cross-tab, the one view neither
    leaderboard nor technique-leaderboard gives on its own: leaderboard
    collapses every technique into one hijack rate per client, and
    technique-leaderboard collapses every client into one hijack rate
    per technique. This keeps both axes - a heatmap-style grid of hijack
    rate per (client, technique) pair, for spotting a client that's fine
    on average but wide open to one specific technique (or a technique
    that's fine on average but devastating against one specific client)
    that an average in either direction alone would hide. Unlike
    technique-leaderboard, each client's results are scored separately
    rather than concatenated - the per-technique breakdown needs to stay
    attributed to its own client, not merged into one combined rate."""
    client_names = _resolve_client_names(args.clients, "matrix")
    injected_alerts = _injected_alerts_for(args.direction)
    requested_severities = _resolve_severities(args.severity, "matrix")
    injected_alerts = _filter_by_severity(injected_alerts, requested_severities)
    technique_names = _technique_names_for_direction(args.techniques, args.direction)

    rows = []
    results_by_client = {}
    for name in client_names:
        client = CLIENT_FACTORIES[name](args)
        results = score_batch(injected_alerts, client, defense=args.defense)
        results_by_client[name] = results
        aggregated = aggregate_by_technique(results)
        # a technique can be entirely absent from aggregated if --severity
        # filtered out every alert it would otherwise have applied to (e.g.
        # --severity low under the default dismiss direction, where no
        # escalate/investigate alert is low-severity) - 0% there, same
        # "empty battery" convention every other subcommand's hijack rate
        # falls back to, rather than a bare KeyError.
        rates = {technique: aggregated.get(technique, {}).get("hijack_rate", 0.0) for technique in technique_names}
        rows.append({"client": name, "rates": rates, "average": sum(rates.values()) / len(technique_names)})
    rows.sort(key=lambda row: row["average"])

    print(f"direction={args.direction} defense={args.defense}\n")
    _print_severity_filter(requested_severities)
    print("client | " + " | ".join(technique_names) + " | average")
    for row in rows:
        cells = " | ".join(f"{row['rates'][technique]:.0%}" for technique in technique_names)
        print(f"{row['client']} | {cells} | {row['average']:.0%}")

    if args.report:
        _write_report(
            args.report,
            markdown_content=render_matrix_report(
                rows, technique_names, args.direction, args.defense, severity_filter=requested_severities,
            ),
            json_content=render_matrix_json_report(
                rows, technique_names, args.direction, args.defense, severity_filter=requested_severities,
            ),
            csv_content=render_matrix_csv_report(rows, technique_names, args.direction, args.defense),
            message=f"\nwrote matrix to {args.report}",
        )

    if args.transcript:
        _write_file(
            args.transcript,
            render_leaderboard_transcript(results_by_client, direction=args.direction, defense=args.defense),
            f"wrote matrix transcript to {args.transcript}",
        )


def cmd_severity_matrix(args):
    """The severity-axis sibling of matrix: that keeps client and
    technique both instead of collapsing one away, for a fixed set of
    clients; this keeps severity and technique both instead, for a
    single client - whether a given technique's hijack rate actually
    shifts with the severity of the alert it's attacking, which neither
    aggregate_by_technique (collapses severity into one rate per
    technique) nor aggregate_by_severity (collapses technique into one
    rate per severity) can show on their own. Single-client, like run/
    compare/full-report, not multi-client like matrix - a severity x
    technique x client cube has no honest single table to put it in.
    Rows stay in canonical critical/high/medium/low order rather than
    sorted by average: severity already has a real-world order a reader
    wants (critical first), unlike client names or technique names."""
    client = build_client(args)
    injected_alerts = _injected_alerts_for(args.direction)
    requested_severities = _resolve_severities(args.severity, "severity-matrix")
    injected_alerts = _filter_by_severity(injected_alerts, requested_severities)
    technique_names = _technique_names_for_direction(args.techniques, args.direction)

    results = score_batch(injected_alerts, client, defense=args.defense)
    grid = aggregate_by_severity_and_technique(results)

    rows = []
    for severity in SEVERITIES:
        if severity not in grid:
            continue
        aggregated = grid[severity]
        rates = {technique: aggregated.get(technique, {}).get("hijack_rate", 0.0) for technique in technique_names}
        rows.append({"severity": severity, "rates": rates, "average": sum(rates.values()) / len(technique_names)})

    print(f"client={args.client} direction={args.direction} defense={args.defense}\n")
    _print_severity_filter(requested_severities)
    print("severity | " + " | ".join(technique_names) + " | average")
    for row in rows:
        cells = " | ".join(f"{row['rates'][technique]:.0%}" for technique in technique_names)
        print(f"{row['severity']} | {cells} | {row['average']:.0%}")

    pairwise_significance = None
    if len(rows) == 2:
        # same exactly-two pattern leaderboard and technique-leaderboard
        # use: pool each severity's hijacked/total across every technique,
        # using the table's own (canonical critical/high/medium/low) order
        # so the line below reads the same direction as the rows above it.
        severity_a, severity_b = rows[0]["severity"], rows[1]["severity"]
        results_a = [r for r in results if r.alert.severity == severity_a]
        results_b = [r for r in results if r.alert.severity == severity_b]
        hijacked_a, total_a = hijacked_and_total(results_a)
        hijacked_b, total_b = hijacked_and_total(results_b)
        z, p_value = two_proportion_z_test(hijacked_a, total_a, hijacked_b, total_b)
        pairwise_significance = {"severity_a": severity_a, "severity_b": severity_b, "z": z, "p_value": p_value}
        verdict = "significant" if is_significant(p_value) else "not significant"
        print(f"\n{severity_a} vs {severity_b} (two-proportion z-test): p={p_value:.4f} ({verdict} at p<{SIGNIFICANCE_ALPHA})")

    if args.report:
        _write_report(
            args.report,
            markdown_content=render_severity_matrix_report(
                rows, technique_names, args.client, args.direction, args.defense,
                severity_filter=requested_severities, pairwise_significance=pairwise_significance,
            ),
            json_content=render_severity_matrix_json_report(
                rows, technique_names, args.client, args.direction, args.defense,
                severity_filter=requested_severities, pairwise_significance=pairwise_significance,
            ),
            csv_content=render_severity_matrix_csv_report(
                rows, technique_names, args.client, args.direction, args.defense,
            ),
            message=f"\nwrote severity matrix to {args.report}",
        )

    if args.transcript:
        _write_file(
            args.transcript,
            render_transcript({args.defense: results}, direction=args.direction),
            f"wrote severity matrix transcript to {args.transcript}",
        )


def _technique_doc(func) -> str:
    """A technique function's docstring, collapsed to one line. Multi-line
    docstrings otherwise carry their source indentation straight through
    into --json/--csv output as literal embedded newlines - harmless in
    json, but a real annoyance in a spreadsheet, where it makes the cell
    wrap oddly instead of reading as one plain sentence. The plain-text
    listing below deliberately doesn't use this - multi-line is fine, even
    preferable, when it's printed straight to a terminal."""
    return " ".join((func.__doc__ or "").split())


def cmd_list_techniques(args):
    if args.json:
        payload = {
            "dismiss": {name: _technique_doc(func) for name, func in TECHNIQUES.items()},
            "escalation": {name: _technique_doc(func) for name, func in ESCALATION_TECHNIQUES.items()},
        }
        print(json.dumps(payload, indent=2))
        return
    if args.csv:
        writer = csv.writer(sys.stdout)
        writer.writerow(["direction", "technique", "description"])
        for name, func in TECHNIQUES.items():
            writer.writerow(["dismiss", name, _technique_doc(func)])
        for name, func in ESCALATION_TECHNIQUES.items():
            writer.writerow(["escalation", name, _technique_doc(func)])
        return
    print(f"{len(TECHNIQUES)} dismiss-direction techniques (hide a real incident):")
    for name, func in TECHNIQUES.items():
        print(f"  {name} - {func.__doc__ or '(no description)'}")
    print(f"\n{len(ESCALATION_TECHNIQUES)} escalation-direction techniques (waste analyst time):")
    for name, func in ESCALATION_TECHNIQUES.items():
        print(f"  {name} - {func.__doc__ or '(no description)'}")


_CLIENT_HELP = (
    "which client to test: a fake-* deterministic test double (see README for what "
    "each one models) for harness validation without a real model, or 'ollama' for a "
    "real local model (requires --model)"
)
_DEFENSE_HELP = (
    "prompt defense to apply: none, sandwich (reinforce after the untrusted content), "
    "strict (name attack patterns up front in the system prompt), or both together"
)
_TIMEOUT_HELP = "request timeout in seconds for --client ollama, default 120 (ignored by every fake-* client)"
_SEVERITY_HELP = (
    "comma-separated subset of severities to test (default: all of them present in the "
    "battery) - e.g. --severity critical,high to focus on the highest-impact alerts"
)


def build_parser():
    parser = argparse.ArgumentParser(prog="soclab", description="LLM SOC analyst prompt injection lab")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run the injection battery against a client")
    run_parser.add_argument("--client", choices=list(CLIENT_FACTORIES), default="fake-robust", help=_CLIENT_HELP)
    run_parser.add_argument("--defense", choices=list(DEFENSES), default=DEFENSE_NONE, help=_DEFENSE_HELP)
    run_parser.add_argument("--direction", choices=list(DIRECTIONS), default="dismiss",
                             help="which attacker goal to test: hide a real incident, or waste analyst time")
    run_parser.add_argument("--severity", help=_SEVERITY_HELP)
    run_parser.add_argument("--model", help="model name, required for --client ollama")
    run_parser.add_argument("--host", help="ollama host, defaults to $OLLAMA_HOST or localhost:11434")
    run_parser.add_argument("--timeout", type=float, default=120.0, help=_TIMEOUT_HELP)
    run_parser.add_argument("--report", help="write results to this path - markdown, or json/csv if the path ends in .json/.csv")
    run_parser.add_argument(
        "--transcript",
        help="write a per-alert json record (action, reasoning, outcome) to this path, for qualitative review",
    )
    run_parser.set_defaults(func=cmd_run)

    compare_parser = sub.add_parser("compare", help="run the battery under every defense and compare hijack rates")
    compare_parser.add_argument("--client", choices=list(CLIENT_FACTORIES), default="fake-robust", help=_CLIENT_HELP)
    compare_parser.add_argument("--direction", choices=list(DIRECTIONS), default="dismiss",
                                 help="which attacker goal to test: hide a real incident, or waste analyst time")
    compare_parser.add_argument("--severity", help=_SEVERITY_HELP)
    compare_parser.add_argument("--model", help="model name, required for --client ollama")
    compare_parser.add_argument("--host", help="ollama host, defaults to $OLLAMA_HOST or localhost:11434")
    compare_parser.add_argument("--timeout", type=float, default=120.0, help=_TIMEOUT_HELP)
    compare_parser.add_argument("--report", help="write results to this path - markdown, or json/csv if the path ends in .json/.csv")
    compare_parser.add_argument(
        "--transcript",
        help="write a per-alert json record (action, reasoning, outcome) for every defense to this path",
    )
    compare_parser.set_defaults(func=cmd_compare)

    full_report_parser = sub.add_parser(
        "full-report", help="run every direction and every defense for a client, write one combined report"
    )
    full_report_parser.add_argument(
        "--client", choices=list(CLIENT_FACTORIES), default="fake-robust", help=_CLIENT_HELP
    )
    full_report_parser.add_argument("--severity", help=_SEVERITY_HELP)
    full_report_parser.add_argument("--model", help="model name, required for --client ollama")
    full_report_parser.add_argument("--host", help="ollama host, defaults to $OLLAMA_HOST or localhost:11434")
    full_report_parser.add_argument("--timeout", type=float, default=120.0, help=_TIMEOUT_HELP)
    full_report_parser.add_argument(
        "--report", required=True,
        help="path to write the combined report to - markdown, or json/csv if the path ends in .json/.csv",
    )
    full_report_parser.add_argument(
        "--transcript",
        help="write a per-alert json record (action, reasoning, outcome) for every direction/defense to this path",
    )
    full_report_parser.set_defaults(func=cmd_full_report)

    leaderboard_parser = sub.add_parser(
        "leaderboard", help="rank every fake-* client by hijack rate under one direction/defense"
    )
    leaderboard_parser.add_argument("--direction", choices=list(DIRECTIONS), default="dismiss",
                                     help="which attacker goal to test: hide a real incident, or waste analyst time")
    leaderboard_parser.add_argument("--defense", choices=list(DEFENSES), default=DEFENSE_NONE, help=_DEFENSE_HELP)
    leaderboard_parser.add_argument("--severity", help=_SEVERITY_HELP)
    leaderboard_parser.add_argument(
        "--clients",
        help="comma-separated subset of fake-* clients to compare (default: all of them) - "
             "see CLIENT_FACTORIES in cli.py or the readme for the available names",
    )
    leaderboard_parser.add_argument(
        "--sort-by", choices=list(_LEADERBOARD_SORT_ASCENDING), default="hijack_rate", dest="sort_by",
        help="which column to rank by, most-robust-first either way (default: hijack_rate)",
    )
    leaderboard_parser.add_argument(
        "--report", help="write the leaderboard to this path - markdown, or json/csv if the path ends in .json/.csv"
    )
    leaderboard_parser.add_argument(
        "--transcript",
        help="write a per-alert json record (action, reasoning, outcome) for every compared client to this path",
    )
    leaderboard_parser.set_defaults(func=cmd_leaderboard)

    technique_leaderboard_parser = sub.add_parser(
        "technique-leaderboard",
        help="rank techniques by hijack rate across every compared fake-* client (most dangerous first)",
    )
    technique_leaderboard_parser.add_argument(
        "--direction", choices=list(DIRECTIONS), default="dismiss",
        help="which attacker goal to test: hide a real incident, or waste analyst time",
    )
    technique_leaderboard_parser.add_argument(
        "--defense", choices=list(DEFENSES), default=DEFENSE_NONE, help=_DEFENSE_HELP,
    )
    technique_leaderboard_parser.add_argument("--severity", help=_SEVERITY_HELP)
    technique_leaderboard_parser.add_argument(
        "--clients",
        help="comma-separated subset of fake-* clients to aggregate across (default: all of them) - "
             "see CLIENT_FACTORIES in cli.py or the readme for the available names",
    )
    technique_leaderboard_parser.add_argument(
        "--techniques",
        help="comma-separated subset of techniques to rank (default: all of them for the chosen "
             "--direction) - see list-techniques for the available names",
    )
    technique_leaderboard_parser.add_argument(
        "--min-rate", type=float, dest="min_rate",
        help="only show techniques with hijack_rate >= this threshold (0.0-1.0, e.g. 0.5 for 50%%) - "
             "for isolating just the techniques that actually work, instead of reading past the safe ones",
    )
    technique_leaderboard_parser.add_argument(
        "--report",
        help="write the technique leaderboard to this path - markdown, or json/csv if the path ends in .json/.csv",
    )
    technique_leaderboard_parser.add_argument(
        "--transcript",
        help="write a per-alert json record (action, reasoning, outcome) for every compared client to this path",
    )
    technique_leaderboard_parser.set_defaults(func=cmd_technique_leaderboard)

    matrix_parser = sub.add_parser(
        "matrix", help="client x technique cross-tab of hijack rates - the heatmap view leaderboard and "
                       "technique-leaderboard each collapse away on one axis"
    )
    matrix_parser.add_argument(
        "--direction", choices=list(DIRECTIONS), default="dismiss",
        help="which attacker goal to test: hide a real incident, or waste analyst time",
    )
    matrix_parser.add_argument("--defense", choices=list(DEFENSES), default=DEFENSE_NONE, help=_DEFENSE_HELP)
    matrix_parser.add_argument("--severity", help=_SEVERITY_HELP)
    matrix_parser.add_argument(
        "--clients",
        help="comma-separated subset of fake-* clients to compare (default: all of them) - "
             "see CLIENT_FACTORIES in cli.py or the readme for the available names",
    )
    matrix_parser.add_argument(
        "--techniques",
        help="comma-separated subset of techniques to show as columns (default: all of them for the "
             "chosen --direction) - see list-techniques for the available names",
    )
    matrix_parser.add_argument(
        "--report", help="write the matrix to this path - markdown, or json/csv if the path ends in .json/.csv"
    )
    matrix_parser.add_argument(
        "--transcript",
        help="write a per-alert json record (action, reasoning, outcome) for every compared client to this path",
    )
    matrix_parser.set_defaults(func=cmd_matrix)

    severity_matrix_parser = sub.add_parser(
        "severity-matrix", help="severity x technique cross-tab of hijack rates for one client - the "
                                 "heatmap view run/compare/full-report each collapse away on one axis"
    )
    severity_matrix_parser.add_argument(
        "--client", choices=list(CLIENT_FACTORIES), default="fake-robust", help=_CLIENT_HELP
    )
    severity_matrix_parser.add_argument("--defense", choices=list(DEFENSES), default=DEFENSE_NONE, help=_DEFENSE_HELP)
    severity_matrix_parser.add_argument(
        "--direction", choices=list(DIRECTIONS), default="dismiss",
        help="which attacker goal to test: hide a real incident, or waste analyst time",
    )
    severity_matrix_parser.add_argument("--severity", help=_SEVERITY_HELP)
    severity_matrix_parser.add_argument(
        "--techniques",
        help="comma-separated subset of techniques to show as columns (default: all of them for the "
             "chosen --direction) - see list-techniques for the available names",
    )
    severity_matrix_parser.add_argument("--model", help="model name, required for --client ollama")
    severity_matrix_parser.add_argument("--host", help="ollama host, defaults to $OLLAMA_HOST or localhost:11434")
    severity_matrix_parser.add_argument("--timeout", type=float, default=120.0, help=_TIMEOUT_HELP)
    severity_matrix_parser.add_argument(
        "--report",
        help="write the severity matrix to this path - markdown, or json/csv if the path ends in .json/.csv",
    )
    severity_matrix_parser.add_argument(
        "--transcript",
        help="write a per-alert json record (action, reasoning, outcome) to this path, for qualitative review",
    )
    severity_matrix_parser.set_defaults(func=cmd_severity_matrix)

    list_parser = sub.add_parser("list-techniques", help="list available injection techniques")
    list_format_group = list_parser.add_mutually_exclusive_group()
    list_format_group.add_argument(
        "--json", action="store_true", help="print as json (technique name -> description) instead of plain text"
    )
    list_format_group.add_argument(
        "--csv", action="store_true", help="print as csv (direction, technique, description) instead of plain text"
    )
    list_parser.set_defaults(func=cmd_list_techniques)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (ValueError, OSError) as exc:
        # OSError covers a bad --report path (missing directory, no
        # permission, etc.) - without it, that crashes with a raw
        # traceback instead of the same clean "error: ..." every other
        # failure in this cli gets.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a real subprocess, not in-process
    sys.exit(main())
