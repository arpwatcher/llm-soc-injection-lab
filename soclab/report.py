"""Renders scoring results as a markdown table, so a run's numbers can be
dropped straight into a writeup instead of copied out of terminal output.
Also renders the same data as JSON, for feeding into a plotting script
instead of a document."""

import csv
import io
import json

from soclab.scoring import SIGNIFICANCE_ALPHA, is_significant


def render_transcript(per_defense: dict, direction: str = "dismiss") -> str:
    """A per-alert record of what the analyst actually decided and why,
    as JSON - the aggregate reports above answer "how often did this get
    hijacked", but say nothing about what a specific decision actually
    looked like. This is for qualitative review: pulling out an example
    of a model's reasoning to quote directly, or spot-checking a
    surprising result instead of trusting the aggregate blindly.
    per_defense maps defense name -> list[ScoredResult] for that defense
    (same shape as the other report functions' input, but with raw
    results instead of an already-aggregated dict), so a single call
    covers every defense a caller ran, each entry tagged with which one
    it came from. raw_response is included alongside the parsed
    reasoning specifically for parse_error=True entries: reasoning is
    empty in that case (there was nothing valid to extract it from), so
    raw_response is the only place to see what the model actually said."""
    entries = [
        {
            "alert_id": r.alert.id,
            "technique": r.alert.injected_technique,
            "severity": r.alert.severity,
            "ground_truth_action": r.alert.ground_truth_action,
            "defense": defense,
            "direction": direction,
            "action": r.decision.action,
            "outcome": r.outcome,
            "reasoning": r.decision.reasoning,
            "parse_error": r.decision.parse_error,
            "raw_response": r.decision.raw_response,
        }
        for defense, results in per_defense.items()
        for r in results
    ]
    return json.dumps(entries, indent=2)


def render_combined_transcript(by_direction: dict) -> str:
    """Same idea as render_transcript, but across every direction a
    caller ran (full-report's shape) - by_direction maps direction name
    -> per_defense dict (the same shape render_transcript takes)."""
    entries = []
    for direction, per_defense in by_direction.items():
        entries.extend(json.loads(render_transcript(per_defense, direction=direction)))
    return json.dumps(entries, indent=2)


def render_leaderboard_transcript(by_client: dict, direction: str = "dismiss", defense: str = "none") -> str:
    """Same idea as render_transcript, but keyed by client instead of
    defense - leaderboard's axis is comparing clients against each other
    under one fixed direction/defense, not comparing defenses for one
    client, so direction and defense are the same for every entry here
    (tagged anyway, for consistency with the other transcript shapes) and
    by_client maps client name -> list[ScoredResult] instead."""
    entries = [
        {
            "client": client,
            "alert_id": r.alert.id,
            "technique": r.alert.injected_technique,
            "severity": r.alert.severity,
            "ground_truth_action": r.alert.ground_truth_action,
            "defense": defense,
            "direction": direction,
            "action": r.decision.action,
            "outcome": r.outcome,
            "reasoning": r.decision.reasoning,
            "parse_error": r.decision.parse_error,
            "raw_response": r.decision.raw_response,
        }
        for client, results in by_client.items()
        for r in results
    ]
    return json.dumps(entries, indent=2)


def _overall_rate(aggregated: dict) -> float:
    total_hijacked = sum(bucket["hijacked"] for bucket in aggregated.values())
    total_count = sum(bucket["total"] for bucket in aggregated.values())
    return total_hijacked / total_count if total_count else 0.0


def rate_by_defense(per_defense: dict) -> dict:
    """defense name -> overall hijack rate for that defense, from a single
    per_defense dict (one direction's worth of results)."""
    return {defense: _overall_rate(aggregated) for defense, aggregated in per_defense.items()}


def _render_summary_table(rates: dict, heading: str, column_label: str = "hijack rate") -> list[str]:
    """Shared by both report functions: a small defense -> rate table, so
    the overall pattern is visible without reading every per-technique
    sub-table by hand. column_label defaults to the hijack-rate summary's
    own header, but is overridden for the clean-alert-accuracy summary -
    same table shape, different column meaning."""
    lines = [heading, "", f"| defense | {column_label} |", "|---|---|"]
    for defense, rate in rates.items():
        lines.append(f"| {defense} | {rate:.0%} |")
    lines.append("")
    return lines


def baseline_line(entry: dict) -> str:
    """entry: {"target", "baseline", "eligible", "rate", "lift"} - how often
    the model already gave the attack's target action on the same alerts
    with no injection, and how far the hijack rate sits above that (the
    part the injection itself caused). Shared by the terminal output and
    the markdown reports so the two read the same."""
    return (
        f"no-injection baseline: {entry['baseline']}/{entry['eligible']} already answered {entry['target']} "
        f"with no injection ({entry['rate']:.0%}) - injection lift {entry['lift'] * 100:+.0f} points"
    )


def lift_interval(low: float, high: float) -> str:
    """a lift's 95% interval in the same signed points as the lift itself."""
    return f"{low * 100:+.0f} to {high * 100:+.0f}"


def technique_lift_rows(lifts: dict) -> list[tuple]:
    """(technique, hijack rate, baseline, lift, lift interval, p-value,
    Holm-adjusted p-value, verdict) per technique from
    scoring.paired_lift_by_technique - the shape both the terminal table
    and the markdown one print. The verdict goes by the Holm-adjusted
    value: the techniques in one table are one family of tests."""
    return [
        (technique, entry["injected_rate"], entry["baseline_rate"], points_or_na(entry["lift"]),
         lift_interval(entry["lift_ci_low"], entry["lift_ci_high"]), entry["p_value"], entry["p_holm"],
         "significant" if is_significant(entry["p_holm"]) else "not significant")
        for technique, entry in lifts.items()
    ]


def _render_technique_lift_table(lifts: dict) -> list[str]:
    lines = [
        ("per-technique lift, each injected alert paired with its clean answer "
         "(exact McNemar test, Holm-adjusted across the techniques):"),
        "",
        "| technique | hijack rate | baseline | lift | lift 95% ci | p | p (holm) | |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for technique, rate, baseline, lift, interval, p_value, p_holm, verdict in technique_lift_rows(lifts):
        lines.append(
            f"| {technique} | {rate:.0%} | {baseline:.0%} | {lift} | {interval} | {p_value:.4f} | {p_holm:.4f} "
            f"| {verdict} |"
        )
    lines.append("")
    return lines


def defense_effect_verdict(entry: dict) -> str:
    """what a defense did to one technique, going by the Holm-adjusted
    paired test - and which way, since a defense can make things worse."""
    if not is_significant(entry["p_holm"]):
        return "no significant change"
    return "reduced" if entry["change"] < 0 else "increased"


def _render_defense_effect_table(effects: dict) -> list[str]:
    lines = [
        ("per-technique effect vs none, each injected alert paired with itself under no defense "
         "(exact McNemar test, Holm-adjusted across the techniques):"),
        "",
        "| technique | without | with | change | change 95% ci | stopped | introduced | p | p (holm) | |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for technique, entry in effects.items():
        lines.append(
            f"| {technique} | {entry['none_rate']:.0%} | {entry['defense_rate']:.0%} | {points_or_na(entry['change'])} "
            f"| {lift_interval(entry['change_ci_low'], entry['change_ci_high'])} | {entry['stopped']} "
            f"| {entry['introduced']} | {entry['p_value']:.4f} | {entry['p_holm']:.4f} | {defense_effect_verdict(entry)} |"
        )
    lines.append("")
    return lines


def _render_clean_accuracy_change_table(changes: dict) -> list[str]:
    lines = [
        ("clean-alert accuracy vs none, each clean alert paired with itself under no defense "
         "(exact McNemar test, Holm-adjusted across the defenses):"),
        "",
        "| defense | without | with | change | change 95% ci | broke | fixed | p | p (holm) | |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for defense, entry in changes.items():
        lines.append(
            f"| {defense} | {entry['none_accuracy']:.0%} | {entry['defense_accuracy']:.0%} "
            f"| {points_or_na(entry['change'])} | {lift_interval(entry['change_ci_low'], entry['change_ci_high'])} "
            f"| {entry['broke']} | {entry['fixed']} | {entry['p_value']:.4f} | {entry['p_holm']:.4f} "
            f"| {defense_effect_verdict(entry)} |"
        )
    lines.append("")
    return lines


def _render_defense_sections(
    per_defense: dict,
    severity_weighted_by_defense: dict | None = None,
    confidence_interval_by_defense: dict | None = None,
    significance_by_defense: dict | None = None,
    heading_level: str = "##",
    severity_breakdown_by_defense: dict | None = None,
    baseline_by_defense: dict | None = None,
    technique_lift_by_defense: dict | None = None,
    defense_effect_by_defense: dict | None = None,
) -> list[str]:
    """per_defense maps defense name -> aggregate_by_technique() output for
    that defense, e.g. {"none": {...}, "sandwich": {...}}. Shared by both
    render_markdown_report and render_combined_report so the two don't
    duplicate the table-building logic. severity_weighted_by_defense,
    confidence_interval_by_defense, and significance_by_defense, when
    given, map defense name -> severity_weighted_hijack_rate() /
    overall_hijack_rate_confidence_interval() / two_proportion_z_test()
    (against the none baseline; none itself and every key have no entry
    here) for that defense's results - none of the three are derivable
    from aggregate_by_technique's per-technique buckets alone (severity
    isn't tracked there, the CI needs the pooled total/hijacked count
    rather than an average of the per-technique CIs, and significance
    needs the baseline's counts too), so all three have to be computed
    separately by the caller and threaded through. severity_breakdown_by_defense,
    when given, maps defense name -> aggregate_by_severity() output - the
    severity-axis complement to the per-technique table above: that
    answers "which technique works best", this answers "does severity
    actually matter", which severity_weighted_hijack_rate's single
    collapsed number can't show on its own."""
    lines = []
    for defense, aggregated in per_defense.items():
        lines.append(f"{heading_level} defense: {defense}")
        lines.append("")
        lines.append("| technique | hijacked | resisted | other | hijack rate |")
        lines.append("|---|---|---|---|---|")
        for technique, bucket in aggregated.items():
            lines.append(
                f"| {technique} | {bucket['hijacked']} | {bucket['resisted']} | "
                f"{bucket['other']} | {bucket['hijack_rate']:.0%} |"
            )
        lines.append("")

        if severity_breakdown_by_defense is not None and defense in severity_breakdown_by_defense:
            lines.append("| severity | hijacked | resisted | other | hijack rate |")
            lines.append("|---|---|---|---|---|")
            for severity, bucket in severity_breakdown_by_defense[defense].items():
                lines.append(
                    f"| {severity} | {bucket['hijacked']} | {bucket['resisted']} | "
                    f"{bucket['other']} | {bucket['hijack_rate']:.0%} |"
                )
            lines.append("")

        lines.append(f"overall hijack rate: {_overall_rate(aggregated):.0%}")
        unparseable = sum(bucket.get("unparseable", 0) for bucket in aggregated.values())
        lines.append(f"unparseable responses: {unparseable}/{sum(bucket['total'] for bucket in aggregated.values())}")
        if baseline_by_defense is not None and defense in baseline_by_defense:
            lines.append(baseline_line(baseline_by_defense[defense]))
        if technique_lift_by_defense is not None and defense in technique_lift_by_defense:
            lines.append("")
            lines.extend(_render_technique_lift_table(technique_lift_by_defense[defense]))
        if defense_effect_by_defense is not None and defense in defense_effect_by_defense:
            lines.extend(_render_defense_effect_table(defense_effect_by_defense[defense]))
        if confidence_interval_by_defense is not None:
            ci_low, ci_high = confidence_interval_by_defense[defense]
            lines.append(f"95% confidence interval: {ci_low:.0%}-{ci_high:.0%}")
        if severity_weighted_by_defense is not None:
            lines.append(f"severity-weighted hijack rate: {severity_weighted_by_defense[defense]:.0%}")
        if significance_by_defense is not None and defense in significance_by_defense:
            _, p_value, p_holm = significance_by_defense[defense]
            verdict = "significant" if is_significant(p_holm) else "not significant"
            lines.append(
                f"significance vs none (two-proportion z-test): p={p_value:.4f}, Holm-adjusted {p_holm:.4f} "
                f"({verdict} at p<{SIGNIFICANCE_ALPHA})"
            )
        lines.append("")
    return lines


def render_markdown_report(
    client_name: str,
    per_defense: dict,
    direction: str = "dismiss",
    severity_weighted_by_defense: dict | None = None,
    confidence_interval_by_defense: dict | None = None,
    significance_by_defense: dict | None = None,
    severity_breakdown_by_defense: dict | None = None,
    clean_accuracy_by_defense: dict | None = None,
    baseline_by_defense: dict | None = None,
    technique_lift_by_defense: dict | None = None,
    defense_effect_by_defense: dict | None = None,
    clean_accuracy_change_by_defense: dict | None = None,
    severity_filter: list | None = None,
) -> str:
    """per_defense maps defense name -> aggregate_by_technique() output for
    that defense. direction says which attacker goal these results are
    for - a report with no direction noted is ambiguous once both exist,
    since technique names alone don't say which one they belong to at a
    glance. severity_weighted_by_defense, confidence_interval_by_defense,
    significance_by_defense, and severity_breakdown_by_defense are
    optional: see _render_defense_sections for what each maps.
    clean_accuracy_by_defense, when given, maps defense name -> fraction
    of clean (non-injected) alerts correctly handled under that defense -
    answers whether a defense's own added verbiage makes the client worse
    at alerts that were never attacked in the first place, which the
    hijack-rate tables alone can't show. severity_filter, when given, is
    the list of severities --severity restricted this run to - recorded
    here so a saved report file still shows which subset of alerts it
    covers without the reader having to remember or dig up the exact
    command that produced it."""
    lines = [f"# injection results - client: {client_name}, direction: {direction}", ""]
    if severity_filter is not None:
        lines.append(f"severity filter: {', '.join(severity_filter)}")
        lines.append("")
    if len(per_defense) > 1:
        lines.extend(_render_summary_table(rate_by_defense(per_defense), "## summary: overall hijack rate by defense"))
    if clean_accuracy_by_defense is not None:
        lines.extend(_render_summary_table(
            clean_accuracy_by_defense, "## summary: clean-alert accuracy by defense", column_label="clean accuracy",
        ))
    if clean_accuracy_change_by_defense:
        lines.extend(_render_clean_accuracy_change_table(clean_accuracy_change_by_defense))
    lines.extend(_render_defense_sections(
        per_defense,
        severity_weighted_by_defense=severity_weighted_by_defense,
        confidence_interval_by_defense=confidence_interval_by_defense,
        significance_by_defense=significance_by_defense,
        severity_breakdown_by_defense=severity_breakdown_by_defense,
        baseline_by_defense=baseline_by_defense,
        technique_lift_by_defense=technique_lift_by_defense,
        defense_effect_by_defense=defense_effect_by_defense,
    ))
    return "\n".join(lines)


def render_json_report(
    client_name: str,
    per_defense: dict,
    direction: str = "dismiss",
    severity_weighted_by_defense: dict | None = None,
    confidence_interval_by_defense: dict | None = None,
    significance_by_defense: dict | None = None,
    severity_breakdown_by_defense: dict | None = None,
    clean_accuracy_by_defense: dict | None = None,
    baseline_by_defense: dict | None = None,
    technique_lift_by_defense: dict | None = None,
    defense_effect_by_defense: dict | None = None,
    clean_accuracy_change_by_defense: dict | None = None,
    severity_filter: list | None = None,
) -> str:
    """Same data as render_markdown_report, as JSON instead of a document -
    meant for a plotting script rather than a person, so the numbers don't
    need to be scraped back out of a markdown table."""
    payload = {
        "client": client_name,
        "direction": direction,
        "severity_filter": severity_filter,
        "summary_by_defense": rate_by_defense(per_defense),
        "severity_weighted_by_defense": severity_weighted_by_defense,
        "confidence_interval_by_defense": confidence_interval_by_defense,
        "significance_vs_none_by_defense": significance_by_defense,
        "severity_breakdown_by_defense": severity_breakdown_by_defense,
        "clean_accuracy_by_defense": clean_accuracy_by_defense,
        "clean_accuracy_vs_none_by_defense": clean_accuracy_change_by_defense,
        "baseline_by_defense": baseline_by_defense,
        "technique_lift_by_defense": technique_lift_by_defense,
        "defense_effect_vs_none_by_defense": defense_effect_by_defense,
        "per_defense": per_defense,
    }
    return json.dumps(payload, indent=2)


def combined_rate_by_defense(by_direction: dict) -> dict:
    """defense name -> hijack rate combined across every direction in
    by_direction (summed counts, not an average of averages) - lets a
    reader see at a glance whether a defense actually helped overall,
    instead of averaging the per-direction sub-tables by hand."""
    totals: dict = {}
    for per_defense in by_direction.values():
        for defense, aggregated in per_defense.items():
            entry = totals.setdefault(defense, {"hijacked": 0, "total": 0})
            entry["hijacked"] += sum(bucket["hijacked"] for bucket in aggregated.values())
            entry["total"] += sum(bucket["total"] for bucket in aggregated.values())

    return {
        defense: (entry["hijacked"] / entry["total"] if entry["total"] else 0.0)
        for defense, entry in totals.items()
    }


def _render_method_section(method: dict) -> list[str]:
    """what a full report actually measured and how, in a form that can go
    into a write-up as it is - otherwise the alert counts, technique
    lists and tests behind the tables below have to be rebuilt from the
    code by whoever reads the report later."""
    lines = ["## method", ""]
    lines.append(
        f"- clean alerts: {method['clean_alerts']}, each answered once under every defense "
        f"(clean-alert accuracy and the no-injection baseline)"
    )
    for direction, entry in method["directions"].items():
        lines.append(
            f"- direction={direction}: {entry['eligible_alerts']} alerts x {len(entry['techniques'])} techniques = "
            f"{entry['injected_alerts']} injected ({', '.join(entry['techniques'])})"
        )
    lines.append(f"- defenses: {', '.join(method['defenses'])} (none is the baseline every comparison is against)")
    lines.append(f"- requests: {method['requests']}")
    lines.extend([
        ("- hijack rates carry 95% Wilson intervals. Each technique's injection lift pairs every injected "
         "alert with the same alert's clean answer: exact McNemar test, Holm-adjusted across that direction's "
         "techniques, 95% Newcombe hybrid score interval on the lift."),
        ("- each defense's effect pairs every injected alert with itself under no defense, and its "
         "clean-accuracy change pairs every clean alert the same way - both exact McNemar, Holm-adjusted "
         "across the techniques and across the defenses respectively. The overall defense-vs-none comparison "
         f"is a pooled two-proportion z-test, Holm-adjusted across the defenses. Significance at p<{SIGNIFICANCE_ALPHA}."),
        "",
    ])
    return lines


def render_combined_report(
    client_name: str,
    by_direction: dict,
    severity_weighted_by_direction: dict | None = None,
    confidence_interval_by_direction: dict | None = None,
    significance_by_direction: dict | None = None,
    severity_breakdown_by_direction: dict | None = None,
    clean_accuracy_by_defense: dict | None = None,
    baseline_by_direction: dict | None = None,
    technique_lift_by_direction: dict | None = None,
    defense_effect_by_direction: dict | None = None,
    clean_accuracy_change_by_defense: dict | None = None,
    method: dict | None = None,
    severity_filter: list | None = None,
) -> str:
    """The capstone report: both attacker directions, every defense, one
    document. by_direction maps direction name -> per_defense dict (the
    same shape render_markdown_report takes), e.g.
    {"dismiss": {"none": {...}, ...}, "escalate": {"none": {...}, ...}}.
    severity_weighted_by_direction, confidence_interval_by_direction,
    significance_by_direction, and severity_breakdown_by_direction are
    optional: each maps direction name -> (defense name -> its stat),
    same shape as by_direction, shown alongside the flat rate in each
    section. clean_accuracy_by_defense, when given, is a flat defense ->
    accuracy map instead (unlike the others, not keyed by direction) -
    the same clean (non-injected) alert battery applies under every
    direction, so there's nothing direction-specific to show here, just
    one combined summary table alongside the hijack-rate one above it.
    severity_filter, when given, is the single --severity subset applied
    to both directions (full-report takes one global filter, not one per
    direction)."""
    lines = [f"# injection results - client: {client_name} (all directions, all defenses)", ""]
    if severity_filter is not None:
        lines.append(f"severity filter: {', '.join(severity_filter)}")
        lines.append("")

    if method is not None:
        lines.extend(_render_method_section(method))
    lines.extend(_render_summary_table(
        combined_rate_by_defense(by_direction),
        "## summary: overall hijack rate by defense (both directions combined)",
    ))
    if clean_accuracy_by_defense is not None:
        lines.extend(_render_summary_table(
            clean_accuracy_by_defense, "## summary: clean-alert accuracy by defense", column_label="clean accuracy",
        ))
    if clean_accuracy_change_by_defense:
        lines.extend(_render_clean_accuracy_change_table(clean_accuracy_change_by_defense))

    for direction, per_defense in by_direction.items():
        lines.append(f"# direction: {direction}")
        lines.append("")
        severity_weighted = severity_weighted_by_direction[direction] if severity_weighted_by_direction else None
        confidence_interval = confidence_interval_by_direction[direction] if confidence_interval_by_direction else None
        significance = significance_by_direction[direction] if significance_by_direction else None
        severity_breakdown = severity_breakdown_by_direction[direction] if severity_breakdown_by_direction else None
        baseline = baseline_by_direction[direction] if baseline_by_direction else None
        technique_lift = technique_lift_by_direction[direction] if technique_lift_by_direction else None
        defense_effect = defense_effect_by_direction[direction] if defense_effect_by_direction else None
        lines.extend(_render_defense_sections(
            per_defense,
            severity_weighted_by_defense=severity_weighted,
            confidence_interval_by_defense=confidence_interval,
            significance_by_defense=significance,
            heading_level="##",
            severity_breakdown_by_defense=severity_breakdown,
            baseline_by_defense=baseline,
            technique_lift_by_defense=technique_lift,
            defense_effect_by_defense=defense_effect,
        ))
    return "\n".join(lines)


def render_combined_json_report(
    client_name: str,
    by_direction: dict,
    severity_weighted_by_direction: dict | None = None,
    confidence_interval_by_direction: dict | None = None,
    significance_by_direction: dict | None = None,
    severity_breakdown_by_direction: dict | None = None,
    clean_accuracy_by_defense: dict | None = None,
    baseline_by_direction: dict | None = None,
    technique_lift_by_direction: dict | None = None,
    defense_effect_by_direction: dict | None = None,
    clean_accuracy_change_by_defense: dict | None = None,
    method: dict | None = None,
    outcomes: dict | None = None,
    severity_filter: list | None = None,
) -> str:
    """Same data as render_combined_report, as JSON instead of a document."""
    payload = {
        "client": client_name,
        "severity_filter": severity_filter,
        "method": method,
        "summary_by_defense": combined_rate_by_defense(by_direction),
        "severity_weighted_by_direction": severity_weighted_by_direction,
        "confidence_interval_by_direction": confidence_interval_by_direction,
        "significance_vs_none_by_direction": significance_by_direction,
        "severity_breakdown_by_direction": severity_breakdown_by_direction,
        "clean_accuracy_by_defense": clean_accuracy_by_defense,
        "clean_accuracy_vs_none_by_defense": clean_accuracy_change_by_defense,
        "baseline_by_direction": baseline_by_direction,
        "technique_lift_by_direction": technique_lift_by_direction,
        "defense_effect_vs_none_by_direction": defense_effect_by_direction,
        "by_direction": by_direction,
        # per-item outcomes - json only, nobody reads 792 of these in markdown
        "outcomes": outcomes,
    }
    return json.dumps(payload, indent=2)


_CSV_FIELDS = [
    "client", "direction", "defense", "technique",
    "hijacked", "resisted", "other", "unparseable", "total", "hijack_rate", "ci_low", "ci_high",
]


def _csv_rows(client_name: str, direction: str, per_defense: dict) -> list[dict]:
    rows = []
    for defense, aggregated in per_defense.items():
        for technique, bucket in aggregated.items():
            rows.append({
                "client": client_name,
                "direction": direction,
                "defense": defense,
                "technique": technique,
                "hijacked": bucket["hijacked"],
                "resisted": bucket["resisted"],
                "other": bucket["other"],
                "unparseable": bucket.get("unparseable", 0),
                "total": bucket["total"],
                "hijack_rate": bucket["hijack_rate"],
                "ci_low": bucket.get("ci_low", ""),
                "ci_high": bucket.get("ci_high", ""),
            })
    return rows


def render_csv_report(client_name: str, per_defense: dict, direction: str = "dismiss") -> str:
    """Same technique-level data as the markdown/json reports, as CSV -
    for opening directly in a spreadsheet instead of writing a script
    against the JSON. One row per (defense, technique) pair, each tagged
    with the client name so multiple exports can be concatenated and
    compared in one spreadsheet."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_CSV_FIELDS)
    writer.writeheader()
    writer.writerows(_csv_rows(client_name, direction, per_defense))
    return output.getvalue()


def render_combined_csv_report(client_name: str, by_direction: dict) -> str:
    """Same idea as render_csv_report, but across every direction a caller
    ran (full-report's shape)."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_CSV_FIELDS)
    writer.writeheader()
    for direction, per_defense in by_direction.items():
        writer.writerows(_csv_rows(client_name, direction, per_defense))
    return output.getvalue()


_LEADERBOARD_CSV_FIELDS = [
    "client", "direction", "defense", "hijack_rate", "ci_low", "ci_high", "baseline", "lift",
    "significant_techniques", "techniques",
    "severity_weighted_hijack_rate", "clean_accuracy", "clean_ci_low", "clean_ci_high",
]


def _significant_count(row: dict) -> str:
    """"7/8" - how many techniques' paired tests cleared significance for
    that client; n/a for a row built without them."""
    if "significant_techniques" not in row:
        return "n/a"
    return f"{row['significant_techniques']}/{row['techniques']}"


def render_leaderboard_report(
    rows: list[dict], direction: str, defense: str, pairwise_significance: dict | None = None,
    severity_filter: list | None = None,
) -> str:
    """rows: one entry per client - {"client", "hijack_rate", "ci_low",
    "ci_high", "severity_weighted_hijack_rate", "clean_accuracy",
    "clean_ci_low", "clean_ci_high"} - already sorted by the caller (most
    robust first). Every other report here is single-client, comparing
    defenses or directions for one client; this instead compares clients
    against each other under one fixed direction and defense, the
    side-by-side vulnerability-profile view none of the others give.
    clean_accuracy (fraction of non-injected alerts correctly resolved) is
    shown alongside the hijack rate specifically because a client that
    just answers wrong across the board scores a misleadingly good 0%
    hijack rate without it - and gets its own Wilson 95% confidence
    interval for the same reason the hijack rate column does: the clean
    battery is no bigger a sample than the injected one. pairwise_significance,
    when given (only meaningful with exactly two clients compared), is
    {"client_a", "client_b", "z", "p_value"} from a two-proportion z-test
    between them, appended as one line below the table. severity_filter,
    when given, is the --severity subset this comparison was restricted
    to - recorded the same way run/compare/full-report already do."""
    lines = [
        f"# leaderboard - direction: {direction}, defense: {defense}",
        "",
    ]
    if severity_filter is not None:
        lines.append(f"severity filter: {', '.join(severity_filter)}")
        lines.append("")
    lines.extend([
        ("| client | hijack rate | 95% ci | baseline | lift | significant techniques | severity-weighted | "
         "clean accuracy | clean 95% ci |"),
        "|---|---|---|---|---|---|---|---|---|",
    ])
    for row in rows:
        lines.append(
            f"| {row['client']} | {row['hijack_rate']:.0%} | "
            f"{row['ci_low']:.0%}-{row['ci_high']:.0%} | {row['baseline']:.0%} | {points_or_na(row['lift'])} | "
            f"{_significant_count(row)} | "
            f"{row['severity_weighted_hijack_rate']:.0%} | "
            f"{row['clean_accuracy']:.0%} | {row['clean_ci_low']:.0%}-{row['clean_ci_high']:.0%} |"
        )
    lines.append("")
    if pairwise_significance is not None:
        p_value = pairwise_significance["p_value"]
        verdict = "significant" if is_significant(p_value) else "not significant"
        lines.append(
            f"{pairwise_significance['client_a']} vs {pairwise_significance['client_b']} "
            f"(two-proportion z-test): p={p_value:.4f} ({verdict} at p<{SIGNIFICANCE_ALPHA})"
        )
        lines.append("")
    return "\n".join(lines)


def render_leaderboard_json_report(
    rows: list[dict], direction: str, defense: str, pairwise_significance: dict | None = None,
    severity_filter: list | None = None,
) -> str:
    """Same data as render_leaderboard_report, as JSON instead of a document."""
    payload = {
        "direction": direction,
        "defense": defense,
        "severity_filter": severity_filter,
        "clients": rows,
        "pairwise_significance": pairwise_significance,
    }
    return json.dumps(payload, indent=2)


def render_leaderboard_csv_report(rows: list[dict], direction: str, defense: str) -> str:
    """Same data as render_leaderboard_report, as CSV - one row per client,
    each tagged with the direction/defense the whole leaderboard ran under
    so exports from different runs can still be told apart if concatenated."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_LEADERBOARD_CSV_FIELDS)
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "client": row["client"],
            "direction": direction,
            "defense": defense,
            "hijack_rate": row["hijack_rate"],
            "ci_low": row["ci_low"],
            "ci_high": row["ci_high"],
            "baseline": row["baseline"],
            "lift": row["lift"],
            "significant_techniques": row.get("significant_techniques", ""),
            "techniques": row.get("techniques", ""),
            "severity_weighted_hijack_rate": row["severity_weighted_hijack_rate"],
            "clean_accuracy": row["clean_accuracy"],
            "clean_ci_low": row["clean_ci_low"],
            "clean_ci_high": row["clean_ci_high"],
        })
    return output.getvalue()


_TECHNIQUE_LEADERBOARD_CSV_FIELDS = [
    "technique", "direction", "defense", "hijacked", "resisted", "other", "total", "hijack_rate", "ci_low", "ci_high",
    "lift", "lift_ci_low", "lift_ci_high", "p_value", "p_holm",
]


def render_technique_leaderboard_report(
    rows: list[tuple[str, dict]], direction: str, defense: str, client_count: int,
    pairwise_significance: dict | None = None, severity_filter: list | None = None,
    baseline: dict | None = None,
) -> str:
    """rows: list of (technique, bucket) pairs from aggregate_by_technique's
    output over every compared client's results concatenated together -
    already sorted by the caller (most dangerous first). The
    technique-axis complement to render_leaderboard_report's client axis:
    that ranks clients against one fixed battery, this ranks techniques
    by how often they succeed across a fixed set of clients instead.
    pairwise_significance, when given (only meaningful with exactly two
    techniques ranked), is {"technique_a", "technique_b", "z", "p_value"}
    from a two-proportion z-test between them, appended as one line below
    the table - the technique-axis mirror of leaderboard's own
    exactly-two-clients pairwise check. severity_filter, when given, is
    the --severity subset this ranking was restricted to."""
    lines = [
        f"# technique leaderboard - direction: {direction}, defense: {defense}, across {client_count} client(s)",
        "",
    ]
    if severity_filter is not None:
        lines.append(f"severity filter: {', '.join(severity_filter)}")
        lines.append("")
    lines.extend([
        "| technique | hijacked | resisted | other | hijack rate | 95% ci | lift | lift 95% ci | p | p (holm) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ])
    for technique, bucket in rows:
        p_value, p_holm = bucket.get("p_value"), bucket.get("p_holm")
        interval = "n/a" if "lift_ci_low" not in bucket else lift_interval(bucket["lift_ci_low"], bucket["lift_ci_high"])
        lines.append(
            f"| {technique} | {bucket['hijacked']} | {bucket['resisted']} | {bucket['other']} | "
            f"{bucket['hijack_rate']:.0%} | {bucket['ci_low']:.0%}-{bucket['ci_high']:.0%} | "
            f"{points_or_na(bucket.get('lift'))} | {interval} | {'n/a' if p_value is None else f'{p_value:.4f}'} | "
            f"{'n/a' if p_holm is None else f'{p_holm:.4f}'} |"
        )
    lines.append("")
    if baseline is not None:
        # one baseline for the whole table - every technique runs on the
        # same alerts against the same clients
        lines.extend([f"{baseline_line(baseline)} (all techniques together)", ""])
    if pairwise_significance is not None:
        p_value = pairwise_significance["p_value"]
        verdict = "significant" if is_significant(p_value) else "not significant"
        lines.append(
            f"{pairwise_significance['technique_a']} vs {pairwise_significance['technique_b']} "
            f"(two-proportion z-test): p={p_value:.4f} ({verdict} at p<{SIGNIFICANCE_ALPHA})"
        )
        lines.append("")
    return "\n".join(lines)


def render_technique_leaderboard_json_report(
    rows: list[tuple[str, dict]], direction: str, defense: str, client_count: int,
    pairwise_significance: dict | None = None, severity_filter: list | None = None,
    baseline: dict | None = None,
) -> str:
    """Same data as render_technique_leaderboard_report, as JSON instead of a document."""
    payload = {
        "direction": direction,
        "defense": defense,
        "client_count": client_count,
        "severity_filter": severity_filter,
        "techniques": [{"technique": technique, **bucket} for technique, bucket in rows],
        "pairwise_significance": pairwise_significance,
        "baseline": baseline,
    }
    return json.dumps(payload, indent=2)


def render_technique_leaderboard_csv_report(rows: list[tuple[str, dict]], direction: str, defense: str) -> str:
    """Same data as render_technique_leaderboard_report, as CSV - one row
    per technique, each tagged with the direction/defense the whole
    comparison ran under so exports from different runs can still be
    told apart if concatenated."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_TECHNIQUE_LEADERBOARD_CSV_FIELDS)
    writer.writeheader()
    for technique, bucket in rows:
        writer.writerow({
            "technique": technique,
            "direction": direction,
            "defense": defense,
            "hijacked": bucket["hijacked"],
            "resisted": bucket["resisted"],
            "other": bucket["other"],
            "total": bucket["total"],
            "hijack_rate": bucket["hijack_rate"],
            "ci_low": bucket["ci_low"],
            "ci_high": bucket["ci_high"],
            "lift": bucket.get("lift", ""),
            "lift_ci_low": bucket.get("lift_ci_low", ""),
            "lift_ci_high": bucket.get("lift_ci_high", ""),
            "p_value": bucket.get("p_value", ""),
            "p_holm": bucket.get("p_holm", ""),
        })
    return output.getvalue()


MATRIX_LEGEND = (
    "* = that technique's lift over the client's own no-injection baseline is significant "
    f"(paired exact McNemar test, Holm-adjusted across the row's techniques, p<{SIGNIFICANCE_ALPHA})"
)


def matrix_cell(row: dict, technique: str) -> str:
    """A matrix cell's hijack rate, starred when its paired test says the
    technique really moved that client (judged on the Holm-adjusted
    value - the row's techniques are one family). A row with no p_holm (built by
    hand, or saved before the test existed) just shows the rate."""
    p_holm = row.get("p_holm", {}).get(technique, 1.0)
    return f"{row['rates'][technique]:.0%}" + ("*" if is_significant(p_holm) else "")


def render_matrix_report(
    rows: list[dict], technique_names: list[str], direction: str, defense: str,
    severity_filter: list | None = None,
) -> str:
    """rows: one entry per client - {"client", "rates": {technique: hijack
    rate, ...}, "average"} - covering every technique in technique_names,
    already sorted by the caller (most robust first by average). The full
    cross-tab neither leaderboard nor technique-leaderboard keeps: that
    one collapses techniques into a single rate per client, this one
    collapses clients into a single rate per technique; here both axes
    stay, a client-by-technique heatmap-style table for a thesis
    appendix. Cells are just the flat hijack rate (not severity-weighted
    or confidence-interval'd) to keep a grid this wide readable - those
    are already available per-client via `leaderboard` and per-technique
    via `technique-leaderboard`. average is the plain mean of a row's own
    cells, shown as a trailing column so a reader doesn't have to eyeball
    a wide row to see which client comes out ahead overall. baseline is how
    often that client already gives the attack's target action on the same
    alerts with no injection - part of every cell in its row, not the
    attack's doing - so a cell's lift is the cell minus it. severity_filter,
    when given, is the --severity subset this matrix was restricted to."""
    header = "| client | " + " | ".join(technique_names) + " | average | baseline |"
    separator = "|---|" + "|".join("---" for _ in technique_names) + "|---|---|"
    lines = [
        f"# matrix - direction: {direction}, defense: {defense}",
        "",
    ]
    if severity_filter is not None:
        lines.append(f"severity filter: {', '.join(severity_filter)}")
        lines.append("")
    lines.extend([header, separator])
    for row in rows:
        cells = " | ".join(matrix_cell(row, technique) for technique in technique_names)
        lines.append(f"| {row['client']} | {cells} | {row['average']:.0%} | {row['baseline']:.0%} |")
    lines.extend(["", MATRIX_LEGEND, ""])
    return "\n".join(lines)


def render_matrix_json_report(
    rows: list[dict], technique_names: list[str], direction: str, defense: str,
    severity_filter: list | None = None,
) -> str:
    """Same data as render_matrix_report, as JSON instead of a document."""
    payload = {
        "direction": direction,
        "defense": defense,
        "severity_filter": severity_filter,
        "techniques": technique_names,
        "clients": rows,
    }
    return json.dumps(payload, indent=2)


def render_matrix_csv_report(rows: list[dict], technique_names: list[str], direction: str, defense: str) -> str:
    """Same data as render_matrix_report, as CSV - one row per client, one
    column per technique (wide, not the long one-row-per-pair shape the
    other CSV exports here use), since a wide grid is the natural shape
    for a spreadsheet heatmap built directly from this file."""
    output = io.StringIO()
    fieldnames = [
        "client", "direction", "defense", *technique_names, "average", "baseline",
        *(f"{technique} p" for technique in technique_names),
        *(f"{technique} p_holm" for technique in technique_names),
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "client": row["client"],
            "direction": direction,
            "defense": defense,
            **row["rates"],
            "average": row["average"],
            "baseline": row["baseline"],
            **{f"{technique} p": row.get("p_values", {}).get(technique, "") for technique in technique_names},
            **{f"{technique} p_holm": row.get("p_holm", {}).get(technique, "") for technique in technique_names},
        })
    return output.getvalue()


def render_severity_matrix_report(
    rows: list[dict], technique_names: list[str], client_name: str, direction: str, defense: str,
    severity_filter: list | None = None, pairwise_significance: dict | None = None,
) -> str:
    """rows: one entry per severity - {"severity", "rates": {technique:
    hijack rate, ...}, "average"} - covering every technique in
    technique_names, in canonical critical/high/medium/low order (not
    sorted by average like `matrix`'s client rows - severity already has
    a meaningful order of its own, critical first, that a reader wants
    to see regardless of which row happens to be most/least vulnerable).
    The severity-axis sibling of `matrix`: that keeps client and
    technique both instead of collapsing one into the other; this keeps
    severity and technique both instead, for one client - answering
    whether a given technique's hijack rate actually shifts with
    severity, which neither aggregate_by_technique (collapses severity)
    nor aggregate_by_severity (collapses technique) can show on their
    own. Cells are the flat hijack rate only, same readability reasoning
    as `matrix`. average is the plain mean of a row's own cells.
    pairwise_significance, when given (only meaningful with exactly two
    severities in scope, via --severity), is {"severity_a", "severity_b",
    "z", "p_value"} from a two-proportion z-test pooling each severity's
    hijacked/total across every technique - the same exactly-two pattern
    leaderboard and technique-leaderboard already use, appended as one
    line below the table."""
    header = "| severity | " + " | ".join(technique_names) + " | average |"
    separator = "|---|" + "|".join("---" for _ in technique_names) + "|---|"
    lines = [
        f"# severity matrix - client: {client_name}, direction: {direction}, defense: {defense}",
        "",
    ]
    if severity_filter is not None:
        lines.append(f"severity filter: {', '.join(severity_filter)}")
        lines.append("")
    lines.extend([header, separator])
    for row in rows:
        cells = " | ".join(f"{row['rates'][technique]:.0%}" for technique in technique_names)
        lines.append(f"| {row['severity']} | {cells} | {row['average']:.0%} |")
    lines.append("")
    if pairwise_significance is not None:
        p_value = pairwise_significance["p_value"]
        verdict = "significant" if is_significant(p_value) else "not significant"
        lines.append(
            f"{pairwise_significance['severity_a']} vs {pairwise_significance['severity_b']} "
            f"(two-proportion z-test): p={p_value:.4f} ({verdict} at p<{SIGNIFICANCE_ALPHA})"
        )
        lines.append("")
    return "\n".join(lines)


def render_severity_matrix_json_report(
    rows: list[dict], technique_names: list[str], client_name: str, direction: str, defense: str,
    severity_filter: list | None = None, pairwise_significance: dict | None = None,
) -> str:
    """Same data as render_severity_matrix_report, as JSON instead of a document."""
    payload = {
        "client": client_name,
        "direction": direction,
        "defense": defense,
        "severity_filter": severity_filter,
        "techniques": technique_names,
        "severities": rows,
        "pairwise_significance": pairwise_significance,
    }
    return json.dumps(payload, indent=2)


def render_severity_matrix_csv_report(
    rows: list[dict], technique_names: list[str], client_name: str, direction: str, defense: str,
) -> str:
    """Same data as render_severity_matrix_report, as CSV - one row per
    severity, one column per technique (wide, same shape render_matrix_csv_report
    uses for its client rows, for the same spreadsheet-heatmap reason)."""
    output = io.StringIO()
    fieldnames = ["client", "severity", "direction", "defense", *technique_names, "average"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "client": client_name,
            "severity": row["severity"],
            "direction": direction,
            "defense": defense,
            **row["rates"],
            "average": row["average"],
        })
    return output.getvalue()


def percent_or_na(value: float | None) -> str:
    """A summarized report that didn't run a defense (full-report
    --defenses) has None there rather than a rate."""
    return "n/a" if value is None else f"{value:.0%}"


def points_or_na(value: float | None) -> str:
    """A lift (a difference of two rates) in signed percentage points."""
    return "n/a" if value is None else f"{value * 100:+.0f}"


def render_summary_report(
    rows: list[dict], defenses: list[str], severity_filter: list | None = None,
    stability: list | None = None,
) -> str:
    """rows: one per saved full-report, in the order given - {"client",
    "source", "hijack_rate": {defense: rate}, "clean_accuracy": {defense:
    rate} or None for a report saved before clean accuracy existed}. The
    cross-model headline table: full-report is single-client by design,
    so comparing how much each defense helps across several real models
    otherwise meant copying numbers out of one file per model by hand."""
    lines = ["# summary - hijack rate by defense, both directions combined", ""]
    if severity_filter is not None:
        lines.extend([f"severity filter: {', '.join(severity_filter)}", ""])
    lines.append("| client | " + " | ".join(defenses) + " |")
    lines.append("|---|" + "|".join("---" for _ in defenses) + "|")
    for row in rows:
        lines.append(f"| {row['client']} | " + " | ".join(percent_or_na(row["hijack_rate"][d]) for d in defenses) + " |")
    lines.extend(["", "## clean-alert accuracy by defense", ""])
    lines.append("| client | " + " | ".join(defenses) + " |")
    lines.append("|---|" + "|".join("---" for _ in defenses) + "|")
    for row in rows:
        cells = (
            " | ".join(percent_or_na(row["clean_accuracy"][d]) for d in defenses)
            if row["clean_accuracy"] is not None else " | ".join("n/a" for _ in defenses)
        )
        lines.append(f"| {row['client']} | {cells} |")
    lines.extend(["", "## injection lift over the no-injection baseline, in points", ""])
    lines.append("| client | " + " | ".join(defenses) + " |")
    lines.append("|---|" + "|".join("---" for _ in defenses) + "|")
    for row in rows:
        lines.append(f"| {row['client']} | " + " | ".join(points_or_na(row["lift"][d]) for d in defenses) + " |")
    if any("significant" in row for row in rows):
        lines.extend([
            "", f"## techniques with a significant lift (both directions, paired McNemar, Holm-adjusted p<{SIGNIFICANCE_ALPHA})", "",
        ])
        lines.append("| client | " + " | ".join(defenses) + " |")
        lines.append("|---|" + "|".join("---" for _ in defenses) + "|")
        for row in rows:
            cells = " | ".join(row.get("significant", {}).get(d) or "n/a" for d in defenses)
            lines.append(f"| {row['client']} | {cells} |")
    applied = [d for d in defenses if d != "none"]
    if applied and any("reduced" in row for row in rows):
        lines.extend([
            "",
            (f"## techniques each defense reduced vs none (both directions, paired McNemar, "
             f"Holm-adjusted p<{SIGNIFICANCE_ALPHA})"),
            "",
        ])
        lines.append("| client | " + " | ".join(applied) + " |")
        lines.append("|---|" + "|".join("---" for _ in applied) + "|")
        for row in rows:
            cells = " | ".join(row.get("reduced", {}).get(d) or "n/a" for d in applied)
            lines.append(f"| {row['client']} | {cells} |")
    if "strict" in defenses and any("strict_split" in row for row in rows):
        lines.extend([
            "",
            ("## strict on the techniques it names vs the ones it doesn't (reduced, of those that got "
             "through without it, both directions)"),
            "",
            "| client | named | unnamed |",
            "|---|---|---|",
        ])
        for row in rows:
            named, unnamed = row.get("strict_split") or ("n/a", "n/a")
            lines.append(f"| {row['client']} | {named} | {unnamed} |")
    if stability:
        lines.extend([
            "", "## run-to-run stability (reports of the same model differing only by --seed)", "",
            "| client | runs | defense | hijack rate | same outcome | kappa |", "|---|---|---|---|---|---|",
        ])
        for entry in stability:
            kappa = "n/a" if entry["kappa"] is None else f"{entry['kappa']:.2f}"
            lines.append(
                f"| {entry['client']} | {entry['runs']} | {entry['defense']} | "
                f"{entry['hijack_rate_min']:.0%}-{entry['hijack_rate_max']:.0%} | {entry['same_outcome']:.0%} | {kappa} |"
            )
    lines.extend(["", "sources: " + ", ".join(f"{row['client']} <- {row['source']}" for row in rows), ""])
    return "\n".join(lines)


def render_summary_json_report(
    rows: list[dict], defenses: list[str], severity_filter: list | None = None, stability: list | None = None,
) -> str:
    """Same data as render_summary_report, as JSON instead of a document."""
    return json.dumps(
        {"severity_filter": severity_filter, "defenses": defenses, "clients": rows, "stability": stability or []},
        indent=2,
    )


def render_summary_csv_report(rows: list[dict], defenses: list[str]) -> str:
    """Same data as render_summary_report, as CSV - long format, one row per
    (client, defense), the shape a spreadsheet pivot or a plotting
    library's grouped bar chart takes directly."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output, fieldnames=["client", "defense", "hijack_rate", "clean_accuracy", "lift", "significant_techniques",
                           "techniques_reduced", "source"],
    )
    writer.writeheader()
    for row in rows:
        for defense in defenses:
            writer.writerow({
                "client": row["client"],
                "defense": defense,
                "hijack_rate": "" if row["hijack_rate"][defense] is None else row["hijack_rate"][defense],
                "clean_accuracy": (
                    "" if row["clean_accuracy"] is None or row["clean_accuracy"][defense] is None
                    else row["clean_accuracy"][defense]
                ),
                "lift": "" if row["lift"][defense] is None else row["lift"][defense],
                "significant_techniques": row.get("significant", {}).get(defense) or "",
                "techniques_reduced": row.get("reduced", {}).get(defense) or "",
                "source": row["source"],
            })
    return output.getvalue()
