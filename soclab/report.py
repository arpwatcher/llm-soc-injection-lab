"""Renders scoring results as a markdown table, so a run's numbers can be
dropped straight into a writeup instead of copied out of terminal output."""


def _overall_rate(aggregated: dict) -> float:
    total_hijacked = sum(bucket["hijacked"] for bucket in aggregated.values())
    total_count = sum(bucket["total"] for bucket in aggregated.values())
    return total_hijacked / total_count if total_count else 0.0


def _rate_by_defense(per_defense: dict) -> dict:
    """defense name -> overall hijack rate for that defense, from a single
    per_defense dict (one direction's worth of results)."""
    return {defense: _overall_rate(aggregated) for defense, aggregated in per_defense.items()}


def _render_summary_table(rates: dict, heading: str) -> list[str]:
    """Shared by both report functions: a small defense -> hijack rate
    table, so the overall pattern is visible without reading every
    per-technique sub-table by hand."""
    lines = [heading, "", "| defense | hijack rate |", "|---|---|"]
    for defense, rate in rates.items():
        lines.append(f"| {defense} | {rate:.0%} |")
    lines.append("")
    return lines


def _render_defense_sections(per_defense: dict, heading_level: str = "##") -> list[str]:
    """per_defense maps defense name -> aggregate_by_technique() output for
    that defense, e.g. {"none": {...}, "sandwich": {...}}. Shared by both
    render_markdown_report and render_combined_report so the two don't
    duplicate the table-building logic."""
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
        lines.append(f"overall hijack rate: {_overall_rate(aggregated):.0%}")
        lines.append("")
    return lines


def render_markdown_report(client_name: str, per_defense: dict, direction: str = "dismiss") -> str:
    """per_defense maps defense name -> aggregate_by_technique() output for
    that defense. direction says which attacker goal these results are
    for - a report with no direction noted is ambiguous once both exist,
    since technique names alone don't say which one they belong to at a
    glance."""
    lines = [f"# injection results - client: {client_name}, direction: {direction}", ""]
    if len(per_defense) > 1:
        lines.extend(_render_summary_table(_rate_by_defense(per_defense), "## summary: overall hijack rate by defense"))
    lines.extend(_render_defense_sections(per_defense))
    return "\n".join(lines)


def _combined_rate_by_defense(by_direction: dict) -> dict:
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


def render_combined_report(client_name: str, by_direction: dict) -> str:
    """The capstone report: both attacker directions, every defense, one
    document. by_direction maps direction name -> per_defense dict (the
    same shape render_markdown_report takes), e.g.
    {"dismiss": {"none": {...}, ...}, "escalate": {"none": {...}, ...}}."""
    lines = [f"# injection results - client: {client_name} (all directions, all defenses)", ""]

    lines.extend(_render_summary_table(
        _combined_rate_by_defense(by_direction),
        "## summary: overall hijack rate by defense (both directions combined)",
    ))

    for direction, per_defense in by_direction.items():
        lines.append(f"# direction: {direction}")
        lines.append("")
        lines.extend(_render_defense_sections(per_defense, heading_level="##"))
    return "\n".join(lines)
