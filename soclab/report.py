"""Renders scoring results as a markdown table, so a run's numbers can be
dropped straight into a writeup instead of copied out of terminal output."""


def render_markdown_report(client_name: str, per_defense: dict, direction: str = "dismiss") -> str:
    """per_defense maps defense name -> aggregate_by_technique() output for
    that defense, e.g. {"none": {...}, "sandwich": {...}}. direction says
    which attacker goal these results are for - a report with no direction
    noted is ambiguous once both exist, since technique names alone don't
    say which one they belong to at a glance."""
    lines = [f"# injection results - client: {client_name}, direction: {direction}", ""]

    for defense, aggregated in per_defense.items():
        lines.append(f"## defense: {defense}")
        lines.append("")
        lines.append("| technique | hijacked | resisted | other | hijack rate |")
        lines.append("|---|---|---|---|---|")
        for technique, bucket in aggregated.items():
            lines.append(
                f"| {technique} | {bucket['hijacked']} | {bucket['resisted']} | "
                f"{bucket['other']} | {bucket['hijack_rate']:.0%} |"
            )

        total_hijacked = sum(bucket["hijacked"] for bucket in aggregated.values())
        total_count = sum(bucket["total"] for bucket in aggregated.values())
        overall = total_hijacked / total_count if total_count else 0.0
        lines.append("")
        lines.append(f"overall hijack rate: {overall:.0%}")
        lines.append("")

    return "\n".join(lines)
