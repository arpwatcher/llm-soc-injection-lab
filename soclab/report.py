"""Renders scoring results as a markdown table, so a run's numbers can be
dropped straight into a writeup instead of copied out of terminal output."""


def render_markdown_report(client_name: str, per_defense: dict) -> str:
    """per_defense maps defense name -> aggregate_by_technique() output for
    that defense, e.g. {"none": {...}, "sandwich": {...}}."""
    lines = [f"# injection results - client: {client_name}", ""]

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
