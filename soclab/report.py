"""Renders scoring results as a markdown table, so a run's numbers can be
dropped straight into a writeup instead of copied out of terminal output."""


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

        total_hijacked = sum(bucket["hijacked"] for bucket in aggregated.values())
        total_count = sum(bucket["total"] for bucket in aggregated.values())
        overall = total_hijacked / total_count if total_count else 0.0
        lines.append("")
        lines.append(f"overall hijack rate: {overall:.0%}")
        lines.append("")
    return lines


def render_markdown_report(client_name: str, per_defense: dict, direction: str = "dismiss") -> str:
    """per_defense maps defense name -> aggregate_by_technique() output for
    that defense. direction says which attacker goal these results are
    for - a report with no direction noted is ambiguous once both exist,
    since technique names alone don't say which one they belong to at a
    glance."""
    lines = [f"# injection results - client: {client_name}, direction: {direction}", ""]
    lines.extend(_render_defense_sections(per_defense))
    return "\n".join(lines)


def render_combined_report(client_name: str, by_direction: dict) -> str:
    """The capstone report: both attacker directions, every defense, one
    document. by_direction maps direction name -> per_defense dict (the
    same shape render_markdown_report takes), e.g.
    {"dismiss": {"none": {...}, ...}, "escalate": {"none": {...}, ...}}."""
    lines = [f"# injection results - client: {client_name} (all directions, all defenses)", ""]
    for direction, per_defense in by_direction.items():
        lines.append(f"# direction: {direction}")
        lines.append("")
        lines.extend(_render_defense_sections(per_defense, heading_level="##"))
    return "\n".join(lines)
