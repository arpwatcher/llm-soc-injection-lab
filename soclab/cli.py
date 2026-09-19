"""Entry point: run the injection battery against a client and print a
per-technique report, or list the available techniques."""

import argparse
import sys

from soclab.alerts import generate_clean_alerts
from soclab.analyst import DEFENSES, DEFENSE_NONE
from soclab.injections import (
    ESCALATION_TECHNIQUES,
    TECHNIQUES,
    apply_all_escalation_techniques,
    apply_all_techniques,
)
from soclab.llm_client import (
    EscalationSandwichSensitiveFakeClient,
    EscalationStrictPromptSensitiveFakeClient,
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
    render_combined_report,
    render_markdown_report,
)
from soclab.scoring import aggregate_by_technique, overall_hijack_rate, score_batch

CLIENT_FACTORIES = {
    "fake-robust": lambda args: RobustFakeClient(),
    "fake-vulnerable": lambda args: VulnerableFakeClient(),
    "fake-semantic-vulnerable": lambda args: SemanticVulnerableFakeClient(),
    "fake-sandwich-sensitive": lambda args: SandwichSensitiveFakeClient(),
    "fake-strict-sensitive": lambda args: StrictPromptSensitiveFakeClient(),
    "fake-stubborn": lambda args: StubbornFakeClient(),
    "fake-escalation-vulnerable": lambda args: EscalationVulnerableFakeClient(),
    "fake-escalation-sandwich-sensitive": lambda args: EscalationSandwichSensitiveFakeClient(),
    "fake-escalation-strict-sensitive": lambda args: EscalationStrictPromptSensitiveFakeClient(),
    "ollama": lambda args: OllamaClient(model=args.model, host=args.host),
}

DIRECTIONS = ("dismiss", "escalate")


def build_client(args):
    if args.client == "ollama" and not args.model:
        raise ValueError("--model is required when --client ollama")
    return CLIENT_FACTORIES[args.client](args)


def _print_report(aggregated, results):
    print(f"{'technique':<24} {'hijacked':>8} {'resisted':>8} {'other':>6} {'hijack_rate':>12}")
    for technique, bucket in aggregated.items():
        print(f"{technique:<24} {bucket['hijacked']:>8} {bucket['resisted']:>8} {bucket['other']:>6} "
              f"{bucket['hijack_rate']:>11.0%}")
    print(f"\noverall hijack rate: {overall_hijack_rate(results):.0%}")


def _print_summary(rates: dict, heading: str):
    print(heading)
    print(f"{'defense':<10} {'hijack_rate':>12}")
    for defense, rate in rates.items():
        print(f"{defense:<10} {rate:>11.0%}")
    print()


def _injected_alerts_for(direction: str) -> list:
    clean_alerts = generate_clean_alerts()
    if direction == "escalate":
        return apply_all_escalation_techniques(clean_alerts)
    return apply_all_techniques(clean_alerts)


def cmd_run(args):
    client = build_client(args)

    clean_alerts = generate_clean_alerts()
    injected_alerts = _injected_alerts_for(args.direction)

    clean_results = score_batch(clean_alerts, client, defense=args.defense)
    clean_correct = sum(1 for r in clean_results if r.outcome == "resisted")
    print(f"clean alerts: {clean_correct}/{len(clean_results)} correct action (defense={args.defense})\n")

    injected_results = score_batch(injected_alerts, client, defense=args.defense)
    print(f"direction={args.direction}")
    aggregated = aggregate_by_technique(injected_results)
    _print_report(aggregated, injected_results)

    if args.report:
        with open(args.report, "w") as f:
            f.write(render_markdown_report(args.client, {args.defense: aggregated}, direction=args.direction))
        print(f"\nwrote report to {args.report}")


def cmd_compare(args):
    client = build_client(args)
    injected_alerts = _injected_alerts_for(args.direction)

    print(f"direction={args.direction}\n")
    per_defense = {}
    for defense in DEFENSES:
        print(f"--- defense={defense} ---")
        results = score_batch(injected_alerts, client, defense=defense)
        aggregated = aggregate_by_technique(results)
        _print_report(aggregated, results)
        per_defense[defense] = aggregated
        print()

    _print_summary(rate_by_defense(per_defense), "summary: overall hijack rate by defense")

    if args.report:
        with open(args.report, "w") as f:
            f.write(render_markdown_report(args.client, per_defense, direction=args.direction))
        print(f"wrote report to {args.report}")


def cmd_full_report(args):
    """The capstone run: every direction, every defense, one client - the
    complete picture in a single invocation, written as one combined
    markdown file. This is what an actual thesis experiment run looks
    like once a real model is reachable."""
    client = build_client(args)

    by_direction = {}
    for direction in DIRECTIONS:
        injected_alerts = _injected_alerts_for(direction)
        per_defense = {}
        for defense in DEFENSES:
            print(f"--- direction={direction} defense={defense} ---")
            results = score_batch(injected_alerts, client, defense=defense)
            aggregated = aggregate_by_technique(results)
            _print_report(aggregated, results)
            per_defense[defense] = aggregated
            print()
        by_direction[direction] = per_defense

    _print_summary(
        combined_rate_by_defense(by_direction),
        "summary: overall hijack rate by defense (both directions combined)",
    )

    with open(args.report, "w") as f:
        f.write(render_combined_report(args.client, by_direction))
    print(f"wrote combined report to {args.report}")


def cmd_list_techniques(args):
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


def build_parser():
    parser = argparse.ArgumentParser(prog="soclab", description="LLM SOC analyst prompt injection lab")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run the injection battery against a client")
    run_parser.add_argument("--client", choices=list(CLIENT_FACTORIES), default="fake-robust", help=_CLIENT_HELP)
    run_parser.add_argument("--defense", choices=list(DEFENSES), default=DEFENSE_NONE, help=_DEFENSE_HELP)
    run_parser.add_argument("--direction", choices=list(DIRECTIONS), default="dismiss",
                             help="which attacker goal to test: hide a real incident, or waste analyst time")
    run_parser.add_argument("--model", help="model name, required for --client ollama")
    run_parser.add_argument("--host", help="ollama host, defaults to $OLLAMA_HOST or localhost:11434")
    run_parser.add_argument("--report", help="write results as a markdown table to this path")
    run_parser.set_defaults(func=cmd_run)

    compare_parser = sub.add_parser("compare", help="run the battery under every defense and compare hijack rates")
    compare_parser.add_argument("--client", choices=list(CLIENT_FACTORIES), default="fake-robust", help=_CLIENT_HELP)
    compare_parser.add_argument("--direction", choices=list(DIRECTIONS), default="dismiss")
    compare_parser.add_argument("--model", help="model name, required for --client ollama")
    compare_parser.add_argument("--host", help="ollama host, defaults to $OLLAMA_HOST or localhost:11434")
    compare_parser.add_argument("--report", help="write results as a markdown table to this path")
    compare_parser.set_defaults(func=cmd_compare)

    full_report_parser = sub.add_parser(
        "full-report", help="run every direction and every defense for a client, write one combined report"
    )
    full_report_parser.add_argument(
        "--client", choices=list(CLIENT_FACTORIES), default="fake-robust", help=_CLIENT_HELP
    )
    full_report_parser.add_argument("--model", help="model name, required for --client ollama")
    full_report_parser.add_argument("--host", help="ollama host, defaults to $OLLAMA_HOST or localhost:11434")
    full_report_parser.add_argument("--report", required=True, help="path to write the combined markdown report to")
    full_report_parser.set_defaults(func=cmd_full_report)

    list_parser = sub.add_parser("list-techniques", help="list available injection techniques")
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


if __name__ == "__main__":
    sys.exit(main())
