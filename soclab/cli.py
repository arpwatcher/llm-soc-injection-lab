"""Entry point: run the injection battery against a client and print a
per-technique report, or list the available techniques."""

import argparse
import sys

from soclab.alerts import generate_clean_alerts
from soclab.injections import TECHNIQUES, apply_all_techniques
from soclab.llm_client import OllamaClient, RobustFakeClient, VulnerableFakeClient
from soclab.scoring import aggregate_by_technique, score_batch

CLIENT_FACTORIES = {
    "fake-robust": lambda args: RobustFakeClient(),
    "fake-vulnerable": lambda args: VulnerableFakeClient(),
    "ollama": lambda args: OllamaClient(model=args.model, host=args.host),
}


def build_client(args):
    if args.client == "ollama" and not args.model:
        raise ValueError("--model is required when --client ollama")
    return CLIENT_FACTORIES[args.client](args)


def cmd_run(args):
    client = build_client(args)

    clean_alerts = generate_clean_alerts()
    injected_alerts = apply_all_techniques(clean_alerts)

    clean_results = score_batch(clean_alerts, client)
    clean_correct = sum(1 for r in clean_results if r.outcome == "resisted")
    print(f"clean alerts: {clean_correct}/{len(clean_results)} correct action\n")

    injected_results = score_batch(injected_alerts, client)
    aggregated = aggregate_by_technique(injected_results)

    print(f"{'technique':<20} {'hijacked':>8} {'resisted':>8} {'other':>6} {'hijack_rate':>12}")
    for technique, bucket in aggregated.items():
        print(f"{technique:<20} {bucket['hijacked']:>8} {bucket['resisted']:>8} {bucket['other']:>6} "
              f"{bucket['hijack_rate']:>11.0%}")


def cmd_list_techniques(args):
    print(f"{len(TECHNIQUES)} injection techniques:")
    for name, func in TECHNIQUES.items():
        print(f"  {name} - {func.__doc__ or '(no description)'}")


def build_parser():
    parser = argparse.ArgumentParser(prog="soclab", description="LLM SOC analyst prompt injection lab")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run the injection battery against a client")
    run_parser.add_argument("--client", choices=list(CLIENT_FACTORIES), default="fake-robust")
    run_parser.add_argument("--model", help="model name, required for --client ollama")
    run_parser.add_argument("--host", help="ollama host, defaults to $OLLAMA_HOST or localhost:11434")
    run_parser.set_defaults(func=cmd_run)

    list_parser = sub.add_parser("list-techniques", help="list available injection techniques")
    list_parser.set_defaults(func=cmd_list_techniques)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
