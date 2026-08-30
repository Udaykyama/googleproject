"""Command-line interface.

Subcommands map to the operational tasks the system exists to support::

    python -m fake_review_detector.cli score    data/sample_reviews.json
    python -m fake_review_detector.cli evaluate data/labelled_reviews.json --sweep
    python -m fake_review_detector.cli queue    --list
    python -m fake_review_detector.cli verify   --audit-log audit.jsonl
    python -m fake_review_detector.cli replay   data/sample_reviews.json

Invoking with a bare file path still works and runs ``score``, so the original
one-argument usage is unchanged.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditLog, replay
from .engine import moderate_batch
from .errors import ModerationError, PolicyError, ValidationError
from .evaluation import evaluate, load_labelled, threshold_sweep
from .models import Action
from .policy import Policy
from .queue import Outcome, ReviewQueue

_ACTION_LABEL = {
    Action.ALLOW: "ALLOW",
    Action.MONITOR: "MONITOR",
    Action.ENQUEUE: "REVIEW",
    Action.REMOVE: "REMOVE",
}


def _load_json(path: Path) -> list:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ModerationError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ModerationError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise ModerationError(f"{path} must contain a JSON array of reviews")
    return payload


def _load_policy(path: Path | None) -> Policy:
    return Policy.from_file(path) if path else Policy()


def _format_report(result, verbose: bool = False) -> str:
    lines: list[str] = []
    for decision in result.decisions:
        label = _ACTION_LABEL[decision.action]
        lines.append(
            f"[{label:>7}] {decision.review_id}  score={decision.score}"
            f"  risk={decision.risk_level.value}"
        )
        for signal in decision.signals:
            lines.append(f"          - {signal.message}  [{signal.code}]")
            if verbose and signal.evidence:
                lines.append(f"              evidence: {json.dumps(signal.evidence, ensure_ascii=False)}")
    return "\n".join(lines)


def _cmd_score(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    result = moderate_batch(_load_json(args.reviews_file), policy)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(_format_report(result, verbose=args.verbose))
        counts = result.by_action()
        report = result.duplicate_report
        print(
            f"\npolicy {result.policy_version} ({result.policy_digest[:12]})"
            f"  duplicates: {len(report.pairs) if report else 0} pair(s)"
            f" via {report.mode if report else 'exact'}"
        )
        print(
            f"{counts['allow']} allowed, {counts['monitor']} monitored, "
            f"{counts['enqueue']} sent for human review, {counts['remove']} removed."
        )
        if result.errors:
            print(f"\n{len(result.errors)} item(s) rejected as invalid:", file=sys.stderr)
            for error in result.errors:
                print(f"  - {error}", file=sys.stderr)

    if args.audit_log:
        AuditLog(args.audit_log).append(result.decisions)
    if args.queue:
        review_queue = ReviewQueue(args.queue)
        added = review_queue.enqueue(result.decisions)
        review_queue.save()
        print(f"{added} item(s) added to {args.queue}")

    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    labelled, errors = load_labelled(_load_json(args.labelled_file))
    if errors:
        print(f"{len(errors)} item(s) skipped:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
    if not labelled:
        raise ModerationError("no usable labelled reviews")

    if args.sweep:
        rows = threshold_sweep(labelled, policy, step=args.step)
        if args.json:
            print(json.dumps([m.to_dict() for m in rows], indent=2))
        else:
            print(f"{'thr':>4} {'prec':>7} {'recall':>7} {'f1':>7} {'fpr':>7}"
                  f" {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}")
            for metrics in rows:
                print(
                    f"{metrics.threshold:>4} {metrics.precision:>7.3f}"
                    f" {metrics.recall:>7.3f} {metrics.f1:>7.3f}"
                    f" {metrics.false_positive_rate:>7.3f}"
                    f" {metrics.true_positives:>4} {metrics.false_positives:>4}"
                    f" {metrics.true_negatives:>4} {metrics.false_negatives:>4}"
                )
        return 0

    metrics = evaluate(labelled, policy, threshold=args.threshold)
    if args.json:
        print(json.dumps(metrics.to_dict(), indent=2))
    else:
        print(f"{len(labelled)} labelled review(s)")
        print(metrics.format_table())
    return 0


def _cmd_queue(args: argparse.Namespace) -> int:
    review_queue = ReviewQueue(args.queue)

    if args.claim:
        items = review_queue.claim(args.claim, limit=args.limit)
        review_queue.save()
        if not items:
            print("nothing pending")
        for item in items:
            print(f"{item.review_id}  score={item.decision.score}")
            for signal in item.decision.signals:
                print(f"  - {signal.message}  [{signal.code}]")
        return 0

    if args.resolve:
        if not args.outcome or not args.moderator:
            raise ModerationError("--resolve requires --moderator and --outcome")
        item = review_queue.resolve(
            args.resolve, args.moderator, Outcome(args.outcome), args.note
        )
        review_queue.save()
        print(f"{item.review_id} resolved as {item.outcome.value} by {item.resolved_by}")
        return 0

    stats = review_queue.stats()
    if args.json:
        print(json.dumps(stats, indent=2))
        return 0

    states = ", ".join(
        f"{count} {state}" for state, count in stats["states"].items() if count
    )
    print(f"{stats['total']} item(s)" + (f": {states}" if states else ""))
    if stats["overturn_rate"] is not None:
        print(
            f"moderator outcomes: {stats['outcomes']['upheld']} upheld, "
            f"{stats['outcomes']['overturned']} overturned "
            f"(overturn rate {stats['overturn_rate']:.1%})"
        )
    if args.list:
        for item in review_queue.pending():
            print(f"  {item.review_id}  score={item.decision.score}  queued {item.queued_at}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    status = AuditLog(args.audit_log).verify()
    print(status)
    return 0 if status.valid else 1


def _cmd_replay(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    differences = replay(AuditLog(args.audit_log), _load_json(args.reviews_file), policy)
    if args.json:
        print(json.dumps(differences, indent=2))
    elif not differences:
        print("replay matches the audit log")
    else:
        for difference in differences:
            print(f"{difference['review_id']}: {difference['difference']} — {difference['detail']}")
    return 1 if differences else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fake_review_detector",
        description="Moderate a batch of reviews for likely fake or policy-violating content.",
    )
    subparsers = parser.add_subparsers(dest="command")

    score = subparsers.add_parser("score", help="Score and decide on a batch of reviews.")
    score.add_argument("reviews_file", type=Path, help="JSON array of review objects.")
    score.add_argument("--policy", type=Path, help="Policy JSON file.")
    score.add_argument("--audit-log", type=Path, help="Append decisions to this audit log.")
    score.add_argument("--queue", type=Path, help="Add items needing review to this queue.")
    score.add_argument("--json", action="store_true", help="Emit JSON.")
    score.add_argument("--verbose", action="store_true", help="Show signal evidence.")
    score.set_defaults(func=_cmd_score)

    evaluate_parser = subparsers.add_parser(
        "evaluate", help="Measure precision/recall against labelled data."
    )
    evaluate_parser.add_argument("labelled_file", type=Path, help="Reviews with an is_fake label.")
    evaluate_parser.add_argument("--policy", type=Path)
    evaluate_parser.add_argument("--threshold", type=int, help="Flag at this score.")
    evaluate_parser.add_argument("--sweep", action="store_true", help="Report every threshold.")
    evaluate_parser.add_argument("--step", type=int, default=5, help="Sweep step size.")
    evaluate_parser.add_argument("--json", action="store_true")
    evaluate_parser.set_defaults(func=_cmd_evaluate)

    queue_parser = subparsers.add_parser("queue", help="Inspect and work the review queue.")
    queue_parser.add_argument("--queue", type=Path, default=Path("queue.json"))
    queue_parser.add_argument("--list", action="store_true", help="List pending items.")
    queue_parser.add_argument("--claim", metavar="MODERATOR", help="Claim pending items.")
    queue_parser.add_argument("--limit", type=int, default=5, help="How many to claim.")
    queue_parser.add_argument("--resolve", metavar="REVIEW_ID", help="Resolve an item.")
    queue_parser.add_argument("--moderator", help="Who is resolving.")
    queue_parser.add_argument(
        "--outcome", choices=[o.value for o in Outcome], help="Moderator verdict."
    )
    queue_parser.add_argument("--note", default="", help="Free-text rationale.")
    queue_parser.add_argument("--json", action="store_true")
    queue_parser.set_defaults(func=_cmd_queue)

    verify = subparsers.add_parser("verify", help="Check the audit log has not been altered.")
    verify.add_argument("--audit-log", type=Path, required=True)
    verify.set_defaults(func=_cmd_verify)

    replay_parser = subparsers.add_parser(
        "replay", help="Re-derive decisions and diff them against the audit log."
    )
    replay_parser.add_argument("reviews_file", type=Path)
    replay_parser.add_argument("--audit-log", type=Path, required=True)
    replay_parser.add_argument("--policy", type=Path)
    replay_parser.add_argument("--json", action="store_true")
    replay_parser.set_defaults(func=_cmd_replay)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Original usage was a bare path with no subcommand; keep it working.
    if argv and not argv[0].startswith("-") and argv[0] not in {
        "score", "evaluate", "queue", "verify", "replay",
    }:
        argv.insert(0, "score")

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2

    try:
        return args.func(args)
    except (ModerationError, PolicyError, ValidationError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
