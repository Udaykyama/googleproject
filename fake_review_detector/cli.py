"""Command-line interface.

Subcommands map to the operational tasks the system exists to support::

    python -m fake_review_detector.cli score    data/sample_reviews.json
    python -m fake_review_detector.cli evaluate data/labelled_reviews.json --sweep
    python -m fake_review_detector.cli queue    --list
    python -m fake_review_detector.cli verify   --audit-log audit.jsonl
    python -m fake_review_detector.cli replay   data/sample_reviews.json
    python -m fake_review_detector.cli backup   --database moderation.sqlite3 \
        --output-dir backups
    python -m fake_review_detector.cli operational-check \
        --data-dir data --backup-dir backups

Invoking with a bare file path still works and runs ``score``, so the original
one-argument usage is unchanged.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditLog, replay
from .backup import backup_database
from .calibration import OBJECTIVES, calibrate, precision_at_prevalence
from .engine import moderate_batch
from .errors import ModerationError, PolicyError, ValidationError
from .evaluation import evaluate, load_labelled, threshold_sweep
from .models import Action
from .operations import run_operational_checks
from .policy import Policy
from .queue import Outcome, QueueState, ReviewQueue
from .sqlite_store import SQLiteStore

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
    except (ValueError, RecursionError) as exc:
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
    if args.database and (args.audit_log or args.queue or args.anchor):
        raise ModerationError("--database replaces --queue, --audit-log, and --anchor")
    if args.anchor and not args.audit_log:
        raise ModerationError("--anchor requires --audit-log")
    policy = _load_policy(args.policy)
    result = moderate_batch(_load_json(args.reviews_file), policy)

    added = None
    destination = args.database or args.queue
    if args.database:
        added = SQLiteStore(args.database).enqueue(result.decisions)
    else:
        if args.audit_log:
            AuditLog(args.audit_log, args.anchor).append(result.decisions)
        if args.queue:
            review_queue = ReviewQueue(args.queue)
            added = review_queue.enqueue(result.decisions)
            review_queue.save()

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

    if added is not None:
        print(
            f"{added} item(s) added to {destination}",
            file=sys.stderr if args.json else sys.stdout,
        )

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


def _cmd_calibrate(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    labelled, errors = load_labelled(_load_json(args.labelled_file))
    if errors:
        print(f"{len(errors)} item(s) skipped:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
    if not labelled:
        raise ModerationError("no usable labelled reviews")

    try:
        result = calibrate(
            labelled,
            policy,
            objective=args.objective,
            recall_floor=args.recall_floor,
            test_fraction=args.test_fraction,
            salt=args.salt,
            step=args.step,
        )
    except ValueError as exc:
        raise ModerationError(str(exc)) from exc

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.recommended else 1

    print(result.format_report())
    print()
    print("Precision if the live stream is mostly genuine (worst case within")
    print("the confidence interval, so a zero-error test split cannot read as")
    print("a guarantee of zero errors in production):")
    print(f"  {'prevalence':>10}  {'incumbent':>10}  {'candidate':>10}")
    for prevalence in (0.37, 0.20, 0.10, 0.05):
        incumbent = precision_at_prevalence(
            result.incumbent_recall.low,
            result.incumbent_false_positive_rate.high,
            prevalence,
        )
        candidate = precision_at_prevalence(
            result.recall.low,
            result.false_positive_rate.high,
            prevalence,
        )
        print(f"  {prevalence:>9.0%}  {incumbent:>10.3f}  {candidate:>10.3f}")
    return 0 if result.recommended else 1


def _cmd_queue(args: argparse.Namespace) -> int:
    review_queue = (
        SQLiteStore(args.database)
        if args.database
        else ReviewQueue(args.queue or Path("queue.json"))
    )

    if args.claim is not None:
        items = review_queue.claim(args.claim, limit=args.limit)
        if isinstance(review_queue, ReviewQueue):
            review_queue.save()
        if args.json:
            print(json.dumps([item.to_dict() for item in items], indent=2))
            return 0
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
        if isinstance(review_queue, ReviewQueue):
            review_queue.save()
        if args.json:
            print(json.dumps(item.to_dict(), indent=2))
        else:
            print(f"{item.review_id} resolved as {item.outcome.value} by {item.resolved_by}")
        return 0

    if args.release:
        review_queue.release(args.release)
        if isinstance(review_queue, ReviewQueue):
            review_queue.save()
        if args.json:
            print(json.dumps({"review_id": args.release, "state": "pending"}))
        else:
            print(f"{args.release} released to the pending queue")
        return 0

    snapshot = (
        review_queue.snapshot(limit=args.page_size, offset=args.offset, state=args.state)
        if args.list else None
    )
    stats = snapshot.stats if snapshot else review_queue.stats()
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
    if snapshot:
        for item in snapshot.items:
            print(f"  {item.review_id}  score={item.decision.score}  queued {item.queued_at}")
        if snapshot.has_next:
            print(f"More items available; use --offset {args.offset + args.page_size}.")
    return 0


def _open_log(args: argparse.Namespace) -> AuditLog | SQLiteStore:
    if args.database:
        if args.anchor or getattr(args, "re_anchor", False):
            raise ModerationError("SQLite keeps its anchor transactionally; file anchor flags do not apply")
        return SQLiteStore(args.database, create=False)
    return AuditLog(args.audit_log, args.anchor)


def _cmd_verify(args: argparse.Namespace) -> int:
    log = _open_log(args)

    if args.integrity:
        if not isinstance(log, SQLiteStore):
            raise ModerationError("--integrity requires --database")
        log.check_integrity()
        print("SQLite integrity check passed")

    if args.re_anchor and isinstance(log, AuditLog):
        anchor = log.write_anchor()
        print(f"anchored {anchor.records} record(s) at {anchor.head_hash}")
        return 0

    status = log.verify()
    print(status)
    if status.valid and not status.anchor_checked and args.require_anchor:
        print("no anchor present, and --require-anchor was given")
        return 1
    return 0 if status.valid else 1


def _cmd_replay(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    differences = replay(
        _open_log(args), _load_json(args.reviews_file), policy
    )
    if args.json:
        print(json.dumps(differences, indent=2))
    elif not differences:
        print("replay matches the audit log")
    else:
        for difference in differences:
            print(f"{difference['review_id']}: {difference['difference']} — {difference['detail']}")
    return 1 if differences else 0


def _cmd_backup(args: argparse.Namespace) -> int:
    result = backup_database(
        args.database,
        args.output_dir,
        keep=args.keep,
        timeout=args.timeout,
    )
    print(
        f"verified backup: {result.path} "
        f"({result.records} audit record(s), {len(result.removed)} expired removed)"
    )
    return 0


def _cmd_operational_check(args: argparse.Namespace) -> int:
    report = run_operational_checks(
        readiness_url=args.readiness_url,
        data_dir=args.data_dir,
        backup_dir=args.backup_dir,
        minimum_free_bytes=args.min_free_bytes,
        minimum_free_percent=args.min_free_percent,
        maximum_backup_age=args.max_backup_age,
        readiness_timeout=args.readiness_timeout,
        backup_timeout=args.backup_timeout,
    )
    print(json.dumps(report.to_dict(), ensure_ascii=True, separators=(",", ":")))
    return 0 if report.ok else 1


def _positive_int(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def _nonnegative_int(raw: str) -> int:
    value = int(raw)
    if value < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return value


def _positive_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number") from None
    if not 0 < value < float("inf"):
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return value


def _percentage(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number") from None
    if not 0 <= value <= 100 or value in (float("inf"), float("-inf")):
        raise argparse.ArgumentTypeError("must be between zero and 100")
    return value


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
    score.add_argument(
        "--anchor",
        type=Path,
        help="Anchor file for --audit-log. Defaults to the log path plus '.anchor'.",
    )
    score.add_argument("--queue", type=Path, help="Add items needing review to this queue.")
    score.add_argument(
        "--database", type=Path,
        help="Atomically store decisions and queued items in a shared SQLite database.",
    )
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
    evaluate_parser.add_argument("--step", type=_positive_int, default=5, help="Sweep step size.")
    evaluate_parser.add_argument("--json", action="store_true")
    evaluate_parser.set_defaults(func=_cmd_evaluate)

    calibrate_parser = subparsers.add_parser(
        "calibrate",
        help="Propose a threshold from labelled data, with a held-out test split.",
    )
    calibrate_parser.add_argument(
        "labelled_file", type=Path, help="Reviews with an is_fake label."
    )
    calibrate_parser.add_argument("--policy", type=Path)
    calibrate_parser.add_argument(
        "--objective",
        choices=sorted(OBJECTIVES),
        default="precision_at_recall",
        help="What to maximise on the training split.",
    )
    calibrate_parser.add_argument(
        "--recall-floor",
        type=float,
        default=0.90,
        help="Minimum acceptable recall for the precision_at_recall objective.",
    )
    calibrate_parser.add_argument(
        "--test-fraction", type=float, default=0.5, help="Share of authors held out."
    )
    calibrate_parser.add_argument(
        "--salt", default="calibration-v1", help="Changes which authors land in which split."
    )
    calibrate_parser.add_argument("--step", type=_positive_int, default=5, help="Sweep step size.")
    calibrate_parser.add_argument("--json", action="store_true")
    calibrate_parser.set_defaults(func=_cmd_calibrate)

    queue_parser = subparsers.add_parser("queue", help="Inspect and work the review queue.")
    queue_storage = queue_parser.add_mutually_exclusive_group()
    queue_storage.add_argument("--queue", type=Path, help="JSON queue (default: queue.json).")
    queue_storage.add_argument("--database", type=Path, help="Shared SQLite database.")
    queue_actions = queue_parser.add_mutually_exclusive_group()
    queue_actions.add_argument("--list", action="store_true", help="List a page of items.")
    queue_actions.add_argument("--claim", metavar="MODERATOR", help="Claim pending items.")
    queue_actions.add_argument("--resolve", metavar="REVIEW_ID", help="Resolve an item.")
    queue_actions.add_argument("--release", metavar="REVIEW_ID", help="Release a claimed item.")
    queue_parser.add_argument("--limit", type=_positive_int, default=5, help="How many to claim.")
    queue_parser.add_argument("--page-size", type=_positive_int, default=50, help="Items per --list page.")
    queue_parser.add_argument("--offset", type=_nonnegative_int, default=0, help="Offset for --list.")
    queue_parser.add_argument("--state", choices=[s.value for s in QueueState], default="pending")
    queue_parser.add_argument("--moderator", help="Who is resolving.")
    queue_parser.add_argument(
        "--outcome", choices=[o.value for o in Outcome], help="Moderator verdict."
    )
    queue_parser.add_argument("--note", default="", help="Free-text rationale.")
    queue_parser.add_argument("--json", action="store_true")
    queue_parser.set_defaults(func=_cmd_queue)

    verify = subparsers.add_parser("verify", help="Check the audit log has not been altered.")
    verify_source = verify.add_mutually_exclusive_group(required=True)
    verify_source.add_argument("--audit-log", type=Path)
    verify_source.add_argument("--database", type=Path)
    verify.add_argument(
        "--anchor",
        type=Path,
        help="Anchor file. Defaults to the log path plus '.anchor'. Point this "
        "at separately administered storage so truncating the log cannot also "
        "rewrite its anchor.",
    )
    verify.add_argument(
        "--re-anchor",
        action="store_true",
        help="Rewrite the anchor to match the log as it currently stands, then "
        "exit. Only do this when the log's current state is known good.",
    )
    verify.add_argument(
        "--require-anchor",
        action="store_true",
        help="Fail when no anchor exists, instead of reporting the truncation "
        "check as not performed.",
    )
    verify.add_argument(
        "--integrity",
        action="store_true",
        help="Also run SQLite's full integrity check; requires --database.",
    )
    verify.set_defaults(func=_cmd_verify)

    replay_parser = subparsers.add_parser(
        "replay", help="Re-derive decisions and diff them against the audit log."
    )
    replay_parser.add_argument("reviews_file", type=Path)
    replay_source = replay_parser.add_mutually_exclusive_group(required=True)
    replay_source.add_argument("--audit-log", type=Path)
    replay_source.add_argument("--database", type=Path)
    replay_parser.add_argument(
        "--anchor", type=Path, help="Anchor file. Defaults to the log path plus '.anchor'."
    )
    replay_parser.add_argument("--policy", type=Path)
    replay_parser.add_argument("--json", action="store_true")
    replay_parser.set_defaults(func=_cmd_replay)

    backup_parser = subparsers.add_parser(
        "backup",
        help="Create and audit-verify an atomic live SQLite backup.",
    )
    backup_parser.add_argument(
        "--database", type=Path, required=True, help="Live moderation SQLite database."
    )
    backup_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Existing persistent directory for timestamped backups.",
    )
    backup_parser.add_argument(
        "--keep",
        type=_positive_int,
        default=14,
        help="Number of timestamped backups to retain (default: 14).",
    )
    backup_parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=30.0,
        help="SQLite lock timeout in seconds (default: 30).",
    )
    backup_parser.set_defaults(func=_cmd_backup)

    operations = subparsers.add_parser(
        "operational-check",
        help="Check local readiness, durable disk headroom, and verified backups.",
    )
    operations.add_argument(
        "--readiness-url",
        default="http://127.0.0.1:8000/readyz",
        help="Local readiness URL (default: http://127.0.0.1:8000/readyz).",
    )
    operations.add_argument(
        "--data-dir",
        type=Path,
        required=True,
        help="Persistent application data directory whose filesystem is checked.",
    )
    operations.add_argument(
        "--backup-dir",
        type=Path,
        required=True,
        help="Directory containing finalized moderation backups.",
    )
    operations.add_argument(
        "--min-free-bytes",
        type=_nonnegative_int,
        default=1_073_741_824,
        help="Minimum data-filesystem free bytes (default: 1073741824).",
    )
    operations.add_argument(
        "--min-free-percent",
        type=_percentage,
        default=10.0,
        help="Minimum data-filesystem free percentage (default: 10).",
    )
    operations.add_argument(
        "--max-backup-age",
        type=_positive_float,
        default=129_600.0,
        help="Maximum latest-backup age in seconds (default: 129600 / 36h).",
    )
    operations.add_argument(
        "--readiness-timeout",
        type=_positive_float,
        default=5.0,
        help="Readiness request timeout in seconds (default: 5).",
    )
    operations.add_argument(
        "--backup-timeout",
        type=_positive_float,
        default=30.0,
        help="SQLite backup-verification lock timeout in seconds (default: 30).",
    )
    operations.set_defaults(func=_cmd_operational_check)

    #: Read back off the subparsers so the bare-path compatibility shim in
    #: main() cannot drift out of sync when a subcommand is added.
    parser.subcommand_names = frozenset(subparsers.choices)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # Original usage was a bare path with no subcommand; keep it working. The
    # command names are read back off the parser rather than repeated here, so
    # adding a subcommand cannot silently turn it into a filename.
    commands = getattr(parser, "subcommand_names", frozenset())
    if argv and not argv[0].startswith("-") and argv[0] not in commands:
        argv.insert(0, "score")

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
