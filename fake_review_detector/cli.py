"""Command-line interface for the fake review detector.

Usage:
    python -m fake_review_detector.cli data/sample_reviews.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detector import Review, score_reviews


def load_reviews(path: Path) -> list[Review]:
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return [Review(**item) for item in raw]


def format_report(scores) -> str:
    lines = []
    for s in scores:
        lines.append(f"[{s.risk_level.upper():>6}] {s.review_id}  score={s.score}")
        for reason in s.reasons:
            lines.append(f"         - {reason}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score a batch of reviews for likely fake/policy-violating content."
    )
    parser.add_argument(
        "reviews_file",
        type=Path,
        help="Path to a JSON file containing a list of review objects.",
    )
    args = parser.parse_args(argv)

    reviews = load_reviews(args.reviews_file)
    scores = score_reviews(reviews)
    print(format_report(scores))

    high_risk = sum(1 for s in scores if s.risk_level == "high")
    print(f"\n{high_risk}/{len(scores)} review(s) flagged as high risk.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
