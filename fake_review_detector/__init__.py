"""Fake Review Detector.

A small, dependency-free heuristic engine that scores product/business
reviews for signals commonly associated with fake or policy-violating
reviews (the same kind of problem Google's Trust & Safety teams work on
for Google Maps / Business Profiles). See RESEARCH.md for background.
"""

from .detector import Review, ReviewScore, score_review, score_reviews

__all__ = ["Review", "ReviewScore", "score_review", "score_reviews"]
