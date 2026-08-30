# googleproject

## Fake Review Detector — a showcase of a problem Google is fixing

Google has publicly reported removing/blocking **240+ million fake or
policy-violating reviews in 2024 alone** (up 40% from 2023), taking down
12 million fake business profiles, and restricting 900,000+ abusive
accounts on Google Maps / Business Profiles. Independent research (UK CMA)
estimates **11-15% of all online reviews may be fake**, and Google
actively hires Trust & Safety / abuse-fighting roles to work on exactly
this problem. See [`RESEARCH.md`](RESEARCH.md) for full sources and
figures.

This repository contains a small, dependency-free **Fake Review Detector**
that showcases the kind of heuristic detection signals used to fight this
problem: generic/templated phrases, extreme ratings paired with low-effort
text, unverified purchases, brand-new accounts, near-duplicate review text
across a batch (review farms), and same-day review "bursts" from one
author.

### Usage

```bash
# Run the test suite
python3 -m pytest tests/ -v

# Score the sample batch of reviews and print a risk report
python3 -m fake_review_detector.cli data/sample_reviews.json
```

Or use it as a library:

```python
from fake_review_detector import Review, score_reviews

reviews = [
    Review(review_id="1", author="alice", rating=5,
           text="Great, well-made product that has held up over months of use.",
           verified_purchase=True, account_age_days=500, date="2024-01-01"),
]
for result in score_reviews(reviews):
    print(result.review_id, result.score, result.risk_level, result.reasons)
```

### Project layout

- `fake_review_detector/detector.py` — the heuristic scoring engine
- `fake_review_detector/cli.py` — command-line report generator
- `data/sample_reviews.json` — example batch of genuine + fake reviews
- `tests/test_detector.py` — pytest unit tests
- `RESEARCH.md` — the research behind the problem this project showcases
