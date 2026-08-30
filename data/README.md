# Labelled data

## What is in `labelled_reviews.json`

174 reviews from 161 distinct authors: 65 labelled fake, 109 labelled genuine.

| Group | Count | What it is |
|---|---|---|
| Genuine | 109 | Ordinary reviews, including 12 non-English |
| — of which hard negatives | 27 | Genuine reviews that *look* suspicious |
| Fake | 65 | Template farms, incentivised bursts, competitor attacks |
| — of which non-English | 15 | Farm output in es, pt, de, fr, ru, zh, ja |

The hard negatives are the useful part. They include a genuine three-review
same-day burst from someone who moved house and reviewed everything at once, an
enthusiast whose real reviews read like generic praise, and a genuine
"Highly recommend." that scores 100 — higher than most actual fakes.

## What this dataset can and cannot tell you

**It cannot validate the detector.** Every review here was hand-written for this
repository by the same author who wrote the detection rules. That is circular:
the data encodes one person's assumptions about what fake reviews look like, and
the rules were written against it. Good scores are close to guaranteed and mean
very little.

**It is for regression testing.** Its job is to catch the day a change stops
detecting something it used to detect, and to hold the false-positive cases that
the rules must keep *not* flagging. That is a real job, and this set does it.

**Its class balance is unrealistic.** At 37% fake it is far more balanced than a
real review stream, where the fake share is usually 5–20%. Precision measured
here is therefore substantially optimistic — see the prevalence table in the
main README. Recall and false-positive rate are unaffected.

## Getting real data

None of the public corpora below are vendored here, because only one of them
permits redistribution. Obtain them yourself from the sources listed.

| Dataset | Size | Labelling | Redistributable? |
|---|---|---|---|
| Ott et al. Deceptive Opinion Spam v1.4 | 1,600 | Crowdworkers paid to write fakes | **No** — research-only, permission required |
| YelpChi | ~67k | Yelp's own filter, as a proxy | **No** — email request; also Yelp ToS |
| YelpNYC / YelpZip | ~360k / ~600k | Yelp's own filter, as a proxy | **No** — same terms as YelpChi |
| Amazon reviews (McAuley et al.) | millions | Unlabelled; needs your own proxy | **Unclear** — non-commercial, terms unstated |
| AiGen-FoodReview | 1,440 | GPT-4-Turbo generated vs. real | **Yes** — MIT licence |
| Pérez-Rosas et al. multi-domain | 3,032 | Crowdworkers paid to write fakes | **No** — permission required |

Do not commit any of these into this repository. Point the tools at a local
path instead:

```bash
python3 -m fake_review_detector.cli calibrate /path/to/your/corpus.json
```

### Known problems with all of them

Worth knowing before treating any published accuracy number as meaningful:

- **The crowdworker confound.** In the Ott and Pérez-Rosas corpora the "fake"
  reviews are essays written to a prompt by paid workers. Classifiers may be
  learning the register of crowdworker writing rather than deception. Real spam
  is templated, bot-generated or coordinated, with a different fingerprint.
- **Platform filters are not ground truth.** The Yelp datasets label reviews by
  whether Yelp's own filter caught them, so a model trained on them learns to
  imitate that filter, including its mistakes.
- **LLM-generated corpora date fast.** AiGen-FoodReview is specifically
  GPT-4-Turbo output; detectors tuned on it need not generalise to other models,
  and it is a different threat model from paid human review spam.
- **Everything is near 50/50.** Balanced sets are easier to learn from and to
  publish, but they systematically overstate precision.

## Schema

```json
{
  "review_id": "g01",
  "author": "handle",
  "rating": 5,
  "text": "...",
  "verified_purchase": true,
  "account_age_days": 900,
  "date": "2024-01-01",
  "is_fake": false
}
```

`date` is optional; everything else is required. `is_fake` is the label.
