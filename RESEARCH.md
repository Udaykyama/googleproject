# Research: The Fake/Manipulated Review Problem Google Is Fighting

This document summarizes the research behind the `fake_review_detector` showcase
project in this repository. The goal was to pick a real, well-documented problem
that Google is actively trying to fix, understand how many users are affected,
and check what Google's own job postings say about how the company staffs
people to solve it.

## The problem

Google Search, Google Maps and Google Business Profiles rely heavily on
user-generated reviews to help people choose businesses, products and
services. That same openness makes reviews a prime target for abuse:
paid/incentivized "review farms", bot-generated praise, competitor
"review bombing" attacks, and fake business listings created purely to
harvest reviews.

Google has publicly confirmed this is a large and growing problem it is
actively fighting with policy, moderation and machine learning (including
Gemini-based models):

- **240+ million fake or policy-violating reviews** removed/blocked by Google
  in 2024 — a **40% increase** over the 170 million removed in 2023
  (Google Maps Content Trust & Safety Report / Google blog, 2024-2025
  transparency updates).
- **12 million fake business profiles** removed in 2024.
- **70 million** policy-violating edits to business listings blocked.
- **900,000+ user accounts** restricted from posting after repeated policy
  violations.
- Independent research from the **UK Competition and Markets Authority (CMA)**
  estimates that **11–15% of all online reviews** (across platforms,
  including Google) may be fake.
- Consumer research cited alongside these figures found that **~82% of
  people** say they've encountered a fake review in the last year, and
  **~74%** say they struggle to tell real reviews from fake ones.
- The UK fake-review problem alone is estimated to cost consumers between
  **£50M and £312M per year** in poor purchasing decisions.

Sources referenced during research: Google's Maps Content Trust & Safety
transparency report, the official Google blog post "Google Maps uses AI to
fight fake Business Profiles", Google's public-policy blog post on legal
action against fake review scams, and third-party analyses summarizing UK
CMA findings on fake review prevalence.

## Who is affected

- **Consumers/users**: hundreds of millions of people rely on Google Maps
  and Search reviews to make everyday purchasing decisions; fake reviews
  directly distort those decisions.
- **Small businesses**: legitimate businesses can be unfairly harmed by
  competitor review-bombing, or lose customers to rivals who buy fake
  5-star reviews.
- **Platform trust**: at scale (hundreds of millions of reviews touched
  per year), unresolved fake reviews erode trust in the platform itself.

## How Google staffs the fight (job postings)

Reviewing Google's public job postings for roles such as *Trust & Safety
Analyst*, *Abuse Operations Analyst*, and *Content Policy Specialist* shows
a consistent set of responsibilities that map directly to this problem:

1. **Detection & investigation** — monitor user-generated content (Maps,
   Search, Play) for fake/fraudulent/abusive reviews, using internal tooling,
   ML signals and analytics to spot spikes, coordinated accounts, or paid
   review rings.
2. **Policy enforcement** — evaluate flagged content against Google's review
   and engagement policies (spam, fake engagement, conflicts of interest,
   harassment), and process appeals consistently.
3. **User & business protection** — remove fake/harmful content quickly,
   restrict abusive accounts, and protect small businesses from targeted
   attacks (e.g., temporarily locking reviews on a listing under attack).
4. **Continuous improvement** — partner with engineering/ML teams to retrain
   detection models against new abuse tactics and reduce false negatives.
5. **Community support** — help users and business owners understand how to
   report abuse and what happens after a report is filed.

## Why this project

Given the scale (hundreds of millions of reviews affected per year) and the
fact that this is a problem Google is *actively, publicly* trying to solve
with a mix of policy and automated detection, this repository implements a
small, self-contained **showcase** of the detection side of that problem:
a rule-based **Fake Review Detector** that scores individual reviews and
whole batches for the same kinds of signals real Trust & Safety teams look
for (see `README.md` for usage).

This is a simplified, educational demonstration — not a production
moderation system — but it illustrates the core detection signals in a way
that is easy to run, test, and extend.
