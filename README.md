# Google Trust & Safety Showcases

## InboxReady

**A pre-flight compliance auditor for Gmail's bulk sender requirements.**

Since **November 2025**, Gmail permanently rejects mail from bulk senders that
fail its authentication requirements. Not "sends it to spam" — rejects it at the
SMTP layer with a `5.7.x` error, so the message never exists in the recipient's
mailbox.

InboxReady tells you whether your domain would pass, *before* Gmail decides.

```
$ inboxready deals.example-shop.test --selector google --message campaign.eml

Score 0/100   Gmail bulk-sender status: NOT READY
Findings: BLOCK 9   CRIT 7   WARN 10   INFO 4

   BLOCK SPF exceeds the 10 DNS-lookup limit  [SPF_TOO_MANY_LOOKUPS]
         Evaluating this record requires 13 DNS lookups; the limit is 10.
           Receivers return permerror, so SPF fails even for hosts you
           legitimately authorised.
         fix: Flatten or prune 'include:' chains, or move rarely used senders
           to a dedicated subdomain.
         ref: RFC 7208 §4.6.4
```

Why this project exists, and how the problem was chosen, is documented in
[RESEARCH.md](RESEARCH.md).

---

## The problem

Google requires every domain sending 5,000+ messages a day to personal Gmail
accounts to publish SPF, DKIM, and DMARC, align them with the `From:` header,
serve valid forward-confirmed reverse DNS, use TLS, implement RFC 8058
one-click unsubscribe, and hold spam complaints below 0.30%.

Three things make this harder than it sounds:

1. **Bulk sender status is permanent.** Cross the threshold once and the domain
   is subject to the full requirements from then on.
2. **The failures are invisible from the sending side.** An SPF record that
   silently exceeded ten DNS lookups when a vendor was added, a DKIM key rotated
   in the signer but not in DNS, a `List-Unsubscribe` header missing the
   `List-Unsubscribe-Post` line — none of these show up in your own inbox.
3. **In October 2025, Google removed the reputation dashboards** from Postmaster
   Tools and replaced them with a pass/fail Compliance Status view, on the
   grounds that reputation scores were misleading and gameable.

That last point is the design brief for this tool. Google decided the thing
worth measuring is deterministic compliance with published standards. So
InboxReady reports facts with citations, never a vague grade.

---

## Install

Requires Python 3.10+. There are no required runtime dependencies for the CLIs.
Use a virtual environment rather than the OS-managed Python installation
(macOS may still provide Python 3.9).

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Or run it straight from a checkout without installing:

```bash
PYTHONPATH=src python3 -m inboxready --help
```

DNS resolution uses [dnspython](https://www.dnspython.org/) when available and
falls back to `dig`. To install the optional accelerator:

```bash
pip install '.[dns]'
```

---

## Try it offline

The repository ships two DNS fixtures and two messages, so the full tool can be
demonstrated with no network access and no real domains.

**A broken sender:**

```bash
inboxready deals.example-shop.test \
  --fixture examples/fixtures/failing-sender.json \
  --selector google --selector legacy \
  --ip 203.0.113.25 \
  --message examples/messages/failing-campaign.eml \
  --daily-volume 1200000 --spam-rate 0.42
```

> Score 0/100, NOT READY, 16 blocking or critical findings, exit code 1.

**A healthy one:**

```bash
inboxready mail.example-good.test \
  --fixture examples/fixtures/compliant-sender.json \
  --selector google \
  --ip 198.51.100.25 \
  --message examples/messages/compliant-campaign.eml \
  --daily-volume 120000 --spam-rate 0.04
```

> Score 96/100, READY, exit code 0. The single warning is `IP_NOT_PUBLIC`: the
> example uses an RFC 5737 documentation address, which is exactly the kind of
> thing the tool is supposed to notice.

**Audit a message with no DNS at all:**

```bash
inboxready --message examples/messages/failing-campaign.eml --offline
```

---

## Usage

```
inboxready [domain] [options]
```

| Flag | Purpose |
| --- | --- |
| `-m`, `--message FILE` | Raw `.eml` to audit (`-` reads stdin) |
| `--selector NAME` | DKIM selector; repeatable. Common ones are probed if omitted |
| `--ip ADDR` | Sending IP to forward-confirm; repeatable |
| `--daily-volume N` | Messages/day to Gmail, for bulk-sender classification |
| `--spam-rate PCT` | Complaint rate from Postmaster Tools, e.g. `0.08` |
| `--transactional` | Treat the message as transactional, skipping unsubscribe rules |
| `--fixture FILE` | Answer DNS from JSON instead of the network |
| `--offline` | Skip DNS entirely; audit the message only |
| `--nameserver ADDR` | Query a specific resolver |
| `--public-suffix-list FILE` | Mozilla's `public_suffix_list.dat` for exact org domains |
| `-f`, `--format` | `text` (default), `json`, or `markdown` |
| `-o`, `--output FILE` | Write to a file instead of stdout |
| `--fail-on` | Severity that triggers a non-zero exit (default `critical`) |

**Exit codes:** `0` clean · `1` findings at or above `--fail-on` · `2` usage error.

Suitable for CI:

```yaml
- name: Check sender compliance
  run: inboxready mail.example.com --selector s1 --fail-on warning
```

---

## What it checks

91 distinct finding codes across seven checks. Every finding carries a severity,
an explanation, a concrete fix, and the standard it derives from.

**SPF** (RFC 7208) — record present and unique, syntax, `+all` / `?all` / missing
`all`, **the 10-DNS-lookup limit** computed by recursively expanding
`include:` and `redirect=` chains, the 2-void-lookup limit, `ptr` deprecation,
macro use, and lookup counts approaching the limit.

**DKIM** (RFC 6376, RFC 8301) — selector resolution, key presence, revoked keys
(`p=` empty), test mode (`t=y`), **RSA key length parsed from the DER**, SHA-1
restriction, service-type and flag tags.

**DMARC** (RFC 7489) — record at `_dmarc`, organisational-domain fallback with
correct `sp=` semantics, `p=` strength, `pct<100`, `rua`/`ruf` presence, and
**external report authorisation** (§7.1), which almost nothing else checks.

**Network** — MX presence and null MX (RFC 7505), **forward-confirmed reverse
DNS** for every supplied IP, MTA-STS (RFC 8461), TLS-RPT (RFC 8460), BIMI and
whether the DMARC policy is strong enough to support it.

**Message hygiene** (RFC 5322, RFC 8058) — required headers, **one-click
unsubscribe done properly** (`List-Unsubscribe-Post` present, HTTPS URI, not
mailto-only), **DKIM `d=` alignment with `From:`**, `l=` body-length tag abuse,
unsigned header attacks, display-name spoofing, `Reply-To` divergence,
`Authentication-Results` verdicts, ARC chains, HTML-only bodies, and Gmail
impersonation.

**Reputation** — bulk-sender classification against the 5,000/day threshold with
an early warning before you cross it, and spam complaint rates banded against
Google's 0.10% target and 0.30% limit.

---

## Design decisions

**No required dependencies.** DKIM key bit-length comes from a small DER/ASN.1
reader rather than a crypto library; DNS falls back to `dig` when dnspython is
absent. The tool runs anywhere Python does.

**No HTTP requests, ever.** MTA-STS policy files and BIMI logos are *not*
fetched — only their DNS records are read. Auditing a domain you do not control
is a natural server-side request forgery primitive, and declining to fetch
anything removes that risk entirely. Some coverage is traded for that guarantee.

**Domain names are validated before they reach a subprocess.** `normalize_name()`
enforces a strict hostname pattern, and `dig` is invoked with an argument vector
and never a shell.

**Key material is elided from reports.** DKIM public keys are public by
definition, but 392-character base64 blobs make JSON reports unreadable, so
`p=` and the signature `b=`/`bh=` values are summarised rather than echoed.

**Findings are facts, not opinions.** Each has a stable code, a severity that
reflects what Gmail will actually do, and a citation. `SPF_TOO_MANY_LOOKUPS` is
a blocker because SPF genuinely returns permerror; `MTA_STS_MISSING` is
informational because Gmail does not require it.

---

## Development

Use pytest to collect both InboxReady's unittest cases and the detector/web
tests. The suite includes real multi-process SQLite writers, rollback,
shared rate limiting, audit cancellation, and offline fixtures; it does not
need live DNS or external services.

```bash
python -m pip install -r requirements.txt '.[dns]'
python -m pytest tests/ -q
```

```
src/inboxready/
├── models.py        Severity, Finding, CheckResult, AuditReport (score, verdict)
├── dnsresolver.py   Resolver ABC, StaticResolver (fixtures), SystemResolver
├── domains.py       Public suffix handling and DMARC alignment
├── checks/          spf, dkim, dmarc, network, message, reputation
├── audit.py         Orchestration
├── report.py        text / json / markdown renderers
└── cli.py           Argument parsing and exit codes
```

Fixtures are plain JSON maps of name → record type → answers, so new scenarios
need no code:

```json
{
  "example.com": { "TXT": ["v=spf1 include:_spf.google.com -all"] },
  "_dmarc.example.com": { "TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"] }
}
```

---

## Limitations

- **DKIM signatures are not cryptographically verified.** Key presence, format,
  size, and `d=` alignment are checked; verifying the signature would require
  the exact bytes as received.
- **Actual complaint rates live in Postmaster Tools.** Only Google has them.
  `--spam-rate` and `--daily-volume` are operator-supplied inputs.
- **The public suffix list is approximated** unless `--public-suffix-list` is
  given. When the built-in table is used, the DMARC output says so.

---

## Licence

MIT.

---

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

### Architecture

The scoring heuristics are the easy part; the moderation system around them is
what makes decisions defensible. The package is layered so each concern is
testable on its own:

| Module | Responsibility |
| --- | --- |
| `normalize.py` | Fold evasion: homoglyphs, invisible characters, letter-spacing, character runs |
| `validation.py` | Reject malformed input before it reaches scoring |
| `policy.py` | Versioned, hashable thresholds and weights; the auto-removal guard |
| `signals.py` | Per-review signals, each with a stable code |
| `dedupe.py` | Near-duplicate detection via MinHash + LSH blocking |
| `engine.py` | Combine signals into a score, a risk level and an action |
| `queue.py` | Persistent human-review queue with claim/resolve and overturn stats |
| `sqlite_store.py` | Multi-worker transactions, indexed queue pages, and atomic queue/audit persistence |
| `audit.py` | Hash-chained decision log that can be verified and replayed |
| `evaluation.py` | Precision/recall measurement and threshold sweeps |
| `calibration.py` | Author-grouped splits, Wilson intervals, prevalence-adjusted precision |

Every decision records the policy version and digest, plus a digest of the
review content, so a decision can be re-derived later and compared against
what was actually served.

#### What the audit log does and does not guarantee

Each record carries the hash of the previous one, so **editing or deleting any
earlier record** is detected, with the line number. A hash chain alone cannot
see **truncation**, though: dropping records off the end leaves a shorter chain
that is still internally consistent, and deleting your own most recent
inconvenient decisions is the obvious insider attack.

So the log is paired with an **anchor** — a sidecar recording how many records
exist and the hash of the last one:

- `verify` compares the log against the anchor and reports a shortfall.
- `append` **refuses to extend a log that does not match its anchor**. Without
  this, truncating and then appending would launder the deletion: the anchor
  would be rewritten to describe the shortened log and every later verify would
  pass.
- When no anchor exists, `verify` reports that truncation *was not checked*
  rather than reporting a pass. `--require-anchor` turns that into a failure.

| Tampering | Detected |
| --- | --- |
| Edit a record's contents | Yes — `record contents do not match record_hash` |
| Delete a record from the middle | Yes — `expected sequence N` |
| Truncate the end of the log | Yes, via the anchor |
| Truncate, then append new records | Yes — the append is refused |
| Delete the log entirely | Yes, via the anchor |
| Truncate *and* rewrite the anchor | **No** — see below |

**The anchor is only as good as where you keep it.** Beside the log it raises
the bar from one edit to two coordinated ones; that is an improvement, not a
guarantee. Pass `--anchor` to place it on append-only or separately
administered storage, which is what makes the check meaningful. Detection is
also not prevention — that is a filesystem and access-control problem, not
something a library can claim to solve.

### Usage

```bash
# Run the test suite
python3 -m pytest tests/ -q

# Score a batch and print a moderation report
python3 -m fake_review_detector.cli score data/sample_reviews.json

# Measure precision/recall against labelled data
python3 -m fake_review_detector.cli evaluate data/labelled_reviews.json

# Ask whether the evidence supports changing the threshold
python3 -m fake_review_detector.cli calibrate data/labelled_reviews.json

# Work the human-review queue, and check the audit log is intact
python3 -m fake_review_detector.cli score data/sample_reviews.json \
    --audit-log decisions.jsonl --queue queue.json
python3 -m fake_review_detector.cli queue --list --queue queue.json
python3 -m fake_review_detector.cli verify --audit-log decisions.jsonl
python3 -m fake_review_detector.cli replay data/sample_reviews.json \
    --audit-log decisions.jsonl
```

For multiple workers, use a SQLite database instead of the single-writer JSON
files. The CLI and web UI can share this database:

```bash
fake-review-detector score data/sample_reviews.json --database .local-data/moderation.sqlite3
fake-review-detector queue --database .local-data/moderation.sqlite3 --list --page-size 50
fake-review-detector queue --database .local-data/moderation.sqlite3 --claim alice --limit 5
fake-review-detector verify --database .local-data/moderation.sqlite3 --require-anchor
fake-review-detector replay data/sample_reviews.json --database .local-data/moderation.sqlite3
```

`--database` replaces `--queue`, `--audit-log`, and file `--anchor` settings.
Scoring logs **every** decision and enqueues new flagged IDs in one transaction.
Submitting an ID again does not reset its claim or moderator outcome, but does
record the new scoring decision in the history. Use `queue --release REVIEW_ID`
to return a claimed item to the pending pool. Listings default to 50 items;
`--offset` and `--state pending|claimed|resolved` select another page or state.
With `score --json`, storage messages go to stderr so stdout remains valid JSON.

Or use it as a library:

```python
from fake_review_detector import Review, moderate_batch

reviews = [
    Review(review_id="1", author="alice", rating=5,
           text="Great, well-made product that has held up over months of use.",
           verified_purchase=True, account_age_days=500, date="2024-01-01"),
]
for decision in moderate_batch(reviews).decisions:
    print(decision.review_id, decision.score, decision.risk_level, decision.action)
```

The original `score_review` / `score_reviews` API still works unchanged.

### Measured behaviour

Numbers below are from this repository on a 2-core CI runner, not estimates.

**Duplicate detection.** The original exhaustive comparison was quadratic,
growing 4x per doubling:

| Reviews | Exhaustive | Blocked (LSH) |
| --- | --- | --- |
| 100 | 1.6 s | — |
| 800 | 104 s | — |
| 2 000 | ~11 min (extrapolated) | 0.6 s |
| 5 000 | ~70 min (extrapolated) | 1.6 s |

A *review bomb* — thousands of near-identical texts — is a different case,
because it genuinely contains a quadratic number of true duplicate pairs. No
candidate-generation scheme changes that, so the number of partners recorded
per review is capped instead: 2 000 near-identical reviews take **2.8 s** and
still flag 1 999 of them, with `DuplicateReport.truncated` set to say the pair
list is deliberately incomplete.

Candidate pairs are now streamed rather than held in a giant set, and duplicate
partners are indexed once instead of rescanning the entire pair list for every
review. The JSON report includes `candidate_pairs`, `compared_pairs`, and
`truncated` so bounded evidence is explicit. The scoring rules and pair order
are unchanged; absence from an approximate or capped report is not proof of
unique text.

**Evasion.** Nine mutations that defeated the original phrase matching —
Cyrillic homoglyphs, fullwidth forms, zero-width spaces, stretched characters,
doubled spaces, and letter-spacing such as `B-e-s-t p-r-o-d-u-c-t e-v-e-r` —
now all normalize to the same matching key and are caught. Homoglyph folding is
applied only to words that *mix* scripts, so genuine non-Latin reviews are not
mangled.

**Accuracy**, against the 174 labelled reviews in `data/labelled_reviews.json`:

```
precision 0.780   recall 0.985   f1 0.871   FPR 0.165
TP 64  FP 18  TN 91  FN 1
```

That precision figure is the honest one for *this set*, and the next section
explains why it is still optimistic for a real one. The labelled set includes
hard negatives — genuine short reviews from new, unverified accounts — and one
of them (`h02`, a real "Highly recommend.") scores **100**, higher than most
actual fakes. Heuristics cannot separate those cases, which is exactly why the
system enqueues for human review rather than deleting.

#### Why this precision number will not survive contact with production

Recall and false-positive rate are properties of the detector. Precision is a
property of the detector *and the population it runs on*, and every published
fake-review corpus — including this one, at 37% fake — is far more balanced
than a real review stream, where the fake share is usually 5–20%.

The same detector, unchanged, at different true prevalence:

| Prevalence | Precision @ threshold 30 | Precision @ threshold 70 |
|---|---|---|
| 37% (this dataset) | 0.78 | 0.96 |
| 20% | 0.60 | 0.92 |
| 10% | 0.40 | 0.84 |
| 5% | **0.24** | 0.71 |

At the default threshold on a 5%-fake stream, roughly **three of every four
flagged reviews would be genuine**. Nothing about the code changed between
those rows. This is the single most important caveat in this README, and it is
invisible if you only ever look at the balanced evaluation set.

`calibrate` reports this projection using the *upper* confidence bound on the
false-positive rate, so a test split that happens to contain zero false
positives cannot be read as a promise of zero false positives in production.

### Calibrating the threshold

```bash
python3 -m fake_review_detector.cli calibrate data/labelled_reviews.json
```

The command splits the labelled data **by author**, picks a threshold on the
training half, and reports it on the held-out half. Splitting by author rather
than by review is deliberate: fake reviews arrive in bursts from one account,
so a per-review split puts one farm's output on both sides and scores the
detector on text it has effectively already seen.

Each half is scored independently, so duplicate evidence cannot leak across
the split. Rejected duplicate IDs cannot overwrite accepted rows' labels.
A recommendation also requires the candidate's precision interval to be
above the incumbent's, not merely different; the `precision_at_recall`
objective must meet its recall floor on held-out data too.

It exits non-zero unless the evidence supports a change, and on the current
dataset it always will:

```
VERDICT: threshold 65 looks better than 30, but the test split is too small to
act on. Treat this as a reason to collect more labelled data, not as a licence
to change the default.
```

This is the intended behaviour, not a limitation to work around. Threshold 65
does look better here, but with 95 test reviews the confidence intervals are
wide enough that the ranking could easily reverse on different data — and
`medium_threshold` also drives risk banding, so it is not a free knob. The
default stays at 30 until there is data that can justify moving it.

To get such data, `data/README.md` lists the public corpora, their sizes, and
— importantly — their licences. Only one of the six is redistributable, which
is why none are vendored here.

### Limitations

- **Heuristics, not ground truth.** Nothing here proves a review is fake. At
  the default threshold roughly one in six genuine reviews in the labelled set
  is flagged, so output is a work queue, not a verdict.
- **The labelled set cannot validate this detector.** All 174 reviews were
  hand-written for this repository by the same author who wrote the rules, so
  they encode one person's idea of what a fake review looks like. Its honest
  purpose is regression testing — catching the day a change stops detecting
  something it used to. Treat the accuracy numbers as a floor on a friendly
  set, never as evidence of field performance.
- **Auto-removal is off by default.** `Policy.allow_auto_removal` is `False`,
  and `action_for()` downgrades a removal to an enqueue unless it is explicitly
  enabled. The `h02` case above is why.
- **No identity or graph signals.** Real review-farm detection leans on device,
  payment and network-graph evidence that a text-only tool cannot see.
- **JSON queue/log files are single-writer.** SQLite supports concurrent workers
  on one host, but still serializes writes. It is not a multi-host database.
- **Duplicate pair lists are capped** in dense clusters, as described above.
- **The phrase table covers 15 languages, not all of them.** A farm operating
  in an untranslated language still evades the phrase signal, though the
  duplicate, burst and account-age signals remain language-independent. Entries
  deliberately exclude bare praise like "good product": an early draft included
  the Russian "отличный товар", which flags the entirely ordinary review
  "Отличный товар, доставка быстрая".
- **Language attribution in evidence is approximate.** The evasion defence that
  folds "Bessst" to "best" also folds Spanish "estrellas" to "estrelas", so
  closely related languages can cross-attribute. The phrase match is still
  correct; only the reported language may be.

### Project layout

- `fake_review_detector/` — the moderation package (modules listed above)
- `fake_review_detector/detector.py` — compatibility shim for the original API
- `fake_review_detector/cli.py` — command-line entry point
- `data/sample_reviews.json` — example batch of genuine + fake reviews
- `data/labelled_reviews.json` — 174 labelled reviews used for evaluation
- `data/README.md` — provenance of that set, and where to obtain real corpora
- `tests/` — unit tests, including `test_production_hardening.py`, which pins
  each measured gap above as a regression test
- `RESEARCH.md` — the research behind the problem this project showcases

---

## Web UI (optional)

Both tools also run behind a small web front end that wraps the same library
calls the command line uses — `inboxready.audit()` and
`moderate_batch()`. It adds no detection logic of its own, so what the browser
shows is exactly what the CLI would print.

Flask is an **optional extra**, never a runtime dependency. Both packages still
import with no third-party code installed, and CI asserts it.

```bash
pip install '.[web]'
python3 -m webui
# then open http://127.0.0.1:8000
```

From a checkout without installing:

```bash
PYTHONPATH=src python3 -m webui
```

The installed wheel includes the same demo fixtures, messages, sample reviews,
templates, and CSS as a checkout. Three pages: an InboxReady audit form, a
review-batch scorer, and a paginated moderation queue where you claim or release
an item, mark it upheld or overturned, and watch the
overturn rate — the number that says whether the scores are worth trusting.

### Settings

All are environment variables. The defaults are the safe ones.

| Variable | Default | What it does |
| --- | --- | --- |
| `SECRET_KEY` | random per start in demo/file modes | Signs the session cookie. Required and shared across workers in SQLite mode. There are no application logins. |
| `LIVE_DNS` | `0` | Allow audits of real domains. Off by default. |
| `STORAGE` | `memory` | `memory`, `file`, or `sqlite`. See below. |
| `DATA_DIR` | — | Required for `file` and `sqlite`; use a persistent local directory. |
| `DEMO_DIR` | checkout examples or packaged demos | Optional override for fixtures and example messages. |
| `MAX_UPLOAD_BYTES` | `262144` | Cap on an uploaded `.eml` or review batch. |
| `MAX_REVIEWS` | `200` | Reviews accepted per batch. |
| `DNS_QUERY_BUDGET` | `120` | Queries one audit may issue before it is abandoned. |
| `DNS_TIMEOUT` | `3.0` | Seconds per DNS query. Lower than the CLI's, because a browser is waiting. |
| `AUDIT_DEADLINE` | `25.0` | Seconds one audit may take. |
| `AUDIT_WORKERS` | `4` | Maximum admitted audits per WSGI process; excess work gets HTTP 503 instead of an unbounded backlog. |
| `QUEUE_PAGE_SIZE` | `50` | Queue items rendered per page; maximum 200. |
| `SQLITE_TIMEOUT` | `5.0` | Seconds to wait for another database writer before a retryable storage error. |
| `RATE_LIMIT_PER_MINUTE` | `6` | Live-DNS audits per client per minute. |
| `RATE_LIMIT_BURST` | `3` | How many of those may arrive at once. |
| `TRUSTED_PROXY_HOPS` | `0` | Reverse proxies in front of the app. Leave at 0 unless there really are some. |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Where `python3 -m webui` listens. |

### Deploying it: read this part

The interesting constraints are not hypothetical.

**Choose persistence explicitly.** Audit history must survive process restarts,
and concurrent workers must not overwrite each other's queue:

- `STORAGE=memory` (the default) writes nothing. The queue is lost on restart
  and different workers have different queues. This is a local demonstration,
  not a shared moderation service.
- `STORAGE=file` preserves the legacy `queue.json` and anchored
  `decisions.jsonl` files. It needs a persistent volume and **exactly one
  writer**, including CLI access. Separate workers or simultaneous CLI/web
  writes are not safe.
- `STORAGE=sqlite` writes `DATA_DIR/moderation.sqlite3`. WAL mode, short
  transactions, indexed queue reads, and atomic claims support multiple
  processes on **one host**. Queue changes, decision records, and the audit
  head commit together; failed writes roll back. Every worker needs the same
  `DATA_DIR` and `SECRET_KEY`.

SQLite must live on a persistent **local** filesystem, not NFS or a shared
network volume. It is not horizontal multi-host scaling, and ephemeral
serverless disks are not durable storage. For multi-host deployment, use a
server database and a shared job service instead.

Switching to SQLite does not import or delete existing JSON files. Keep
`STORAGE=file` for existing queue state until an explicit data migration is
planned; rescoring the original reviews into SQLite does not migrate human
claims or outcomes.

The SQLite audit head lives in the same transaction as the records. It detects
inconsistent edits or truncation, **not** someone rewriting or rolling back
the entire database and its head together. Keep independently administered
backups/checkpoints for that threat. Queue pages show counts without scanning
all historical decisions; use **Check audit integrity** or the CLI `verify`
command for a full, streaming scan.

**Live DNS is a free scanning service** for anyone who finds the URL. It is off
unless you set `LIVE_DNS=1`. When on, each client gets a token bucket and each
audit gets a hard query budget and a wall-clock deadline. Admission to the
audit pool is bounded: HTTP 503 means it is full, HTTP 504 means the deadline
expired, and HTTP 429 includes a retry delay for a rate limit. Expired audits
cancel subsequent DNS work, and each outstanding lookup is timeout-bounded.
SQLite mode shares rate-limit buckets across workers and restarts; memory/file
mode limits are per process. The tool makes no outbound HTTP requests.

**Uploads may be someone's real mail.** They are size-capped before the body is
read, processed in memory, never written to disk, and never logged.

**There is no authentication.** Anyone who can reach the app can work the
queue. Moderator names are attribution labels, not authenticated ownership.
Bind to loopback and put an identity-aware HTTPS proxy in front of any shared
deployment. Only set `TRUSTED_PROXY_HOPS` to the actual trusted proxy count.

### Where to run it

| Option | Storage | Notes |
| --- | --- | --- |
| Locally | any | `python3 -m webui` for development only. |
| One host with a persistent local volume | `sqlite` | Multiple WSGI workers share durable state and rate limits. |
| One process with a persistent volume | `file` | Legacy operation; no concurrent CLI writer. |
| Ephemeral/serverless instances | `memory` only | Demo only: each process has its own disposable queue. |
| A static page of pre-generated fixture output | none | Zero cost, zero attack surface, if the point is only to show the work. |

For the supported multi-worker deployment:

```bash
python -m pip install '.[server,dns]'
export STORAGE=sqlite
export DATA_DIR="$PWD/.local-data" # use your mounted persistent directory in production
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
gunicorn --bind 127.0.0.1:8000 --workers 2 --threads 4 --timeout 60 'webui:create_app()'
```

Generate the key once and save it in your deployment's secret store; do not
regenerate it on every restart. `/healthz` is process liveness; `/readyz` also
checks that moderation storage is accessible and returns HTTP 503 if it is not.
Keep the WSGI timeout above `AUDIT_DEADLINE` and `SQLITE_TIMEOUT`. Gunicorn is
for Unix-like servers; both CLIs and the development UI remain portable.

Back up a live SQLite database through SQLite's backup API, **not** by copying
only the `.sqlite3` file while its WAL is active:

```bash
python - <<'PY'
import os
import sqlite3
from pathlib import Path

source = Path(os.environ["DATA_DIR"]).resolve() / "moderation.sqlite3"
with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as db:
    with sqlite3.connect("moderation-backup.sqlite3") as backup:
        db.backup(backup)
PY
fake-review-detector verify --database moderation-backup.sqlite3 --require-anchor
```
