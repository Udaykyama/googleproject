# googleproject

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

Requires Python 3.10+. There are no required dependencies.

```bash
pip install .
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

```bash
python3 -m unittest discover -s tests -t tests
```

226 tests, no test dependencies, runs in well under a second.

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
