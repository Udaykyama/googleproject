# Research: what is Google actually trying to fix right now?

This document is the research phase that produced **InboxReady**. It records what
was investigated, what the evidence showed, which problem was selected, and why.

All figures below are cited. Where a number comes from a secondary aggregator
rather than Google directly, that is stated.

---

## 1. Method

Four parallel lines of enquiry:

1. **News and articles** — what is Google shipping, enforcing, or publicly
   struggling with in late 2025 / 2026.
2. **Official Google documentation** — support pages, developer guides,
   deprecation notices. These are the load-bearing sources, because they state
   requirements Google actually enforces.
3. **Google job postings** — what Google is *paying people to fix* is the most
   honest signal of what Google considers unsolved.
4. **Impact data** — how many users and organisations are affected, and what it
   costs them.

---

## 2. What the job postings say

Job descriptions are the least-marketed artefact a company produces. Three
postings were the most informative.

### 2a. Senior Software Engineer, Gmail Abuse and Safety Protections

Job ID `122568463024562886` · Sunnyvale, CA · $174,000–$252,000 + bonus + equity
<https://www.google.com/about/careers/applications/jobs/results/122568463024562886>

> "Leverage machine learning, advanced analysis, and big data infrastructure to
> detect, investigate, and prevent a wide variety of abuse types (like spam,
> phishing, fraud) in real-time for billions of users."

> "Assess threats to Gmail users from new disruptive technologies like
> Generative AI (GenAI) and proactively design and implement robust safeguards
> to address those emerging threats."

The tension in this role: generative AI is simultaneously Google's best new
defence *and* the attacker's best new weapon. Phishing that used to be
identifiable by broken grammar is now fluent, personalised, and cheap.

### 2b. Engineering Manager, Egregious Abuse Protection

San Jose, CA ·
<https://jobs.asugsvsummit.com/companies/google-24698/jobs/91511024-engineering-manager-egregious-abuse-protection>

> "Oversee the development and deployment of abuse-fighting technologies, which
> include heuristics, advanced machine learning models, and large-scale data
> analysis systems."

> "Integrate generative AI tools or large language model (LLM) interfaces into
> workflows where applicable."

### 2c. Senior Engineering Analyst — Trust & Safety, Egregious Harms

<https://www.google.com/about/careers/applications/jobs/results/134403138571379398>

An analyst-track counterpart to the engineering roles: anti-abuse data analysis,
trend identification, content policy work alongside engineering.

**Read across all three:** Google's anti-abuse organisation is hiring to rebuild
detection for an era where content-based signals are cheap for attackers to
fake. When you cannot trust *what a message says*, you fall back on *who
provably sent it*. That is cryptographic sender authentication — and it is
exactly what Google spent 2024–2025 forcing onto the entire email ecosystem.

---

## 3. The problem selected: Gmail's bulk sender enforcement

### 3a. What Google mandated

Source: [Gmail Email sender guidelines](https://support.google.com/mail/answer/81126)
and the [sender guidelines FAQ](https://support.google.com/mail/answer/14229414).

| Requirement | All senders | Bulk senders (≥5,000/day) |
| --- | --- | --- |
| SPF **or** DKIM | Required | — |
| SPF **and** DKIM | — | Required |
| DMARC record | — | Required (`p=none` accepted as a floor) |
| SPF or DKIM domain aligned with `From:` | Required | Required |
| TLS for inbound connections | Required | Required |
| Valid forward-confirmed reverse DNS (FCrDNS) | Required | Required |
| RFC 8058 one-click unsubscribe | — | Required |
| Unsubscribes honoured within 48 hours | — | Required |
| Spam complaint rate below 0.30% | Required | Required |
| RFC 5322 formatting, no Gmail `From:` impersonation | Required | Required |

Two details make this much sharper than it first appears:

- **Bulk sender status is permanent.** Cross 5,000 messages to personal Gmail
  addresses on a single day and the domain is a bulk sender from then on.
- **The spam-rate numbers are two different numbers.** Google asks senders to
  stay under **0.10%** and describes **0.30%** as the level that must never be
  reached. Sitting between them is not "passing"; it is a warning.

### 3b. The enforcement timeline — why this is live, not historical

| Date | What happened |
| --- | --- |
| Oct 2023 | Requirements announced |
| Feb 2024 | Requirements take effect; non-compliant mail gets warnings |
| Jun 2024 | Rejection of a percentage of non-compliant traffic begins |
| Jun 2024 | One-click unsubscribe becomes mandatory for bulk senders |
| **Nov 2025** | **Permanent SMTP `5.7.x` rejection of non-compliant mail** |
| End of 2025 | Postmaster Tools **v1 API and dashboard shut down** |

The November 2025 step is the one that matters. Before it, a misconfigured
sender saw degraded inbox placement. After it, the mail is refused at the SMTP
layer and never exists in the recipient's account.

Google is not alone. Microsoft applied equivalent requirements to
Outlook/Hotmail from May 2025, Apple tightened iCloud Mail in late 2024, and
Yahoo moved in lockstep with Google in 2024. Practitioners now refer to this
bloc as **MAGY** (Microsoft, Apple, Google, Yahoo). A domain failing Google's
rules is very likely failing all four.

### 3c. Postmaster Tools v2 — Google removed the scores on purpose

Sources:
[migration guide](https://developers.google.com/workspace/gmail/postmaster/guides/migration-v2),
[deprecation notice](https://support.google.com/mail/answer/16594218).

Google **deleted** the Domain Reputation and IP Reputation dashboards — the
familiar High / Medium / Low / Bad bars — and replaced them with a **Compliance
Status** dashboard showing explicit pass/fail for SPF, DKIM, DMARC, one-click
unsubscribe, and spam complaint rate.

The stated rationale is that the old scores were misleading, gave a false sense
of security, and lagged real sender behaviour. Practically: reputation scores
were gameable, and compliance facts are not.

**This is the single most important finding for the project.** Google has
declared that the thing worth measuring is *verifiable, deterministic
compliance with published standards*. That is precisely the kind of thing a tool
can check.

### 3d. Who is affected

| Metric | Value | Source |
| --- | --- | --- |
| Gmail users | ~3 billion | emailanalytics.com, Jan 2026 |
| Spam/phishing/malware blocked daily | ~15 billion messages | Google |
| Phishing messages blocked daily | ~100 million | aag-it.com |
| Gmail spam block rate | >99.9% | Google |
| Global spam volume | ~45.6 billion/day (~65% of all email) | worldmetrics.org |

And the cost of the attacks these rules exist to stop, from the
[FBI IC3 2024 Annual Report](https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf):

| Metric | 2024 |
| --- | --- |
| Business Email Compromise losses | **$2.77 billion** |
| BEC incidents reported | 21,442 |
| Cumulative BEC losses 2022–2024 | $8.5 billion |
| All internet crime losses | $16.6 billion (+33% YoY) |

The sending side is where the pain lands. Every organisation that sends
newsletters, receipts, password resets, or notifications to Gmail addresses is
in scope, and the failure modes are unglamorous: an SPF record that quietly
exceeded ten DNS lookups after a vendor was added, a DKIM key rotated in the
signer but not in DNS, a `List-Unsubscribe` header without the
`List-Unsubscribe-Post` line that RFC 8058 requires.

None of these are visible from the sender's own inbox. All of them are visible
in DNS and in the message source.

---

## 4. The alternative that was considered and rejected

The research also surfaced **indirect prompt injection in agentic AI** as a
problem Google publicly admits it has not solved:

- Google DeepMind, *Lessons from Defending Gemini Against Indirect Prompt
  Injections* — [arXiv:2505.14534](https://arxiv.org/abs/2505.14534)
- [Advancing Gemini's security safeguards](https://deepmind.google/blog/advancing-geminis-security-safeguards/)
- [Google's layered prompt-injection defence](https://blog.google/security/mitigating-prompt-injection-attacks/)
- EchoLeak, CVE-2025-32711, CVSS 9.3 — the first documented zero-click indirect
  prompt injection in a production LLM system

Google's own words: baseline defences such as Spotlighting and Self-reflection
"became much less effective against adaptive attacks", and models with tool
access "remain fundamentally at risk as long as they must process untrusted
input."

It is a genuinely open problem, and that is exactly why it was rejected as a
build target. There is no specification to check against and no ground truth to
test, so any demo would amount to a heuristic with an unfalsifiable success
claim.

The Gmail sender problem is the opposite in every respect:

| | Prompt injection | Gmail sender compliance |
| --- | --- | --- |
| Ground truth | Contested | Published RFCs + Google's own docs |
| Verifiable | Statistically, at best | Deterministically |
| Testable offline | Not really | Completely |
| Currently causing damage | Emerging | Yes, since November 2025 |
| Fixable by the affected party | No | Yes, usually in under a day |

---

## 5. What was built, and how it maps to the research

**InboxReady** audits a sending domain and a raw message against the rules
above, and reports what would get the mail rejected.

| Research finding | Implementation |
| --- | --- |
| SPF and DKIM both required for bulk senders | `checks/spf.py`, `checks/dkim.py` |
| Ten-DNS-lookup SPF limit (RFC 7208 §4.6.4) — the most common silent failure | `_count_lookups()`, recursive and cycle-safe |
| DKIM keys must exist, be ≥1024-bit, not be revoked or in test mode | DER parser in `checks/dkim.py`, no external crypto dependency |
| DMARC required, aligned with `From:` | `checks/dmarc.py`, with organisational-domain fallback and `sp=` handling |
| FCrDNS required | `checks/network.py`, forward-confirms every PTR |
| RFC 8058 one-click unsubscribe | `checks/message.py`, checks `List-Unsubscribe-Post` and HTTPS, not just the header's presence |
| Spam rate 0.10% target / 0.30% limit | `checks/reputation.py`, banded as pass / elevated / critical |
| Bulk status is permanent above 5,000/day | `checks/reputation.py`, warns *before* the threshold is crossed |
| Postmaster Tools v2 replaced scores with compliance facts | The whole tool: every finding is a checkable fact with an RFC citation, never a score-like opinion |

The tool deliberately reports **what Gmail will do**, not a vague grade. Each
finding carries a severity, the specific standard it derives from, and the
remediation.

---

## 6. Honest limitations

- **DNS and message content only.** InboxReady cannot see a sender's actual
  complaint rate, IP warm-up history, or engagement metrics — those live in
  Postmaster Tools and only Google has them. Where volume and spam rate matter,
  they are inputs the operator supplies.
- **No cryptographic signature verification.** InboxReady checks that a DKIM
  key is present, correctly formed, adequately sized, and that `d=` aligns with
  `From:`. It does not verify the signature itself, which would require the
  exact bytes as received.
- **The public suffix list is approximated** by default. Organisational-domain
  boundaries use a built-in table covering common multi-label suffixes; pass
  `--public-suffix-list` with the Mozilla list for authoritative results. When
  the built-in table is in use, the DMARC output says so.
- **No HTTP requests, ever.** MTA-STS policy files and BIMI logos are not
  fetched, only their DNS records are checked. This is a deliberate trade of
  completeness for the guarantee that auditing a hostile domain cannot be turned
  into a server-side request forgery.

---

## 7. Sources

**Google, primary**

- Gmail email sender guidelines — <https://support.google.com/mail/answer/81126>
- Sender guidelines FAQ — <https://support.google.com/mail/answer/14229414>
- Postmaster Tools v2 migration — <https://developers.google.com/workspace/gmail/postmaster/guides/migration-v2>
- Postmaster Tools v1 deprecation — <https://support.google.com/mail/answer/16594218>
- Senior SWE, Gmail Abuse and Safety Protections — <https://www.google.com/about/careers/applications/jobs/results/122568463024562886>
- Advancing Gemini's security safeguards — <https://deepmind.google/blog/advancing-geminis-security-safeguards/>
- Mitigating prompt injection attacks — <https://blog.google/security/mitigating-prompt-injection-attacks/>
- Workspace approach to indirect prompt injection — <https://blog.google/security/google-workspaces-continuous-approach-to-mitigating-indirect-prompt-injections/>

**Standards**

- RFC 7208 — Sender Policy Framework
- RFC 6376 — DomainKeys Identified Mail
- RFC 7489 — DMARC
- RFC 8058 — One-click functionality for List-Unsubscribe
- RFC 8460 — SMTP TLS Reporting
- RFC 8461 — SMTP MTA Strict Transport Security
- RFC 5322 — Internet Message Format
- RFC 8617 — Authenticated Received Chain

**Research and reporting**

- arXiv:2505.14534 — Lessons from Defending Gemini Against Indirect Prompt Injections
- arXiv:2509.10540 — EchoLeak (CVE-2025-32711)
- FBI IC3 2024 Annual Report — Business Email Compromise
- Engineering Manager, Egregious Abuse Protection — <https://jobs.asugsvsummit.com/companies/google-24698/jobs/91511024-engineering-manager-egregious-abuse-protection>

*Research compiled 30 August 2026. Statistics reflect the most recent figures
available at that date; the enforcement requirements are the operative ones as
published by Google.*

---

## Fake Review Detector research


This document summarizes the research behind the `fake_review_detector` showcase
project in this repository. The goal was to pick a real, well-documented problem
that Google is actively trying to fix, understand how many users are affected,
and check what Google's own job postings say about how the company staffs
people to solve it.

### The problem

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

### Who is affected

- **Consumers/users**: hundreds of millions of people rely on Google Maps
  and Search reviews to make everyday purchasing decisions; fake reviews
  directly distort those decisions.
- **Small businesses**: legitimate businesses can be unfairly harmed by
  competitor review-bombing, or lose customers to rivals who buy fake
  5-star reviews.
- **Platform trust**: at scale (hundreds of millions of reviews touched
  per year), unresolved fake reviews erode trust in the platform itself.

### How Google staffs the fight (job postings)

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

### Why this project

Given the scale (hundreds of millions of reviews affected per year) and the
fact that this is a problem Google is *actively, publicly* trying to solve
with a mix of policy and automated detection, this repository implements a
small, self-contained **showcase** of the detection side of that problem:
a rule-based **Fake Review Detector** that scores individual reviews and
whole batches for the same kinds of signals real Trust & Safety teams look
for (see `README.md` for usage).

### From demonstration to moderation system

The detector began as an illustration of those signals. Detection signals
alone, though, are the part of content moderation that is *least* contested;
what determines whether a system can be operated is everything around them.
The package was therefore extended into a moderation system proper:

- **Adversarial input is assumed.** Nine text mutations defeated the original
  phrase matching, including Cyrillic homoglyphs and letter-spacing. Matching
  now runs on a normalized key. Homoglyph folding is restricted to words that
  mix scripts, because folding indiscriminately would corrupt genuine
  non-Latin reviews — the same reasoning Chrome applies to IDN display.
- **Decisions are reviewable.** Every decision carries a stable signal code, a
  policy version and digest, and a content digest, appended to a hash-chained
  log that can be verified and replayed. A moderation decision that cannot be
  explained after the fact cannot be appealed.
- **Removal is not automatic.** Measuring against labelled data — including
  hard negatives — showed a genuine review ("Highly recommend.", new
  unverified account) scoring 85, above several real fakes. That is a
  structural limit of text heuristics, not a tuning error, so high-scoring
  reviews are enqueued for human review rather than deleted. This mirrors
  Google's own framing when it retired Postmaster Tools' reputation scores in
  favour of deterministic compliance signals (§3c): a score that cannot be
  acted on unambiguously should not be presented as if it can.
- **Cost is bounded under attack.** Duplicate detection was quadratic, which a
  review bomb turns into a denial-of-service. Blocking made the normal case
  sub-quadratic; a per-review partner cap bounds the pathological case, since
  a bomb of n identical reviews genuinely contains a quadratic number of true
  duplicate pairs.

`README.md` records the measured numbers, and the limitations that remain.
