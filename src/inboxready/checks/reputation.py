"""Bulk-sender classification and Postmaster Tools spam-rate thresholds.

Google's requirements are tiered: a small set applies to everyone, and a
stricter set applies to "bulk senders". The definition is a cliff edge — cross
5,000 messages to personal Gmail accounts in any single 24-hour period and the
status is permanent, even if volume later drops.

Spam complaint rate, as reported by Postmaster Tools, is the other hard number:
stay under 0.10%, and never reach 0.30%.
"""

from __future__ import annotations

from ..models import CheckResult, Finding, Severity

__all__ = ["check_reputation", "BULK_SENDER_THRESHOLD", "SPAM_RATE_TARGET", "SPAM_RATE_LIMIT"]

#: Messages per 24h to personal Gmail accounts that make a domain a bulk sender.
BULK_SENDER_THRESHOLD = 5_000
#: Google's stated target: keep the reported spam rate below 0.10%.
SPAM_RATE_TARGET = 0.10
#: Google's hard threshold: never reach 0.30%.
SPAM_RATE_LIMIT = 0.30


def check_reputation(
    daily_volume: int | None = None,
    spam_rate: float | None = None,
    bulk: bool | None = None,
) -> CheckResult:
    """Classify the sender and grade its spam complaint rate.

    ``spam_rate`` is a percentage as Postmaster Tools reports it, so ``0.25``
    means 0.25%, not 25%.
    """

    result = CheckResult(name="reputation")

    if daily_volume is None and spam_rate is None and bulk is None:
        result.skipped_reason = (
            "no volume or spam-rate supplied (pass --daily-volume / --spam-rate from "
            "Postmaster Tools)"
        )
        return result

    is_bulk = bulk
    if is_bulk is None and daily_volume is not None:
        is_bulk = daily_volume >= BULK_SENDER_THRESHOLD

    result.data["daily_volume"] = daily_volume
    result.data["spam_rate_percent"] = spam_rate
    result.data["bulk_sender"] = is_bulk
    result.data["bulk_sender_threshold"] = BULK_SENDER_THRESHOLD

    if daily_volume is not None and daily_volume < 0:
        result.add(
            Finding(
                code="REP_VOLUME_INVALID",
                title="Daily volume cannot be negative",
                severity=Severity.WARNING,
                detail=f"Got {daily_volume}.",
                remediation="Supply the number of messages sent to Gmail in 24 hours.",
                reference="",
            )
        )
        return result

    if is_bulk:
        result.add(
            Finding(
                code="REP_BULK_SENDER",
                title="Classified as a bulk sender",
                severity=Severity.INFO,
                detail=(
                    (
                        f"{daily_volume:,} messages/day is at or above the "
                        f"{BULK_SENDER_THRESHOLD:,} threshold. "
                        if daily_volume is not None
                        else ""
                    )
                    + "Bulk status is permanent once reached, so DMARC and one-click "
                    "unsubscribe are mandatory from now on."
                ),
                remediation="Treat every bulk-sender requirement in this report as blocking.",
                reference="Google sender guidelines",
            )
        )
    elif daily_volume is not None:
        headroom = BULK_SENDER_THRESHOLD - daily_volume
        if headroom <= BULK_SENDER_THRESHOLD * 0.2:
            result.add(
                Finding(
                    code="REP_NEAR_BULK_THRESHOLD",
                    title="Close to the bulk-sender threshold",
                    severity=Severity.WARNING,
                    detail=(
                        f"{daily_volume:,} messages/day leaves only {headroom:,} before the "
                        f"{BULK_SENDER_THRESHOLD:,} threshold. A single campaign can cross it, "
                        "and the classification never reverts."
                    ),
                    remediation="Meet the bulk-sender requirements before you need to.",
                    reference="Google sender guidelines",
                )
            )

    if spam_rate is None:
        result.add(
            Finding(
                code="REP_NO_SPAM_RATE",
                title="No spam complaint rate supplied",
                severity=Severity.INFO,
                detail=(
                    "Spam rate is the single metric Google acts on most directly, and it is "
                    "only visible in Postmaster Tools."
                ),
                remediation=(
                    "Register the domain at postmaster.google.com and rerun with --spam-rate."
                ),
                reference="Google Postmaster Tools",
            )
        )
        return result

    if spam_rate < 0:
        result.add(
            Finding(
                code="REP_SPAM_RATE_INVALID",
                title="Spam rate cannot be negative",
                severity=Severity.WARNING,
                detail=f"Got {spam_rate}.",
                remediation="Supply the percentage shown in Postmaster Tools, e.g. 0.08.",
                reference="",
            )
        )
        return result

    if spam_rate >= SPAM_RATE_LIMIT:
        result.add(
            Finding(
                code="REP_SPAM_RATE_CRITICAL",
                title=f"Spam complaint rate is {spam_rate:.2f}%",
                severity=Severity.BLOCKER,
                detail=(
                    f"At or above {SPAM_RATE_LIMIT:.2f}% Google withdraws delivery mitigations "
                    "and mail is filtered or rejected. Recovery takes weeks of clean sending, "
                    "not a configuration change."
                ),
                remediation=(
                    "Stop sending to unengaged and purchased lists immediately, honour "
                    "unsubscribes within 48 hours, and segment by recent engagement."
                ),
                reference="Google sender guidelines; Postmaster Tools",
            )
        )
    elif spam_rate > SPAM_RATE_TARGET:
        result.add(
            Finding(
                code="REP_SPAM_RATE_ELEVATED",
                title=f"Spam complaint rate is {spam_rate:.2f}%",
                severity=Severity.CRITICAL,
                detail=(
                    f"Google's stated target is below {SPAM_RATE_TARGET:.2f}%, and the hard "
                    f"threshold is {SPAM_RATE_LIMIT:.2f}%. Rates in this band usually keep "
                    "climbing as list quality decays."
                ),
                remediation="Suppress unengaged recipients and make unsubscribing effortless.",
                reference="Google sender guidelines; Postmaster Tools",
            )
        )
    else:
        result.add(
            Finding(
                code="REP_SPAM_RATE_OK",
                title=f"Spam complaint rate is {spam_rate:.2f}%",
                severity=Severity.PASS,
                detail=f"Below Google's {SPAM_RATE_TARGET:.2f}% target.",
                remediation="",
                reference="Google Postmaster Tools",
            )
        )

    return result
