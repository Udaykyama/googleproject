"""InboxReady, wrapped for a browser.

The audit logic is untouched; this module only supplies the guard rails a
public endpoint needs and that a CLI does not:

* a **query budget**, so one pathological SPF chain cannot issue unbounded DNS
  traffic on a visitor's behalf;
* a **deadline**, enforced on a worker thread so a slow resolver returns an
  error rather than pinning the request;
* **input validation** ahead of any resolution, reusing InboxReady's own strict
  hostname check — the same one that keeps names away from ``dig``'s argv.

Fixtures are restricted to the bundled demo set. A user-supplied fixture path
would be a file-read primitive, so the form offers a fixed list by name and
never accepts a path.
"""

from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path

from inboxready import audit as run_inboxready_audit
from inboxready.dnsresolver import (
    DnsError,
    Resolver,
    StaticResolver,
    SystemResolver,
    is_valid_hostname,
)
from inboxready.domains import PublicSuffixList

from .config import AppConfig

__all__ = [
    "AuditRequest",
    "AuditProblem",
    "DemoAssets",
    "AuditService",
    "MODE_FIXTURE",
    "MODE_OFFLINE",
    "MODE_LIVE",
]

MODE_FIXTURE = "fixture"
MODE_OFFLINE = "offline"
MODE_LIVE = "live"

_MODES = {MODE_FIXTURE, MODE_OFFLINE, MODE_LIVE}

#: DKIM selectors are DNS labels. Restricting them here keeps a hostile
#: selector from being concatenated into a name that is then resolved.
_SELECTOR_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,62})$")

#: Names of demo assets, so a request can never name a path.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_MAX_SELECTORS = 8
_MAX_IPS = 8
_MAX_DAILY_VOLUME = 10_000_000_000


class AuditProblem(ValueError):
    """A user-facing problem with the submitted form."""


class QueryBudgetExceeded(Exception):
    """The audit issued more DNS queries than the deployment permits.

    Deliberately **not** a :class:`~inboxready.dnsresolver.DnsError`: each check
    catches ``DnsError`` and degrades gracefully, which is right for a single
    failed lookup and wrong for an exhausted budget. This one propagates and
    aborts the run.
    """


class _BudgetedResolver(SystemResolver):
    """A live resolver that refuses to exceed a fixed number of queries."""

    def __init__(self, budget: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self.budget = budget

    def _lookup(self, name: str, rrtype: str) -> list[str]:
        # ``Resolver.query`` increments the counter before delegating here, and
        # serves cache hits without delegating, so this counts real queries.
        if self.query_count > self.budget:
            raise QueryBudgetExceeded(
                f"this audit exceeded the {self.budget}-query limit for the "
                "hosted version. Run the command-line tool for an "
                "unrestricted audit."
            )
        return super()._lookup(name, rrtype)


@dataclass(frozen=True)
class DemoAssets:
    """The bundled fixtures and messages the demo mode can offer."""

    fixtures: dict[str, Path] = field(default_factory=dict)
    messages: dict[str, Path] = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return bool(self.fixtures)

    @classmethod
    def discover(cls, config: AppConfig) -> "DemoAssets":
        return cls(
            fixtures=_index(config.fixtures_dir, ".json"),
            messages=_index(config.messages_dir, ".eml"),
        )


def _index(directory: Path | None, suffix: str) -> dict[str, Path]:
    if directory is None or not directory.is_dir():
        return {}
    found = {}
    for path in sorted(directory.glob(f"*{suffix}")):
        if path.is_file() and _SAFE_NAME_RE.match(path.stem):
            found[path.stem] = path
    return found


@dataclass(frozen=True)
class AuditRequest:
    """A validated audit request. Constructing one proves it is safe to run."""

    mode: str
    domain: str | None = None
    fixture: str | None = None
    selectors: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    daily_volume: int | None = None
    spam_rate: float | None = None
    transactional: bool = False
    message: bytes | None = None
    message_name: str = ""


def _clean_domain(raw: str) -> str:
    domain = raw.strip().rstrip(".").lower()
    if not domain:
        raise AuditProblem("Enter a domain to audit.")
    if len(domain) > 253:
        raise AuditProblem("That domain name is too long to be valid.")
    if not is_valid_hostname(domain):
        raise AuditProblem(
            f"{domain!r} is not a valid domain name. Use a hostname such as "
            "mail.example.com — not a URL, an email address, or an IP."
        )
    return domain


def _clean_selectors(raw: str) -> tuple[str, ...]:
    selectors = []
    for token in re.split(r"[\s,]+", raw.strip()):
        if not token:
            continue
        if not _SELECTOR_RE.match(token):
            raise AuditProblem(
                f"{token!r} is not a valid DKIM selector. Selectors are DNS "
                "labels, e.g. google or s1."
            )
        if token not in selectors:
            selectors.append(token)
    if len(selectors) > _MAX_SELECTORS:
        raise AuditProblem(f"At most {_MAX_SELECTORS} selectors per audit.")
    return tuple(selectors)


def _clean_ips(raw: str) -> tuple[str, ...]:
    ips = []
    for token in re.split(r"[\s,]+", raw.strip()):
        if not token:
            continue
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            raise AuditProblem(
                f"{token!r} is not an IP address. Give the address mail is "
                "sent from, e.g. 203.0.113.25."
            ) from None
        text = str(address)
        if text not in ips:
            ips.append(text)
    if len(ips) > _MAX_IPS:
        raise AuditProblem(f"At most {_MAX_IPS} sending IPs per audit.")
    return tuple(ips)


def _clean_daily_volume(raw: str) -> int | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        value = int(raw.replace(",", "").replace(" ", ""))
    except ValueError:
        raise AuditProblem("Daily volume must be a whole number.") from None
    if value < 0:
        raise AuditProblem("Daily volume cannot be negative.")
    if value > _MAX_DAILY_VOLUME:
        raise AuditProblem("That daily volume is implausibly large.")
    return value


def _clean_spam_rate(raw: str) -> float | None:
    raw = raw.strip().rstrip("%").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        raise AuditProblem(
            "Spam rate must be a percentage, e.g. 0.08 for 0.08%."
        ) from None
    if value != value or value in (float("inf"), float("-inf")):
        raise AuditProblem("Spam rate must be a real number.")
    if not 0.0 <= value <= 100.0:
        raise AuditProblem("Spam rate is a percentage between 0 and 100.")
    return value


class AuditService:
    """Validates audit requests and runs them under the deployment's limits."""

    def __init__(self, config: AppConfig, assets: DemoAssets | None = None) -> None:
        self.config = config
        self.assets = assets if assets is not None else DemoAssets.discover(config)
        self._psl = PublicSuffixList()
        # One shared pool: the deadline is enforced by abandoning the future,
        # so bounding the workers also bounds how many abandoned audits can be
        # in flight at once.
        self._pool = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="inboxready-audit"
        )

    # -- request building -------------------------------------------------

    def available_modes(self) -> list[str]:
        modes = [MODE_OFFLINE]
        if self.assets.available:
            modes.insert(0, MODE_FIXTURE)
        if self.config.live_dns:
            modes.append(MODE_LIVE)
        return modes

    def build_request(
        self, form, message: bytes | None = None, message_name: str = ""
    ) -> AuditRequest:
        """Validate a submitted form into an :class:`AuditRequest`."""

        mode = (form.get("mode") or MODE_FIXTURE).strip().lower()
        if mode not in _MODES:
            raise AuditProblem("Choose a DNS source.")
        if mode not in self.available_modes():
            if mode == MODE_LIVE:
                raise AuditProblem(
                    "Live DNS lookups are disabled on this deployment. Use a "
                    "demo fixture, or run the command-line tool locally."
                )
            raise AuditProblem("That DNS source is not available here.")

        if mode == MODE_OFFLINE:
            if message is None:
                raise AuditProblem(
                    "A message-only audit needs an .eml file to inspect."
                )
            return AuditRequest(
                mode=mode,
                transactional=bool(form.get("transactional")),
                message=message,
                message_name=message_name,
            )

        fixture = None
        if mode == MODE_FIXTURE:
            fixture = (form.get("fixture") or "").strip()
            if fixture not in self.assets.fixtures:
                raise AuditProblem("Choose one of the bundled demo fixtures.")

        return AuditRequest(
            mode=mode,
            domain=_clean_domain(form.get("domain") or ""),
            fixture=fixture,
            selectors=_clean_selectors(form.get("selectors") or ""),
            ips=_clean_ips(form.get("ips") or ""),
            daily_volume=_clean_daily_volume(form.get("daily_volume") or ""),
            spam_rate=_clean_spam_rate(form.get("spam_rate") or ""),
            transactional=bool(form.get("transactional")),
            message=message,
            message_name=message_name,
        )

    def demo_message(self, name: str) -> tuple[bytes, str]:
        """Load a bundled example message by name."""

        path = self.assets.messages.get(name)
        if path is None:
            raise AuditProblem("Choose one of the bundled example messages.")
        return path.read_bytes(), path.name

    # -- execution --------------------------------------------------------

    def _resolver(self, request: AuditRequest) -> Resolver | None:
        if request.mode == MODE_OFFLINE:
            return None
        if request.mode == MODE_FIXTURE:
            path = self.assets.fixtures[request.fixture]
            return StaticResolver.from_file(path)
        return _BudgetedResolver(
            budget=self.config.dns_query_budget,
            timeout=self.config.dns_timeout,
        )

    def run(self, request: AuditRequest):
        """Run an audit, returning an :class:`~inboxready.models.AuditReport`."""

        try:
            resolver = self._resolver(request)
        except DnsError as exc:
            raise AuditProblem(
                f"This deployment cannot resolve DNS right now: {exc}"
            ) from exc
        except (OSError, ValueError) as exc:
            raise AuditProblem(f"Could not load that fixture: {exc}") from exc

        future = self._pool.submit(
            run_inboxready_audit,
            resolver=resolver,
            domain=request.domain,
            raw_message=request.message,
            selectors=list(request.selectors),
            ips=list(request.ips),
            daily_volume=request.daily_volume,
            spam_rate=request.spam_rate,
            bulk=False if request.transactional else None,
            psl=self._psl,
        )
        try:
            return future.result(timeout=self.config.audit_deadline)
        except FutureTimeout:
            future.cancel()
            raise AuditProblem(
                f"The audit took longer than {self.config.audit_deadline:g}s and "
                "was stopped. Slow or unresponsive nameservers are the usual "
                "cause; the command-line tool has no deadline."
            ) from None
        except QueryBudgetExceeded as exc:
            raise AuditProblem(str(exc)) from exc
        except DnsError as exc:
            raise AuditProblem(f"DNS lookup failed: {exc}") from exc
        except ValueError as exc:
            raise AuditProblem(str(exc)) from exc
