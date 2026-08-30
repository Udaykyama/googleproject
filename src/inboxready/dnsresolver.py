"""DNS access for InboxReady.

Two implementations are provided:

``StaticResolver``
    Answers from an in-memory dict. Used by the test-suite and by the shipped
    example fixtures so the whole tool can be demonstrated with no network.
``SystemResolver``
    Uses ``dnspython`` when it is installed, and otherwise shells out to
    ``dig``. Keeping ``dnspython`` optional means InboxReady runs from a bare
    Python 3.10+ install with nothing to ``pip install``.

Every resolver counts the DNS queries it makes, because SPF evaluation has a
hard limit of 10 lookups (RFC 7208 section 4.6.4) and we need to report on it.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

__all__ = [
    "DnsError",
    "NXDOMAIN",
    "Resolver",
    "StaticResolver",
    "SystemResolver",
    "is_valid_hostname",
    "normalize_name",
    "reverse_pointer",
]

SUPPORTED_RRTYPES = ("A", "AAAA", "TXT", "MX", "PTR", "CNAME")

# A conservative hostname pattern. Every label is 1-63 chars of
# alphanumerics/underscore/hyphen. Underscores are permitted because DNS-based
# email policy lives under names such as `_dmarc` and `selector._domainkey`.
_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*\.?$")


class DnsError(Exception):
    """Raised when a lookup cannot be completed (SERVFAIL, timeout, ...)."""


class NXDOMAIN(DnsError):
    """Raised when a name definitively does not exist."""


def is_valid_hostname(name: str) -> bool:
    """Return True if ``name`` is a syntactically valid DNS name.

    This is a security control as much as a correctness one: names reach
    ``subprocess`` in :class:`SystemResolver`, so anything that is not a plain
    hostname is rejected before it gets there.
    """

    if not name or len(name.rstrip(".")) > 253:
        return False
    return bool(_HOSTNAME_RE.match(name))


def normalize_name(name: str) -> str:
    """Lower-case, strip the root dot, and IDNA-encode a DNS name."""

    candidate = name.strip().rstrip(".")
    if not candidate:
        raise ValueError("empty DNS name")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        # Not encodable as IDNA (e.g. it contains an underscore label, which
        # `encode('idna')` rejects). Fall back to the raw value; the hostname
        # validation below is what actually protects us.
        pass
    candidate = candidate.lower()
    if not is_valid_hostname(candidate):
        raise ValueError(f"invalid DNS name: {name!r}")
    return candidate


def reverse_pointer(ip: str) -> str:
    """Return the ``in-addr.arpa`` / ``ip6.arpa`` name for an IP address."""

    return ipaddress.ip_address(ip).reverse_pointer


class Resolver(ABC):
    """Minimal DNS interface: the record types email policy actually needs."""

    def __init__(self) -> None:
        self.query_count = 0
        self._cache: dict[tuple[str, str], list[str]] = {}

    def query(self, name: str, rrtype: str) -> list[str]:
        """Look up ``name``/``rrtype``, returning a list of string rdata.

        Results (including negative results) are cached for the lifetime of the
        resolver so that repeated SPF ``include:`` chains stay cheap and the
        lookup counter reflects genuine network work.
        """

        rrtype = rrtype.upper()
        if rrtype not in SUPPORTED_RRTYPES:
            raise ValueError(f"unsupported rrtype: {rrtype}")
        key = (normalize_name(name), rrtype)
        if key in self._cache:
            return list(self._cache[key])
        self.query_count += 1
        answers = self._lookup(key[0], rrtype)
        self._cache[key] = answers
        return list(answers)

    # Convenience wrappers ------------------------------------------------
    def txt(self, name: str) -> list[str]:
        return self.query(name, "TXT")

    def a(self, name: str) -> list[str]:
        return self.query(name, "A")

    def aaaa(self, name: str) -> list[str]:
        return self.query(name, "AAAA")

    def mx(self, name: str) -> list[str]:
        return self.query(name, "MX")

    def cname(self, name: str) -> list[str]:
        return self.query(name, "CNAME")

    def ptr(self, ip: str) -> list[str]:
        return self.query(reverse_pointer(ip), "PTR")

    @abstractmethod
    def _lookup(self, name: str, rrtype: str) -> list[str]:
        """Perform the actual lookup. ``name`` is already normalized."""


class StaticResolver(Resolver):
    """A resolver backed by a fixture mapping.

    ``records`` maps a DNS name to a mapping of rrtype -> list of rdata
    strings. Names absent from the mapping raise :class:`NXDOMAIN`; names that
    are present but lack the requested rrtype return an empty list (NODATA).
    """

    def __init__(self, records: dict[str, dict[str, list[str]]] | None = None) -> None:
        super().__init__()
        self.records: dict[str, dict[str, list[str]]] = {}
        for name, rrsets in (records or {}).items():
            self.records[normalize_name(name)] = {
                rrtype.upper(): list(values) for rrtype, values in rrsets.items()
            }

    @classmethod
    def from_file(cls, path: str | Path) -> "StaticResolver":
        """Load a fixture from a JSON file."""

        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        zone = payload.get("dns", payload)
        if not isinstance(zone, dict):
            raise ValueError("fixture must contain an object of DNS records")
        return cls(zone)

    def _lookup(self, name: str, rrtype: str) -> list[str]:
        try:
            rrsets = self.records[name]
        except KeyError:
            raise NXDOMAIN(f"{name} does not exist") from None
        return list(rrsets.get(rrtype, []))


class SystemResolver(Resolver):
    """Queries real DNS via ``dnspython`` if available, else ``dig``."""

    def __init__(self, timeout: float = 5.0, nameserver: str | None = None) -> None:
        super().__init__()
        self.timeout = timeout
        self.nameserver = nameserver
        self._dns = self._import_dnspython()
        if self._dns is None and shutil.which("dig") is None:
            raise DnsError(
                "no DNS backend available: install 'dnspython' (pip install dnspython) "
                "or make the 'dig' command available, or run with --fixture for an "
                "offline audit"
            )

    @staticmethod
    def _import_dnspython():  # pragma: no cover - depends on the environment
        try:
            import dns.rdatatype  # noqa: F401
            import dns.resolver

            return dns.resolver
        except ImportError:
            return None

    def _lookup(self, name: str, rrtype: str) -> list[str]:
        if self._dns is not None:  # pragma: no cover - environment dependent
            return self._lookup_dnspython(name, rrtype)
        return self._lookup_dig(name, rrtype)

    def _lookup_dnspython(self, name: str, rrtype: str) -> list[str]:  # pragma: no cover
        dnsresolver = self._dns
        resolver = dnsresolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout
        if self.nameserver:
            resolver.nameservers = [self.nameserver]
        try:
            answer = resolver.resolve(name, rrtype)
        except dnsresolver.NXDOMAIN as exc:
            raise NXDOMAIN(f"{name} does not exist") from exc
        except dnsresolver.NoAnswer:
            return []
        except Exception as exc:
            raise DnsError(f"{rrtype} lookup for {name} failed: {exc}") from exc
        return [self._render_rdata(rdata, rrtype) for rdata in answer]

    @staticmethod
    def _render_rdata(rdata, rrtype: str) -> str:  # pragma: no cover
        if rrtype == "TXT":
            # Re-join the character-strings of a multi-part TXT record, which
            # is how SPF/DKIM records longer than 255 bytes are published.
            return "".join(
                part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
        return str(rdata).rstrip(".")

    def _lookup_dig(self, name: str, rrtype: str) -> list[str]:
        # `name` has already been through normalize_name(), so it matches
        # _HOSTNAME_RE and cannot smuggle in arguments. No shell is used.
        if not is_valid_hostname(name):  # defensive: never reachable via query()
            raise ValueError(f"refusing to resolve invalid name: {name!r}")
        argv = ["dig", "+time=%d" % max(1, int(self.timeout)), "+tries=1", "+noall", "+answer"]
        if self.nameserver:
            server = str(ipaddress.ip_address(self.nameserver))
            argv.append(f"@{server}")
        argv += [rrtype, name]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout + 5,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DnsError(f"{rrtype} lookup for {name} failed: {exc}") from exc
        if proc.returncode != 0:
            raise DnsError(f"{rrtype} lookup for {name} failed: {proc.stderr.strip()}")
        return list(self._parse_dig_answer(proc.stdout, rrtype))

    @staticmethod
    def _parse_dig_answer(stdout: str, rrtype: str) -> Iterable[str]:
        for line in stdout.splitlines():
            fields = line.split(maxsplit=4)
            if len(fields) < 5 or fields[3].upper() != rrtype:
                continue
            rdata = fields[4].strip()
            if rrtype == "TXT":
                yield _unquote_txt(rdata)
            else:
                yield rdata.rstrip(".")


def _unquote_txt(rdata: str) -> str:
    """Join the quoted character-strings ``dig`` prints for a TXT record."""

    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', rdata)
    if not parts:
        return rdata.strip()
    return "".join(part.replace('\\"', '"').replace("\\\\", "\\") for part in parts)
