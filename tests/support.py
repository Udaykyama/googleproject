"""Shared helpers for the InboxReady test-suite."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
EXAMPLES = REPO_ROOT / "examples"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# A valid 2048-bit RSA SubjectPublicKeyInfo, base64-encoded as DKIM publishes it.
RSA_2048_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1dBl3ytFZ1BtjE7FmFj9XEPQOzX2imP81sRX7Ce+"
    "ixvp0OPlMa7ZRtbZurG1NPIES1y6IXrQTW2d2DGI1mQCtItQ8X6FHppZC58TQ1TWcTYmzX8tR5WQuHH7opj/"
    "t9njR0y+u5ZvJchbZuPwH9nz8pWRqOOhhRJ5SnP0hEK5sgn1ed7CSymJ4O1/xOGYnpXG8TM621wHgKOBiK1j"
    "L9orxmf2NKUK3XvXGRA8EUUfViZXe9wWBMDODJP9aGqfOabXEdL5j4Nut6U1lxfvOGzX+My5I+A/tWKAB/0T"
    "syiwO1n9Fghm2wIHZNVNzOAXCUbtvunN/24SjhU9WCHTrVtH7QIDAQAB"
)

# A 512-bit RSA key: structurally valid, cryptographically useless.
RSA_512_B64 = (
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKvFQBZIt8qYsNLCE4zBJ22VEY3dsDEScNAs0fBmn+rgmOqu0s8V"
    "OEADqNjNzr/Zr5IVeconipaJdmkL+i6qGiUCAwEAAQ=="
)


def finding_codes(result) -> set[str]:
    """Collect the finding codes from a CheckResult or AuditReport."""

    return {finding.code for finding in result.findings}
