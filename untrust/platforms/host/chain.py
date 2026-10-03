"""X.509 chain validation to a *pinned* root, shared by the SEV-SNP and TPM2 paths.

A chain that verifies is worthless if any self-signed root is accepted: an
attacker mints their own "ARK" or "AK CA" and signs whatever evidence they like.
So the root is never taken from the evidence on trust; its SHA-256 fingerprint
must be pinned in the baseline.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding


def load_certs(blob: bytes) -> list[x509.Certificate]:
    """Load one DER cert, or one or more PEM certs, from ``blob``."""
    if b"-----BEGIN CERTIFICATE-----" in blob:
        return x509.load_pem_x509_certificates(blob)
    return [x509.load_der_x509_certificate(blob)]


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> str | None:
    """Return an issue string if ``issuer`` did not sign ``cert``, else None."""
    try:
        cert.verify_directly_issued_by(issuer)
    except InvalidSignature:
        return "signature does not verify"
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        return str(e)
    return None


def verify_chain(
    certs: list[x509.Certificate],
    pinned_roots: list[str],
    *,
    now: datetime | None = None,
    require_ca_constraint: bool = False,
) -> dict[str, Any]:
    """Verify ``certs`` (leaf first, root last) and that the root is pinned.

    ``require_ca_constraint`` additionally demands BasicConstraints CA=true on
    every issuer, so a leaf cert cannot act as a CA. AMD's ARK/ASK predate that
    convention, so the SEV-SNP path leaves it off and relies on the pinned root.
    """
    now = now or datetime.now(timezone.utc)
    issues: list[str] = []
    pins = {p.lower().replace(":", "") for p in pinned_roots}
    subjects = [c.subject.rfc4514_string() for c in certs]
    if not certs:
        return {"chain": [], "root_sha256": None, "root_pinned": False,
                "issues": ["no certificates supplied"], "passed": False}

    for i, cert in enumerate(certs):
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            issues.append(f"{subjects[i]} is outside its validity window")
        issuer = certs[i + 1] if i + 1 < len(certs) else cert
        problem = _issued_by(cert, issuer)
        if problem:
            role = "root is not self-signed" if issuer is cert else (
                f"{subjects[i]} is not issued by {subjects[i + 1]}")
            issues.append(f"{role} ({problem})")
    if require_ca_constraint:
        for issuer in certs[1:]:
            try:
                is_ca = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            except x509.ExtensionNotFound:
                is_ca = False
            if not is_ca:
                issues.append(f"{issuer.subject.rfc4514_string()} is not a CA certificate")

    root = certs[-1]
    root_fp = fingerprint(root)
    root_pinned = root_fp in pins
    if not pins:
        issues.append("no trusted root is pinned in the baseline; any self-signed "
                      "root (including an attacker's) would be accepted")
    elif not root_pinned:
        issues.append(f"chain root {root_fp} is not a pinned trusted root")
    return {
        "chain": subjects,
        "root_sha256": root_fp,
        "root_pinned": root_pinned,
        "issues": list(dict.fromkeys(issues)),
        "passed": not issues,
    }
