"""CSPACE-ATT-01: Confidential Space attestation token asserts a trusted state.

The runtime analog of Nitro's ENCLAVE-01/04. Given a captured Confidential Space
attestation token (the JWT the launcher hands the workload), verify the *claims*
describe a non-debug, signed, production workload on AMD SEV hardware:

  * ``dbgstat == 'disabled-since-boot'``            — not a debug VM
  * ``submods.confidential_space.support_attributes`` contains STABLE/LATEST and
    NOT USABLE                                       — not a debug-tooling image
  * ``submods.container.image_signatures`` present   — the image is cosign-signed
  * ``hwmodel`` names hardware Confidential Space attests: an AMD SEV model
    (``GCP_AMD_SEV``) or Intel TDX (``GCP_INTEL_TDX``)

NOTE: this inspects claims only. Full trust also requires verifying the token's
RS256 signature against Google's Confidential Space JWKS and checking aud/exp/
nonce freshness — do that in the workload's key-release code, not here. This
check audits *what the token asserts*, which is where deploy-time mistakes show.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    """Decode a JWT's payload segment without verifying the signature."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (expected header.payload.signature)")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)  # restore base64 padding
    claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload))
    return claims


def attested_hwmodel(hwmodel: str) -> bool:
    """AMD SEV (GCP_AMD_SEV, and its SEV-ES variant) or Intel TDX."""
    value = hwmodel.upper()
    return value.startswith("GCP_AMD_SEV") or value == "GCP_INTEL_TDX"


def analyze_token_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """Pure analysis of Confidential Space attestation-token claims."""
    dbgstat = claims.get("dbgstat", "")
    hwmodel = str(claims.get("hwmodel", ""))
    submods = claims.get("submods", {}) or {}
    container = submods.get("container", {}) or {}
    cspace = submods.get("confidential_space", {}) or {}
    support = [str(s).upper() for s in (cspace.get("support_attributes") or [])]
    signatures = container.get("image_signatures") or []

    issues: list[str] = []
    if dbgstat != "disabled-since-boot":
        issues.append(f"dbgstat is '{dbgstat or 'unset'}' (expected disabled-since-boot)")
    if "USABLE" in support:
        issues.append("support_attributes includes USABLE (a debug-tooling image)")
    if not support:
        issues.append("no support_attributes present (cannot confirm STABLE/LATEST image)")
    if not signatures:
        issues.append("no image_signatures present (workload image is unsigned)")
    if not attested_hwmodel(hwmodel):
        issues.append(
            f"hwmodel '{hwmodel or 'unset'}' is not Confidential Space hardware "
            "(expected GCP_AMD_SEV or GCP_INTEL_TDX)"
        )

    return {
        "dbgstat": dbgstat,
        "hwmodel": hwmodel,
        "support_attributes": support,
        "image_reference": container.get("image_reference"),
        "image_digest": container.get("image_digest"),
        "image_signature_count": len(signatures),
        "issues": issues,
        "passed": not issues,
    }


class ConfidentialSpaceAttestationCheck(Check):
    check_id = "CSPACE-ATT-01"
    title = "Confidential Space attestation token asserts a trusted state"
    severity = Severity.CRITICAL

    def run(self, target: Target) -> Finding:
        if not target.attestation_token:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --attestation-token specified; skipping check.",
            )

        try:
            with open(target.attestation_token) as f:
                token = f.read()
            claims = _decode_jwt_claims(token)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/decode attestation token: {e}",
            )

        verdict = analyze_token_claims(claims)
        if not verdict["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="Attestation token does not assert a trusted state: "
                + "; ".join(verdict["issues"])
                + ".",
                remediation=(
                    "Launch the workload from a non-debug (production) "
                    "Confidential Space image, deploy a cosign-signed workload "
                    "container, and confirm the VM runs on an AMD SEV-SNP "
                    "machine type. Never accept a token with dbgstat != "
                    "'disabled-since-boot' in your key-release path."
                ),
                evidence=verdict,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "Attestation token asserts disabled-since-boot, a signed image, "
                "and AMD SEV hardware."
            ),
            evidence=verdict,
        )
