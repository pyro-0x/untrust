"""GPUCC-SIGVERIFY-01: the attestation report signature is actually verified.

GPUCC-ATT-01 inspects the report's *claims*; this checks that the relying party
*cryptographically verifies the report signature* against the GPU's device key —
not merely reads the fields and trusts them. A verifier that parses claims without
checking the signature accepts a fully fabricated report. Together with
GPUCC-CERT-01 (the signer chains to NVIDIA's RoT) this closes the "attestation is
lying" surface at the crypto layer, not just the claims layer.

Input: the verifier policy's ``verify_signature`` flag.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_signature_verification(policy: dict[str, Any]) -> dict[str, Any]:
    """Assess whether the report signature is cryptographically verified."""
    verify = bool(policy.get("verify_signature", False))
    issues: list[str] = []
    if not verify:
        issues.append(
            "verifier does not cryptographically verify the report signature "
            "(claims are trusted as-is — a fabricated report would be accepted)"
        )
    return {"verify_signature": verify, "issues": issues, "passed": not issues}


class GpuSignatureVerifyCheck(Check):
    check_id = "GPUCC-SIGVERIFY-01"
    title = "The attestation report signature is cryptographically verified"
    severity = Severity.CRITICAL

    def run(self, target: Target) -> Finding:
        if not target.gpu_verifier_policy:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-verifier-policy specified; skipping check.",
            )
        try:
            policy = load_json_file(target.gpu_verifier_policy)
        except Exception as e:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse verifier policy: {e}",
            )
        v = analyze_signature_verification(policy)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.FAIL,
                severity=self.severity,
                summary="Report signature is not verified: " + "; ".join(v["issues"]) + ".",
                remediation=(
                    "Cryptographically verify the attestation report signature against "
                    "the GPU device key (and chain it to the NVIDIA RoT) before trusting "
                    "any claim in it — never parse-and-trust."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id, title=self.title, status=Status.PASS,
            severity=self.severity,
            summary="The verifier cryptographically verifies the report signature.",
            evidence=v,
        )
