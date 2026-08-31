"""GPUCC-FAILOPEN-01: the verifier fails CLOSED when attestation can't be checked.

If the attestation path is unavailable — NRAS times out, the RIM service is down,
the local verifier errors — a safe deployment denies key/data release (fail
closed). A fail-open verifier hands the workload's secrets to an unverified GPU
exactly when verification is broken, which is also precisely when an untrusted
host would *induce* that failure (block NRAS, drop the RIM fetch).

Input: the verifier policy's ``fail_closed`` flag.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_fail_closed(policy: dict[str, Any]) -> dict[str, Any]:
    """Assess whether the verifier denies on attestation-path failure."""
    fail_closed = bool(policy.get("fail_closed", False))
    issues: list[str] = []
    if not fail_closed:
        issues.append(
            "verifier fails OPEN on attestation error/outage (NRAS/RIM down, verifier "
            "error) — the untrusted host can force that failure and get an unverified GPU trusted"
        )
    return {"fail_closed": fail_closed, "issues": issues, "passed": not issues}


class GpuFailOpenCheck(Check):
    check_id = "GPUCC-FAILOPEN-01"
    title = "The verifier fails closed when attestation can't be checked"
    severity = Severity.HIGH

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
        v = analyze_fail_closed(policy)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.FAIL,
                severity=self.severity,
                summary="The verifier fails open: " + "; ".join(v["issues"]) + ".",
                remediation=(
                    "Fail closed: on any attestation error/timeout, deny key/data release "
                    "and refuse to run the workload. Never treat 'could not verify' as 'verified'."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id, title=self.title, status=Status.PASS,
            severity=self.severity,
            summary="The verifier fails closed on attestation-path failure.",
            evidence=v,
        )
