"""GPUCC-READY-01: attest before trusting the GPU (and bind key release to it).

The core boot-time ordering. In NVIDIA CC, after a CVM+GPU boots the user must
query the attestation report, verify it, and only then toggle the GPU "ready
state" ON to run CUDA — and only then release model weights / data keys to it.
Handing secrets to a GPU whose attestation has not been verified is the GPU
analog of an unconditioned KMS grant (KMS-01 / CSPACE-KMS-01): the workload
trusts the device before it has proven anything.

Input: the relying party's key-release / launch policy —
``attest_before_ready`` (verification precedes ready-state / secret load) and
``attestation_bound`` (the DEK is released only to a successfully attested GPU).
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_key_release_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Assess attest-before-trust ordering and attestation-bound key release."""
    attest_before_ready = bool(policy.get("attest_before_ready", False))
    attestation_bound = bool(policy.get("attestation_bound", False))

    issues: list[str] = []
    if not attest_before_ready:
        issues.append(
            "workload does not verify GPU attestation before toggling the ready-state ON "
            "/ loading secrets (data handed to an unverified GPU)"
        )
    if not attestation_bound:
        issues.append(
            "key/DEK release is not bound to the GPU attestation result "
            "(a key is released without requiring a valid attestation)"
        )
    return {
        "attest_before_ready": attest_before_ready,
        "attestation_bound": attestation_bound,
        "issues": issues,
        "passed": not issues,
    }


class GpuReadyStateCheck(Check):
    check_id = "GPUCC-READY-01"
    title = "Workload attests before trusting the GPU (attestation-bound key release)"
    severity = Severity.CRITICAL

    def run(self, target: Target) -> Finding:
        if not target.gpu_kbs_policy:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-kbs-policy specified; skipping check.",
            )
        try:
            policy = load_json_file(target.gpu_kbs_policy)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse key-release policy: {e}",
            )
        v = analyze_key_release_policy(policy)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="GPU is trusted before attestation is verified: "
                + "; ".join(v["issues"])
                + ".",
                remediation=(
                    "Verify the GPU attestation report (CC-On, pinned measurements, valid "
                    "cert chain) BEFORE toggling the GPU ready-state ON and before "
                    "releasing any DEK/weights; gate KBS/KMS key release on a successful "
                    "attestation so no key is released to an unverified GPU."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "Attestation is verified before the GPU is trusted, and key "
                "release is bound to it."
            ),
            evidence=v,
        )
