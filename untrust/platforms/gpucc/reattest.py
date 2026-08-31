"""GPUCC-REATTEST-01: attestation is continuous, not attest-once-run-forever.

A GPU attestation is a point-in-time snapshot. If the deployment attests once at
boot and then trusts the GPU forever, an attacker who changes the GPU state *after*
attestation — flipping CC mode to DevTools, resetting the GPU, or swapping firmware
on a relaunch — keeps the trust. A robust deployment re-attests on a schedule and
on state-change events (the TEE-specific "continuous attestation" the untrust
roadmap calls out), so drift is caught.

Input: the verifier policy — ``continuous_attestation`` (re-attests periodically)
and ``reattest_on_state_change`` (re-attests when CC mode / GPU state changes).
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_reattestation(policy: dict[str, Any]) -> dict[str, Any]:
    """Assess whether attestation is continuous rather than one-shot."""
    continuous = bool(policy.get("continuous_attestation", False))
    on_change = bool(policy.get("reattest_on_state_change", False))
    issues: list[str] = []
    if not continuous:
        issues.append("attestation is one-shot (attest-once-run-forever; drift not caught)")
    if not on_change:
        issues.append("no re-attestation on GPU state change (a post-attest mode flip is trusted)")
    return {
        "continuous_attestation": continuous,
        "reattest_on_state_change": on_change,
        "issues": issues,
        "passed": not issues,
    }


class GpuReattestCheck(Check):
    check_id = "GPUCC-REATTEST-01"
    title = "Attestation is continuous, not one-shot (post-attest drift is caught)"
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
        v = analyze_reattestation(policy)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.FAIL,
                severity=self.severity,
                summary="Attestation is not continuous: " + "; ".join(v["issues"]) + ".",
                remediation=(
                    "Re-attest the GPU periodically and on state-change events (CC-mode "
                    "change, GPU reset, relaunch); gate continued key/data use on a fresh "
                    "attestation, not a boot-time one."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id, title=self.title, status=Status.PASS,
            severity=self.severity,
            summary="Attestation is continuous and re-runs on GPU state change.",
            evidence=v,
        )
