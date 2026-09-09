"""GPUCC-BIND-01: the GPU attestation is bound to the CVM it runs in.

A confidential-GPU deployment is TWO independent TEEs — the H100 and the CPU CVM
(Intel TDX / AMD SEV-SNP) — each with its own signed attestation. GPUCC-CVM-01
checks the CVM is *verified*; this checks the two are *bound* to each other. If the
GPU attestation report does not incorporate the CVM measurement (and vice versa), a
genuine GPU report can be **relayed/substituted** onto a different or unmeasured CVM:
an attacker runs the workload in the clear (or in a debug TDX domain the host reads)
while presenting a real GPU attestation, and the relying party can't tell.

Proven live in the lab: the deployment verified only the GPU report and never the
8000-byte Intel-signed TDX quote, and the two were unbound — 5/5 untrusted CPU
contexts were trusted with a genuine GPU report (``exploit/relay_cpu_attestation.py``).

Input: the attestation report's ``binding`` block —
``gpu_report_includes_cvm_measurement`` (the GPU report's nonce/claims cover the
CVM's MRTD/measurement) and ``cvm_quote_includes_gpu_identity`` (the CVM quote
covers the GPU's identity). Both are required for a real cross-TEE binding.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_gpu_cvm_binding(report: dict[str, Any]) -> dict[str, Any]:
    """Assess whether the GPU and CVM attestations are bound to each other."""
    binding = report.get("binding") or {}
    gpu_bound = bool(binding.get("gpu_report_includes_cvm_measurement", False))
    cvm_bound = bool(binding.get("cvm_quote_includes_gpu_identity", False))

    issues: list[str] = []
    if not gpu_bound:
        issues.append(
            "the GPU attestation does not incorporate the CVM measurement — a genuine "
            "GPU report can be relayed onto a different/unmeasured CVM"
        )
    if not cvm_bound:
        issues.append(
            "the CVM quote does not incorporate the GPU identity — the two TEEs are "
            "attested independently and can be mixed-and-matched"
        )
    return {
        "gpu_report_includes_cvm_measurement": gpu_bound,
        "cvm_quote_includes_gpu_identity": cvm_bound,
        "fully_unbound": not gpu_bound and not cvm_bound,
        "issues": issues,
        "passed": not issues,
    }


class GpuCvmBindCheck(Check):
    check_id = "GPUCC-BIND-01"
    title = "The GPU attestation is cryptographically bound to the CVM"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_attestation_report:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-attestation-report specified; skipping check.",
            )
        try:
            report = load_json_file(target.gpu_attestation_report)
        except Exception as e:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse attestation report: {e}",
            )
        v = analyze_gpu_cvm_binding(report)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.FAIL,
                severity=Severity.CRITICAL if v["fully_unbound"] else self.severity,
                summary=(
                    "The GPU and CVM attestations are not bound: "
                    + "; ".join(v["issues"]) + "."
                ),
                remediation=(
                    "Bind the two TEEs: include the CVM measurement (MRTD/RTMR) in the "
                    "GPU attestation challenge/nonce and the GPU identity in the CVM quote, "
                    "and verify BOTH together. An unbound GPU report is relayable onto any "
                    "CVM — verifying the GPU TEE alone is necessary but not sufficient."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id, title=self.title, status=Status.PASS,
            severity=self.severity,
            summary="The GPU attestation and the CVM quote are cryptographically bound.",
            evidence=v,
        )
