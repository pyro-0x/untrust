"""GPUCC-CVM-01: the GPU is attached to a verified Confidential VM.

NVIDIA GPU CC is only half of a joint TEE: the H100/H200 is attached to a
confidential VM on the CPU (Intel TDX or AMD SEV-SNP), and on clouds like Azure
NCC H100 v5 the CPU and GPU jointly produce the attestation report. If the CPU
side is *not* a verified confidential VM (or is in debug, or Secure Boot is off),
the workload and its host-RAM staging area are exposed regardless of how well the
GPU is locked down — a partial trust boundary. Composes with CSPACE-VM-01.

Input: the attestation report's ``cpu_tee`` section — ``type`` (tdx/sev-snp),
``verified``, ``debug``, ``secure_boot``.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file

_CONFIDENTIAL_TYPES = ("tdx", "sev-snp", "sev_snp", "snp")


def analyze_cvm_binding(report: dict[str, Any]) -> dict[str, Any]:
    """Assess the CPU-side confidential VM the GPU is bound to."""
    cpu = report.get("cpu_tee", {}) or {}
    cpu_type = str(cpu.get("type", "")).strip().lower()
    verified = bool(cpu.get("verified", False))
    debug = bool(cpu.get("debug", False))
    secure_boot = bool(cpu.get("secure_boot", False))

    is_confidential = cpu_type in _CONFIDENTIAL_TYPES
    issues: list[str] = []
    if not is_confidential:
        issues.append(
            f"CPU is not a confidential VM (cpu_tee.type '{cpu_type or 'none'}' is not TDX/SEV-SNP)"
        )
    if not verified:
        issues.append("the CVM attestation is not verified (joint CPU+GPU trust incomplete)")
    if debug:
        issues.append("the CVM is in debug mode")
    if not secure_boot:
        issues.append("Secure Boot is not enabled on the CVM")

    return {
        "cpu_tee_type": cpu_type or None,
        "verified": verified,
        "debug": debug,
        "secure_boot": secure_boot,
        "issues": issues,
        "passed": not issues,
    }


class GpuCvmBindingCheck(Check):
    check_id = "GPUCC-CVM-01"
    title = "GPU is attached to a verified Confidential VM (TDX/SEV-SNP)"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_attestation_report:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-attestation-report specified; skipping check.",
            )
        try:
            report = load_json_file(target.gpu_attestation_report)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse attestation report: {e}",
            )
        v = analyze_cvm_binding(report)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "The CPU-side confidential VM is incomplete: "
                    + "; ".join(v["issues"]) + "."
                ),
                remediation=(
                    "Run the GPU inside a genuine confidential VM (Intel TDX / AMD "
                    "SEV-SNP), verify the joint CPU+GPU attestation, keep the CVM out of "
                    "debug mode, and enable Secure Boot — the GPU boundary is only as "
                    "strong as the CPU VM it is attached to."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="GPU is attached to a verified, non-debug confidential VM with Secure Boot.",
            evidence=v,
        )
