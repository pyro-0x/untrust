"""GPUCC-DMA-01: CPU<->GPU traffic is encrypted over an SPDM secure session.

In CC mode the GPU driver (SPDM requester) establishes an authenticated,
encrypted session with the GPU's GSP (responder); all command buffers, kernels,
and data crossing the PCIe bus transit **encrypted bounce buffers**. If the
secure session is not established, or an unprotected DMA path remains, the
untrusted host can snoop cleartext data in transit between CPU and GPU.

Input: the attestation report's ``memory.pcie_encryption`` and
``memory.spdm_session`` flags.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_dma_session(report: dict[str, Any]) -> dict[str, Any]:
    """Assess whether PCIe/bounce-buffer traffic is encrypted over SPDM."""
    memory = report.get("memory", {}) or {}
    pcie = bool(memory.get("pcie_encryption", False))
    spdm = bool(memory.get("spdm_session", False))
    issues: list[str] = []
    if not spdm:
        issues.append("no SPDM secure session established between the driver and the GPU")
    if not pcie:
        issues.append("PCIe/bounce-buffer traffic is not encrypted (host-snoopable CPU<->GPU DMA)")
    return {
        "pcie_encryption": pcie,
        "spdm_session": spdm,
        "issues": issues,
        "passed": not issues,
    }


class GpuDmaSessionCheck(Check):
    check_id = "GPUCC-DMA-01"
    title = "CPU<->GPU DMA is encrypted over an SPDM secure session"
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
        v = analyze_dma_session(report)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="CPU<->GPU traffic is not fully protected: " + "; ".join(v["issues"]) + ".",
                remediation=(
                    "Run in CC-On so the driver establishes the SPDM session and all PCIe "
                    "traffic uses encrypted bounce buffers; do not disable the secure "
                    "session or use an unprotected DMA path."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="CPU<->GPU DMA is encrypted over an established SPDM session.",
            evidence=v,
        )
