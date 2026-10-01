"""GPUCC-VRAM-01: hardware VRAM encryption is in effect.

In CC-On, the H100/H200 encrypts VRAM with a key generated inside the GPU
security processor and never exposed to host software. If VRAM encryption is
off or partial (e.g. the GPU slipped to CC-Off, or a protected-region config is
wrong), GPU memory — model weights, activations, KV cache — is readable by the
untrusted host. This is the GPU-side of the runtime-memory boundary.

Input: the attestation report's ``memory.vram_encryption`` flag.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_vram_encryption(report: dict[str, Any]) -> dict[str, Any]:
    """Assess whether hardware VRAM encryption is active."""
    memory = report.get("memory", {}) or {}
    vram = bool(memory.get("vram_encryption", False))
    issues: list[str] = []
    if not vram:
        issues.append("VRAM encryption is not in effect (GPU memory is readable by the host)")
    return {"vram_encryption": vram, "issues": issues, "passed": not issues}


class GpuVramEncryptionCheck(Check):
    check_id = "GPUCC-VRAM-01"
    title = "Hardware VRAM encryption is in effect"
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
        v = analyze_vram_encryption(report)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="VRAM encryption is not active: " + "; ".join(v["issues"]) + ".",
                remediation=(
                    "Run the GPU in CC-On so hardware VRAM encryption is enforced; confirm "
                    "the attestation report shows memory protection active before loading "
                    "weights."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Hardware VRAM encryption is in effect.",
            evidence=v,
        )
