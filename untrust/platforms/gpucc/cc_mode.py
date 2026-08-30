"""GPUCC-MODE-01: the GPU is in CC-On, not CC-DevTools (debug) or CC-Off.

NVIDIA Confidential Computing has three modes: CC-Off (no protection), CC-On
(hardware confidentiality + integrity), and **CC-DevTools** — a performance-
debugging mode that runs the GPU in CC but *weakens* the isolation and is
flagged in the attestation report. Running production workloads in DevTools is
the GPU analog of a debug Nitro enclave (ENCLAVE-01) or a Confidential Space VM
with ``dbgstat != 'disabled-since-boot'`` (CSPACE-ATT-01): attestation still
"passes", but the confidentiality guarantee you are relying on is degraded.

Input is the CC-mode string as reported by ``nvidia-smi conf-compute -f`` (or the
``cc_mode`` field of the attestation report): one of ``on`` / ``devtools`` / ``off``.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target

_ON = "on"


def analyze_cc_mode(mode: str | None) -> dict[str, Any]:
    """Assess the GPU Confidential Computing mode string."""
    normalized = (mode or "").strip().lower().replace("cc-", "").replace(" ", "")
    is_on = normalized == _ON
    is_devtools = normalized in ("devtools", "devtool")
    issues: list[str] = []
    if not normalized:
        issues.append("CC mode is unset (cannot confirm the GPU is in Confidential Computing mode)")
    elif is_devtools:
        issues.append("CC mode is DevTools — a debug/perf mode that weakens the isolation")
    elif not is_on:
        issues.append(f"CC mode is '{normalized}' (expected 'on')")
    return {
        "cc_mode": normalized or None,
        "is_on": is_on,
        "is_devtools": is_devtools,
        "issues": issues,
        "passed": not issues,
    }


class GpuCcModeCheck(Check):
    check_id = "GPUCC-MODE-01"
    title = "GPU is in CC-On mode, not CC-DevTools or CC-Off"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_cc_mode:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-cc-mode specified; skipping check.",
            )
        v = analyze_cc_mode(target.gpu_cc_mode)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL if v["is_devtools"] else self.severity,
                summary="GPU is not in production Confidential Computing mode: "
                + "; ".join(v["issues"])
                + ".",
                remediation=(
                    "Set the GPU to CC-On (not CC-DevTools) before running production "
                    "workloads on a CC-capable driver, and confirm `nvidia-smi "
                    "conf-compute -f` reports ON. Never run confidential workloads in "
                    "DevTools mode."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="GPU reports CC-On (production Confidential Computing mode).",
            evidence=v,
        )
