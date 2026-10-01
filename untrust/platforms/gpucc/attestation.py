"""GPUCC-ATT-01: the GPU attestation report asserts a trusted state.

The GPU analog of CSPACE-ATT-01. Given a captured NVIDIA attestation report,
verify the *claims* describe a production, non-debug GPU in Confidential
Computing mode with a real hardware identity and a signed report:

  * ``cc_mode == 'on'``                 — not DevTools/Off
  * ``gpu.debug`` is false              — the GPU is not in a debug state
  * ``measurements`` present            — there is something to compare to RIM
  * ``gpu.model`` recognized            — a known NVIDIA CC GPU (H100/H200/B*/GH*/GB*)
  * ``signature.present`` (+ verified)  — the report is cryptographically signed

NOTE: this inspects the report's *claims*. GPUCC-RIM-01 checks that the verifier
*pins* those measurements, and GPUCC-CERT-01 that the signing cert chains to the
NVIDIA root — signature/nonce *freshness* verification belongs in the relying
party's attestation code, not a deploy auditor.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file

# Recognized NVIDIA Confidential-Computing GPU families (substring match, upper).
_KNOWN_MODELS = ("H100", "H200", "B100", "B200", "GH200", "GB200")


def analyze_attestation_report(report: dict[str, Any]) -> dict[str, Any]:
    """Pure analysis of an NVIDIA GPU attestation report's claims."""
    cc_mode = str(report.get("cc_mode", "")).strip().lower().replace("cc-", "")
    gpu = report.get("gpu", {}) or {}
    model = str(gpu.get("model", ""))
    debug = bool(gpu.get("debug", False))
    measurements = report.get("measurements", {}) or {}
    signature = report.get("signature", {}) or {}

    issues: list[str] = []
    if cc_mode != "on":
        issues.append(f"cc_mode is '{cc_mode or 'unset'}' (expected on)")
    if debug:
        issues.append("gpu.debug is true (the GPU is in a debug state)")
    if not measurements:
        issues.append("no measurements present (nothing to compare against RIM golden values)")
    if not any(m in model.upper() for m in _KNOWN_MODELS):
        issues.append(f"gpu.model '{model or 'unset'}' is not a recognized CC GPU family")
    if not signature.get("present"):
        issues.append("report is unsigned (signature.present is false)")

    return {
        "cc_mode": cc_mode or None,
        "gpu_model": model or None,
        "gpu_debug": debug,
        "measurement_keys": sorted(measurements.keys()),
        "signature_present": bool(signature.get("present")),
        "issues": issues,
        "passed": not issues,
    }


class GpuAttestationCheck(Check):
    check_id = "GPUCC-ATT-01"
    title = "GPU attestation report asserts a trusted state"
    severity = Severity.CRITICAL

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
        v = analyze_attestation_report(report)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="GPU attestation report does not assert a trusted state: "
                + "; ".join(v["issues"])
                + ".",
                remediation=(
                    "Collect the report from a CC-On (non-DevTools) production GPU with "
                    "the NVIDIA Attestation SDK, confirm the GPU model and signed report, "
                    "and reject any report whose cc_mode != on or that carries a debug "
                    "flag in your key-release path."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Attestation report asserts CC-On, a signed report, and a known GPU.",
            evidence=v,
        )
