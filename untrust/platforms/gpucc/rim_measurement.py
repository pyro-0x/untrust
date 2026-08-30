"""GPUCC-RIM-01: verification pins RIM golden measurements, not identity only.

NVIDIA verifies a GPU by comparing the runtime measurements in the attestation
report against **golden measurements** in the Reference Integrity Manifest (RIM)
— VBIOS, GSP firmware, and driver. The GPU analog of CSPACE-KEYBIND-01's
image-digest pinning: a verifier that accepts *any* signed report from *any*
GPU model (without pinning the RIM measurements) proves *identity*, not *code
state*, and will accept a downgraded or arbitrary firmware.

Inputs: the relying party's verifier policy (``pinned_measurements: [...]``) and,
when available, the attestation report (to confirm which measurements exist and
must therefore be pinned).
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file

# The measurement classes that must be pinned for a real code-state binding.
REQUIRED_MEASUREMENTS = ("vbios", "gsp_firmware", "driver")


def analyze_rim_pinning(policy: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Assess whether the verifier policy pins the golden RIM measurements."""
    pinned = [str(m).strip().lower() for m in (policy.get("pinned_measurements") or [])]
    report_measurements = [k.lower() for k in (report.get("measurements") or {})]

    issues: list[str] = []
    if not pinned:
        issues.append(
            "verifier policy pins no measurements — verification is identity-only, "
            "not bound to a RIM code measurement (any firmware/driver is accepted)"
        )
    else:
        for m in REQUIRED_MEASUREMENTS:
            present = (m in report_measurements) if report_measurements else True
            if present and m not in pinned:
                issues.append(f"golden measurement '{m}' is not pinned by the verifier policy")

    return {
        "pinned_measurements": pinned,
        "report_measurements": report_measurements,
        "issues": issues,
        "passed": not issues,
    }


class GpuRimPinningCheck(Check):
    check_id = "GPUCC-RIM-01"
    title = "Verification pins RIM golden measurements (VBIOS/firmware/driver)"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_verifier_policy:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-verifier-policy specified; skipping check.",
            )
        try:
            policy = load_json_file(target.gpu_verifier_policy)
            report = (
                load_json_file(target.gpu_attestation_report)
                if target.gpu_attestation_report
                else {}
            )
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse verifier policy or report: {e}",
            )
        v = analyze_rim_pinning(policy, report)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="Verification does not pin the golden RIM measurements: "
                + "; ".join(v["issues"])
                + ".",
                remediation=(
                    "Configure the verifier (local Verifier or NRAS policy) to pin the "
                    "RIM golden measurements — VBIOS, GSP firmware, and driver — to the "
                    "approved versions, so a downgraded or arbitrary firmware is rejected "
                    "even when the report is validly signed."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Verifier policy pins the required RIM golden measurements.",
            evidence=v,
        )
