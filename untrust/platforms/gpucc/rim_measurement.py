"""GPUCC-RIM-01: verification pins RIM golden measurements, not identity only.

NVIDIA verifies a GPU by comparing the runtime measurements in the attestation
report against **golden measurements** in the Reference Integrity Manifest (RIM).
Confirmed against a live H100 (NVIDIA local GPU verifier): the verifier
authenticates two RIMs — a **Driver RIM** and a **VBIOS RIM** — and matches the
report's driver + VBIOS versions to the golden values. On Hopper the GSP firmware
measurement is carried *within* the driver RIM, so "driver" + "vbios" are the
measurement classes a policy must pin (there is no standalone GSP RIM).

Inputs: the relying party's verifier policy — ``pinned_measurements: [...]`` (the
measurement *names* that must be pinned) and, optionally, ``expected_measurements:
{name: golden_value}`` (the approved golden values) — and, when available, the
attestation report. When the policy carries golden values, the check stops being a
pure pinning *declaration* and cross-checks the operator's golden values against
the report's *actual* measurement values, catching a downgraded/tampered firmware
even when the report is validly formed. That cross-check makes the verdict
report-derived (trustworthy as far as the report signature is verified — see
GPUCC-SIGVERIFY-01) rather than operator-declared, so the check promotes its own
assurance tier at runtime.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Assurance, Check, Finding, Severity, Status, Target
from ._io import load_json_file

# The measurement classes that must be pinned for a real code-state binding.
# Default matches the live NVIDIA verifier's Driver RIM + VBIOS RIM on **Hopper**
# (H100/H200) — GSP firmware is measured within the driver RIM, not separately.
# Blackwell and multi-GPU NVLink domains (GB200 NVL) may add/rename measurements,
# so a verifier policy can override this set via ``required_measurements``.
REQUIRED_MEASUREMENTS = ("driver", "vbios")


def analyze_rim_pinning(policy: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Assess RIM pinning and, when golden values are given, cross-check them."""
    # Hopper-calibrated default; a policy may declare a chip-specific measurement set.
    required = tuple(
        str(m).strip().lower() for m in (policy.get("required_measurements") or [])
    ) or REQUIRED_MEASUREMENTS
    pinned = [str(m).strip().lower() for m in (policy.get("pinned_measurements") or [])]
    report_meas = report.get("measurements") or {}
    report_measurements = [k.lower() for k in report_meas]
    report_values = {str(k).lower(): str(v) for k, v in report_meas.items()}
    expected = {
        str(k).strip().lower(): str(v)
        for k, v in (policy.get("expected_measurements") or {}).items()
    }
    # The operator opted into value-pinning and there are report values to check.
    values_checked = bool(expected and report_values)

    issues: list[str] = []
    if not pinned:
        issues.append(
            "verifier policy pins no measurements — verification is identity-only, "
            "not bound to a RIM code measurement (any firmware/driver is accepted)"
        )
    else:
        for m in required:
            present = (m in report_measurements) if report_measurements else True
            if present and m not in pinned:
                issues.append(f"golden measurement '{m}' is not pinned by the verifier policy")

    # Strong, report-derived signal: compare the operator's golden values against
    # the report's actual measurement values. A mismatch is a downgraded/tampered
    # firmware that a name-only pinning check would wave through.
    mismatches: list[str] = []
    if values_checked:
        for m in required:
            if m not in report_values:
                continue
            if m not in expected:
                issues.append(
                    f"golden value for '{m}' is not pinned (expected_measurements) — "
                    f"the report's {m} measurement is not cross-checked"
                )
            elif report_values[m] != expected[m]:
                mismatches.append(m)
                issues.append(
                    f"measurement '{m}' in the report ({report_values[m]}) does not match "
                    f"the pinned golden value ({expected[m]}) — downgraded/tampered firmware"
                )

    return {
        "pinned_measurements": pinned,
        "report_measurements": report_measurements,
        "expected_measurements": expected,
        "values_checked": values_checked,
        "mismatches": mismatches,
        "issues": issues,
        "passed": not issues,
    }


class GpuRimPinningCheck(Check):
    check_id = "GPUCC-RIM-01"
    title = "Verification pins RIM golden measurements (driver + VBIOS)"
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
        # When the check actually cross-checked golden values against the report,
        # its verdict is report-derived, not a pinning declaration — promote the
        # tier (the runner still flags it "unverified" if SIGVERIFY-01 didn't pass).
        tier = Assurance.REPORT_DERIVED if v["values_checked"] else None
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
                    "RIM golden measurements — the driver and VBIOS RIMs (GSP firmware is "
                    "measured within the driver RIM) — and pin their golden values "
                    "(expected_measurements) so a downgraded or arbitrary firmware is "
                    "rejected even when the report is validly signed."
                ),
                evidence=v,
                assurance=tier,
            )
        summary = (
            "Verifier pins the required RIM measurements and their golden values match "
            "the report."
            if v["values_checked"]
            else "Verifier policy pins the required RIM golden measurements."
        )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=summary,
            evidence=v,
            assurance=tier,
        )
