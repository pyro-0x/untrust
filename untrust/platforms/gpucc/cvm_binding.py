"""GPUCC-CVM-01: the GPU is attached to a verified Confidential VM.

NVIDIA GPU CC is only half of a joint TEE: the H100/H200 is attached to a
confidential VM on the CPU (Intel TDX or AMD SEV-SNP). If the CPU side is *not* a
genuinely verified confidential VM (or is in debug, or Secure Boot is off), the
workload and its host-RAM staging area are exposed regardless of how well the GPU
is locked down — a partial trust boundary. Composes with CSPACE-VM-01.

The CVM's trustworthiness must come from a REAL, vendor-signed attestation quote
(an Intel-chained TDX quote / AMD SEV-SNP report), not a self-asserted ``verified``
boolean. A deployment that never verifies the CPU-side quote is trusting fabricated
state — the lab's live campaign proved the second TEE was never checked and the two
were unbound (see GPUCC-BIND-01).

Input: the attestation report's ``cpu_tee`` section — ``type`` (tdx/sev-snp),
``debug``, ``secure_boot``, and a ``quote`` sub-object (``present``,
``intel_chained`` / vendor-chained, ``verified``, ``debug`` for the TD/VM).
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file

# Recognized confidential-CPU TEE types the GPU can be attached to. x86 hosts use
# Intel TDX / AMD SEV-SNP; NVIDIA Grace superchips (GH200/GB200) use ARM CCA, so a
# legitimate Grace confidential VM reports one of the ARM-CCA aliases and must not
# be falsely rejected.
_CONFIDENTIAL_TYPES = (
    "tdx", "sev-snp", "sev_snp", "snp",       # x86 hosts
    "cca", "arm-cca", "arm_cca", "grace",     # NVIDIA Grace (ARM CCA) superchips
)


def analyze_cvm_binding(report: dict[str, Any]) -> dict[str, Any]:
    """Assess the CPU-side confidential VM the GPU is bound to."""
    cpu = report.get("cpu_tee", {}) or {}
    cpu_type = str(cpu.get("type", "")).strip().lower()
    debug = bool(cpu.get("debug", False))
    secure_boot = bool(cpu.get("secure_boot", False))

    quote = cpu.get("quote") or {}
    quote_present = bool(quote.get("present", False))
    # Chained to the CPU-vendor root: Intel (TDX) / AMD (SEV-SNP) / ARM (Grace CCA).
    quote_chained = bool(quote.get("intel_chained") or quote.get("vendor_chained"))
    quote_verified = bool(quote.get("verified", False))
    quote_debug = bool(quote.get("debug", False))

    is_confidential = cpu_type in _CONFIDENTIAL_TYPES
    issues: list[str] = []
    if not is_confidential:
        issues.append(
            f"CPU is not a confidential VM (cpu_tee.type '{cpu_type or 'none'}' is not TDX/SEV-SNP)"
        )
    # The CVM must be backed by a REAL vendor-verified quote, not an asserted flag.
    if not quote_present:
        issues.append(
            "the CVM state is asserted, not backed by a vendor-signed attestation quote "
            "(no Intel-TDX / AMD-SEV-SNP quote to verify — the second TEE is unchecked)"
        )
    else:
        if not quote_chained:
            issues.append("the CVM quote is not chained to the Intel/AMD root (forged/self-signed)")
        if not quote_verified:
            issues.append("the CVM quote is present but not cryptographically verified")
        if quote_debug:
            issues.append("the CVM quote reports a debug TD/VM (host can read guest memory)")
    if debug:
        issues.append("the CVM is in debug mode")
    if not secure_boot:
        issues.append("Secure Boot is not enabled on the CVM")

    return {
        "cpu_tee_type": cpu_type or None,
        "quote_present": quote_present,
        "quote_chained": quote_chained,
        "quote_verified": quote_verified,
        "debug": debug,
        "secure_boot": secure_boot,
        "issues": issues,
        "passed": not issues,
    }


class GpuCvmBindingCheck(Check):
    check_id = "GPUCC-CVM-01"
    title = "GPU is attached to a verified Confidential VM (real TDX/SEV-SNP quote)"
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
                    "SEV-SNP) and VERIFY its vendor-signed quote (Intel-chained TDX quote / "
                    "SEV-SNP report) — not a self-asserted flag — keep the CVM out of debug "
                    "mode, and enable Secure Boot. The GPU boundary is only as strong as "
                    "the CPU VM it is attached to."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="GPU is attached to a CVM with a verified, vendor-chained quote.",
            evidence=v,
        )
