"""HOST-* checks: one finding per verifier control (see ``verify.py``).

Each check re-runs the verifier over the same evidence and reports its own
control, so the scanner gets one finding per control while the verdict logic
lives in a single library function.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from .verify import HostVerdict, load_baseline, load_evidence, verify


def run_verifier(target: Target) -> HostVerdict:
    if not target.host_evidence:
        raise ValueError("no --host-evidence specified")
    evidence = load_evidence(target.host_evidence)
    baseline = load_baseline(target.host_baseline) if target.host_baseline else {}
    nonce = bytes.fromhex(target.host_nonce) if target.host_nonce else None
    return verify(evidence, baseline, nonce)


class HostControlCheck(Check):
    control: str = ""
    remediation: str = ""
    # Summary used when a control has no input to assess (passed is None).
    unassessed: str = ""

    def _finding(self, status: Status, summary: str, **kw: Any) -> Finding:
        return Finding(check_id=self.check_id, title=self.title, status=status,
                       severity=self.severity, summary=summary, **kw)

    def run(self, target: Target) -> Finding:
        if not target.host_evidence:
            return self._finding(Status.SKIP, "No --host-evidence specified; skipping check.")
        try:
            verdict = run_verifier(target)
        except Exception as e:
            return self._finding(Status.ERROR, f"Could not load host evidence: {e}")
        c = verdict.controls[self.control]
        evidence = {"evidence_type": verdict.evidence_type, **c.evidence}
        if c.passed is None:
            return self._finding(Status.SKIP, self.unassessed, evidence=evidence)
        if not c.passed:
            return self._finding(
                Status.FAIL, f"{verdict.evidence_type}: " + "; ".join(c.issues) + ".",
                remediation=self.remediation, evidence={**evidence, "issues": c.issues})
        return self._finding(Status.PASS, f"{verdict.evidence_type}: {self.title}.",
                             evidence=evidence)


class HostChainCheck(HostControlCheck):
    check_id = "HOST-CHAIN-01"
    title = "Evidence signing key chains to a pinned vendor root"
    severity = Severity.CRITICAL
    control = "chain"
    remediation = (
        "Validate the full VCEK/VLEK -> ASK -> ARK (or AK -> CA) chain and pin the "
        "root's SHA-256 fingerprint in the baseline; never accept a root because the "
        "evidence supplied it."
    )


class HostSignatureCheck(HostControlCheck):
    check_id = "HOST-SIG-01"
    title = "Attestation evidence signature verifies"
    severity = Severity.CRITICAL
    control = "signature"
    remediation = (
        "Verify the report/quote signature with the certified key before reading any "
        "field; reject unsigned (MASK_CHIP_KEY) reports and SHA-1 quotes."
    )


class HostNonceCheck(HostControlCheck):
    check_id = "HOST-NONCE-01"
    title = "Evidence is bound to the verifier's fresh nonce"
    severity = Severity.HIGH
    control = "nonce"
    unassessed = ("No --host-nonce supplied; freshness is unproven, so a replayed "
                  "report or quote cannot be ruled out.")
    remediation = (
        "Issue a single-use random nonce per attestation and require it in SNP "
        "REPORT_DATA or the TPM quote's qualifying data (extraData)."
    )


class HostDebugCheck(HostControlCheck):
    check_id = "HOST-DEBUG-01"
    title = "Host is not in a debug or insecure-boot state"
    severity = Severity.CRITICAL
    control = "debug"
    unassessed = ("No event log in the TPM evidence; Secure Boot state cannot be "
                  "verified.")
    remediation = (
        "SEV-SNP: launch with the DEBUG and MIGRATE_MA policy bits clear. TPM2: boot "
        "with UEFI Secure Boot on, quote PCR 7, and ship the event log with the quote."
    )


class HostTcbCheck(HostControlCheck):
    check_id = "HOST-TCB-01"
    title = "Platform TCB meets the anti-rollback floor"
    severity = Severity.HIGH
    control = "tcb"
    remediation = (
        "Set min_tcb (SNP bootloader/TEE/SNP/microcode SVNs) or min_firmware_version "
        "(TPM) in the baseline from the vendor's current security bulletin, and fetch "
        "the VCEK for the report's REPORTED_TCB."
    )


class HostMeasurementCheck(HostControlCheck):
    check_id = "HOST-MEAS-01"
    title = "Launch measurement or PCRs match the pinned baseline"
    severity = Severity.CRITICAL
    control = "measurement"
    remediation = (
        "Pin golden launch measurements (SNP) or PCR values (TPM) per host class, quote "
        "every pinned PCR, and verify the event log replays to the quoted values."
    )
