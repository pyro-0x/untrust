"""CSPACE-VM-01: the VM is actually a SEV-SNP Confidential VM with Shielded boot.

A deployment can *believe* it is confidential while running a plain VM, or a
SEV VM without the SEV-SNP attestation report, or a Confidential VM with Secure
Boot / vTPM disabled. This check reads the instance config and verifies the
hardware/boot posture the whole SEV-SNP story depends on:

  * confidentialInstanceConfig.enableConfidentialCompute == true
  * confidentialInstanceType == 'SEV_SNP' (plain 'SEV' lacks the SNP report;
    'TDX' is the wrong platform for a gcp-cspace audit)
  * shieldedInstanceConfig: Secure Boot, vTPM, and integrity monitoring on
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target


def analyze_instance_config(instance: dict[str, Any]) -> dict[str, Any]:
    """Pure analysis of a GCP compute instance's confidential/shielded config."""
    conf = instance.get("confidentialInstanceConfig", {}) or {}
    shield = instance.get("shieldedInstanceConfig", {}) or {}

    enable_cc = conf.get("enableConfidentialCompute", False)
    cc_type = conf.get("confidentialInstanceType", "")
    secure_boot = shield.get("enableSecureBoot", False)
    vtpm = shield.get("enableVtpm", False)
    integrity = shield.get("enableIntegrityMonitoring", False)

    issues: list[str] = []
    if not enable_cc:
        issues.append("enableConfidentialCompute is false (not a Confidential VM)")
    if cc_type != "SEV_SNP":
        issues.append(f"confidentialInstanceType is '{cc_type or 'unset'}' (expected SEV_SNP)")
    if not secure_boot:
        issues.append("Secure Boot is disabled")
    if not vtpm:
        issues.append("vTPM is disabled")
    if not integrity:
        issues.append("integrity monitoring is disabled")

    return {
        "enable_confidential_compute": enable_cc,
        "confidential_instance_type": cc_type,
        "secure_boot": secure_boot,
        "vtpm": vtpm,
        "integrity_monitoring": integrity,
        "issues": issues,
        "passed": not issues,
    }


class ConfidentialVmConfigCheck(Check):
    check_id = "CSPACE-VM-01"
    title = "Confidential VM runs SEV-SNP with Shielded boot"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not (target.gcp_instance and target.gcp_zone and target.gcp_project):
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="Need --gcp-instance, --gcp-zone, and --gcp-project; skipping check.",
            )

        try:
            instance = _fetch_instance(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read instance config: {e}",
            )

        verdict = analyze_instance_config(instance)
        if not verdict["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "Confidential VM posture is incomplete: " + "; ".join(verdict["issues"]) + "."
                ),
                remediation=(
                    "Recreate the instance with confidentialInstanceType=SEV_SNP, "
                    "enableConfidentialCompute=true, and Shielded VM (Secure Boot, "
                    "vTPM, integrity monitoring) enabled."
                ),
                evidence=verdict,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Instance is a SEV-SNP Confidential VM with Shielded boot enabled.",
            evidence=verdict,
        )


def _fetch_instance(target: Target) -> dict:  # pragma: no cover - live only
    from googleapiclient.discovery import build  # type: ignore

    service = build("compute", "v1", cache_discovery=False)
    instance: dict[str, Any] = (
        service.instances()
        .get(project=target.gcp_project, zone=target.gcp_zone, instance=target.gcp_instance)
        .execute()
    )
    return instance
