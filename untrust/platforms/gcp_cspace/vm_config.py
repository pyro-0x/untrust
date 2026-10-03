"""CSPACE-VM-01: the VM is a Confidential VM on a TEE Confidential Space can attest.

A deployment can *believe* it is confidential while running a plain VM, or a
Confidential VM with Secure Boot / vTPM disabled, or a Confidential Space
workload on hardware the attestation service will not attest. This check reads
the instance config and verifies the hardware/boot posture:

  * confidentialInstanceConfig.enableConfidentialCompute == true
  * confidentialInstanceType is a Confidential VM type: SEV, TDX or SEV_SNP
  * when the VM runs Confidential Space (tee-* launcher metadata or the
    confidential-space image), the type must be one Confidential Space
    attests: AMD SEV or Intel TDX. Google's attestation service rejects SEV-SNP
    (UNSUPPORTED_CC_TECHNOLOGY), so the launcher exits before the workload
    starts and no attestation token is ever issued. SEV-SNP stays fine for a
    plain Confidential VM.
  * shieldedInstanceConfig: Secure Boot, vTPM, and integrity monitoring on
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target

# Confidential VM types, and the subset Confidential Space can attest.
CONFIDENTIAL_TYPES = {"SEV": "AMD SEV", "SEV_SNP": "AMD SEV-SNP", "TDX": "Intel TDX"}
CSPACE_TYPES = {"SEV", "TDX"}


def runs_confidential_space(instance: dict[str, Any]) -> bool:
    """True when the instance boots the Confidential Space launcher."""
    items = (instance.get("metadata", {}) or {}).get("items", []) or []
    if any(str(i.get("key", "")).startswith("tee-image-reference") for i in items):
        return True
    for disk in instance.get("disks", []) or []:
        if any("confidential-space" in str(lic) for lic in disk.get("licenses", []) or []):
            return True
    return False


def analyze_instance_config(instance: dict[str, Any]) -> dict[str, Any]:
    """Pure analysis of a GCP compute instance's confidential/shielded config."""
    conf = instance.get("confidentialInstanceConfig", {}) or {}
    shield = instance.get("shieldedInstanceConfig", {}) or {}

    enable_cc = conf.get("enableConfidentialCompute", False)
    cc_type = conf.get("confidentialInstanceType", "")
    secure_boot = shield.get("enableSecureBoot", False)
    vtpm = shield.get("enableVtpm", False)
    integrity = shield.get("enableIntegrityMonitoring", False)

    cspace = runs_confidential_space(instance)

    issues: list[str] = []
    if not enable_cc:
        issues.append("enableConfidentialCompute is false (not a Confidential VM)")
    if cc_type not in CONFIDENTIAL_TYPES:
        issues.append(
            f"confidentialInstanceType is '{cc_type or 'unset'}' (expected SEV, TDX or SEV_SNP)"
        )
    elif cspace and cc_type not in CSPACE_TYPES:
        issues.append(
            f"runs Confidential Space on {CONFIDENTIAL_TYPES[cc_type]}, which Confidential "
            "Space cannot attest (UNSUPPORTED_CC_TECHNOLOGY): the launcher exits before the "
            "workload starts; use AMD SEV or Intel TDX"
        )
    if not secure_boot:
        issues.append("Secure Boot is disabled")
    if not vtpm:
        issues.append("vTPM is disabled")
    if not integrity:
        issues.append("integrity monitoring is disabled")

    return {
        "enable_confidential_compute": enable_cc,
        "confidential_instance_type": cc_type,
        "tee": CONFIDENTIAL_TYPES.get(cc_type),
        "runs_confidential_space": cspace,
        "secure_boot": secure_boot,
        "vtpm": vtpm,
        "integrity_monitoring": integrity,
        "issues": issues,
        "passed": not issues,
    }


class ConfidentialVmConfigCheck(Check):
    check_id = "CSPACE-VM-01"
    title = "Confidential VM runs an attestable TEE with Shielded boot"
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
                    "Recreate the instance as a Confidential VM (enableConfidentialCompute"
                    "=true) with Shielded VM (Secure Boot, vTPM, integrity monitoring). "
                    "For Confidential Space use confidentialInstanceType=SEV (n2d/c3d) or "
                    "TDX (c3); SEV_SNP suits a plain Confidential VM only."
                ),
                evidence=verdict,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                f"Instance is an {verdict['tee']} Confidential VM with Shielded boot enabled"
                + (", running Confidential Space." if verdict["runs_confidential_space"] else ".")
            ),
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
