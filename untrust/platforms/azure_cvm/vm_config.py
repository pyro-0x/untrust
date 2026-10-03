"""AZ-SKU-01, AZ-BOOT-01, AZ-DISK-01: the VM is really a confidential VM.

An Azure VM is only confidential when three things hold together:

* AZ-SKU-01: ``securityProfile.securityType`` is ``ConfidentialVM`` on a
  confidential size (DCas/ECas v5 and v6 for AMD SEV-SNP, DCes/ECes v5 for Intel
  TDX). Trusted Launch on a general-purpose size gives none of the memory isolation.
* AZ-BOOT-01: Secure Boot and the vTPM are on. The vTPM carries the boot
  measurements MAA attests; without Secure Boot an unsigned boot chain loads.
* AZ-DISK-01: the OS disk uses confidential encryption with the VM guest state
  (``DiskWithVMGuestState``). ``VMGuestStateOnly`` protects the vTPM state but
  leaves the OS disk readable by the host.
"""
from __future__ import annotations

import re
from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target

# Confidential VM families: AMD SEV-SNP (DCas/DCads/ECas/ECads v5 and v6) and
# Intel TDX (DCes/DCeds/ECes/ECeds v5 and v6).
_SNP_SIZE = re.compile(r"Standard_[DE]C\d+a(d)?s_v[56]$", re.IGNORECASE)
_TDX_SIZE = re.compile(r"Standard_[DE]C\d+e(d)?s_v[56]$", re.IGNORECASE)


def tee_of_size(size: str) -> str | None:
    if _SNP_SIZE.match(size or ""):
        return "AMD SEV-SNP"
    if _TDX_SIZE.match(size or ""):
        return "Intel TDX"
    return None


def analyze_sku(vm: dict[str, Any]) -> dict[str, Any]:
    props = vm.get("properties", {}) or {}
    size = (props.get("hardwareProfile") or {}).get("vmSize", "")
    security = props.get("securityProfile") or {}
    security_type = security.get("securityType", "")
    tee = tee_of_size(size)
    issues = []
    if security_type != "ConfidentialVM":
        issues.append(f"securityType is '{security_type or 'Standard'}', not ConfidentialVM")
    if tee is None:
        issues.append(f"size {size or 'unknown'} is not a confidential VM size")
    return {"vm_size": size, "security_type": security_type, "tee": tee,
            "issues": issues, "passed": not issues}


def analyze_boot(vm: dict[str, Any]) -> dict[str, Any]:
    uefi = ((vm.get("properties", {}) or {}).get("securityProfile") or {}).get(
        "uefiSettings") or {}
    secure_boot, vtpm = uefi.get("secureBootEnabled") is True, uefi.get("vTpmEnabled") is True
    issues = []
    if not secure_boot:
        issues.append("Secure Boot is off")
    if not vtpm:
        issues.append("vTPM is off")
    return {"secure_boot": secure_boot, "vtpm": vtpm, "issues": issues, "passed": not issues}


def analyze_disk(vm: dict[str, Any]) -> dict[str, Any]:
    managed = (((vm.get("properties", {}) or {}).get("storageProfile") or {}).get(
        "osDisk") or {}).get("managedDisk") or {}
    profile = managed.get("securityProfile") or {}
    encryption = profile.get("securityEncryptionType", "")
    customer_key = bool((profile.get("diskEncryptionSet") or {}).get("id"))
    issues = []
    if encryption != "DiskWithVMGuestState":
        issues.append("OS disk confidential encryption is "
                      + (f"'{encryption}' (guest state only)" if encryption else "off"))
    return {"security_encryption_type": encryption or None,
            "customer_managed_key": customer_key, "issues": issues, "passed": not issues}


_HINT = "Need --azure-subscription, --azure-resource-group and --azure-vm; skipping check."


class _VmCheck(Check):
    remediation = ""

    def analyze(self, vm: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def run(self, target: Target) -> Finding:
        if not (target.azure_subscription and target.azure_resource_group and target.azure_vm):
            return Finding(self.check_id, self.title, Status.SKIP, self.severity, _HINT)
        try:
            vm = _fetch_vm(target)
        except Exception as e:
            return Finding(self.check_id, self.title, Status.ERROR, self.severity,
                           f"Could not read the VM: {e}")
        verdict = self.analyze(vm)
        if verdict["passed"]:
            return Finding(self.check_id, self.title, Status.PASS, self.severity,
                           self.passed(verdict), evidence=verdict)
        return Finding(self.check_id, self.title, Status.FAIL, self.severity,
                       f"{target.azure_vm}: " + "; ".join(verdict["issues"]) + ".",
                       remediation=self.remediation, evidence=verdict)

    def passed(self, verdict: dict[str, Any]) -> str:
        return "Configured as required."


class AzureCvmSkuCheck(_VmCheck):
    check_id = "AZ-SKU-01"
    title = "VM is a confidential VM on a confidential size"
    severity = Severity.CRITICAL
    remediation = ("Redeploy on a DCas/ECas v5 (SEV-SNP) or DCes/ECes v5 (TDX) size with "
                   "securityType ConfidentialVM; the setting cannot be changed in place.")

    def analyze(self, vm: dict[str, Any]) -> dict[str, Any]:
        return analyze_sku(vm)

    def passed(self, verdict: dict[str, Any]) -> str:
        return f"{verdict['vm_size']} confidential VM on {verdict['tee']}."


class AzureCvmBootCheck(_VmCheck):
    check_id = "AZ-BOOT-01"
    title = "Secure Boot and vTPM are on"
    severity = Severity.HIGH
    remediation = "Enable Secure Boot and the vTPM in the VM's security profile."

    def analyze(self, vm: dict[str, Any]) -> dict[str, Any]:
        return analyze_boot(vm)

    def passed(self, verdict: dict[str, Any]) -> str:
        return "Secure Boot and the vTPM are on."


class AzureCvmDiskCheck(_VmCheck):
    check_id = "AZ-DISK-01"
    title = "OS disk uses confidential encryption with the guest state"
    severity = Severity.HIGH
    remediation = ("Recreate the OS disk with securityEncryptionType DiskWithVMGuestState "
                   "(confidential OS disk encryption), ideally with a customer-managed key.")

    def analyze(self, vm: dict[str, Any]) -> dict[str, Any]:
        return analyze_disk(vm)

    def passed(self, verdict: dict[str, Any]) -> str:
        key = "a customer-managed key" if verdict["customer_managed_key"] else "a platform key"
        return f"OS disk is confidentially encrypted with the guest state, under {key}."


def _fetch_vm(target: Target) -> dict[str, Any]:  # pragma: no cover - live only
    from .arm import vm

    assert target.azure_subscription and target.azure_resource_group and target.azure_vm
    return vm(target.azure_subscription, target.azure_resource_group, target.azure_vm)
