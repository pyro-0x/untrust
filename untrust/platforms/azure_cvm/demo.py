"""Demo mode for azure-cvm: a simulated, mis-configured Azure confidential VM.

The findings come from the real analysis functions over synthetic ARM, Key Vault
and MAA responses, so the demo tracks the check logic. No Azure access needed.
"""
from __future__ import annotations

import base64
import json

from ...checks.base import Finding, Status, Target
from . import AZURE_CVM_CHECKS
from .attestation import analyze_claims
from .key_release import analyze_attestation_provider, analyze_release_policy, authorities
from .vm_config import analyze_boot, analyze_disk, analyze_sku

_VM = {"properties": {
    "hardwareProfile": {"vmSize": "Standard_DC4as_v5"},
    "securityProfile": {"securityType": "ConfidentialVM",
                        "uefiSettings": {"secureBootEnabled": False, "vTpmEnabled": True}},
    "storageProfile": {"osDisk": {"managedDisk": {
        "securityProfile": {"securityEncryptionType": "VMGuestStateOnly"}}}}}}
# Release policy that only checks the TEE type: a debuggable CVM gets the key.
_POLICY = {"version": "1.0.0", "anyOf": [{
    "authority": "https://untrustdemo.eus2.attest.azure.net",
    "allOf": [{"claim": "x-ms-isolation-tee.x-ms-attestation-type", "equals": "sevsnpvm"}]}]}
_KEY = {"attributes": {"exportable": True}, "release_policy": {
    "contentType": "application/json; charset=utf-8",
    "data": base64.urlsafe_b64encode(json.dumps(_POLICY).encode()).decode().rstrip("=")}}
_PROVIDER = {"properties": {"attestUri": "https://untrustdemo.eus2.attest.azure.net",
                            "trustModel": "AAD", "status": "Ready"}}
_CLAIMS = {"iss": "https://untrustdemo.eus2.attest.azure.net", "secureboot": False,
           "x-ms-isolation-tee": {"x-ms-attestation-type": "sevsnpvm",
                                  "x-ms-compliance-status": "azure-compliant-cvm",
                                  "x-ms-sevsnpvm-is-debuggable": True}}


def run_azure_cvm_demo() -> tuple[Target, list[Finding]]:
    target = Target(platform="azure-cvm", azure_subscription="00000000-demo",
                    azure_resource_group="cvm-demo", azure_vm="cvm-demo-01",
                    azure_key_vault="kv-demo", azure_key="workload-key")
    key = analyze_release_policy(_KEY)
    verdicts = {
        "AZ-SKU-01": analyze_sku(_VM), "AZ-BOOT-01": analyze_boot(_VM),
        "AZ-DISK-01": analyze_disk(_VM), "AZ-SKR-01": key,
        "AZ-MAA-01": analyze_attestation_provider(authorities(key)[0], _PROVIDER),
        "AZ-DBG-01": analyze_claims(_CLAIMS),
    }
    findings = []
    for cls in AZURE_CVM_CHECKS:
        verdict = verdicts[cls.check_id]
        status = Status.PASS if verdict["passed"] else Status.FAIL
        summary = ("Configured as required." if verdict["passed"]
                   else "; ".join(verdict["issues"]) + ".")
        findings.append(Finding(cls.check_id, cls.title, status, cls.severity, summary,
                                evidence=verdict))
    return target, findings
