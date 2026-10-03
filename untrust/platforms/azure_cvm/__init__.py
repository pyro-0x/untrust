"""Azure confidential VM platform (``--platform azure-cvm``).

Audits an Azure confidential VM and the Secure Key Release chain that hands it
secrets: the VM's size, security type, boot and disk encryption settings; the
Key Vault key's release policy; the Microsoft Azure Attestation provider that
policy trusts; and, from a token captured in the VM, MAA's own verdict.
"""
from __future__ import annotations

from ...checks.base import Boundary, Check
from .attestation import AzureCvmDebugCheck
from .key_release import AzureAttestationPolicyCheck, AzureSecureKeyReleaseCheck
from .vm_config import AzureCvmBootCheck, AzureCvmDiskCheck, AzureCvmSkuCheck

AZURE_CVM_CHECKS: list[type[Check]] = [
    AzureCvmSkuCheck,  # AZ-SKU-01
    AzureCvmBootCheck,  # AZ-BOOT-01
    AzureCvmDiskCheck,  # AZ-DISK-01
    AzureSecureKeyReleaseCheck,  # AZ-SKR-01
    AzureAttestationPolicyCheck,  # AZ-MAA-01
    AzureCvmDebugCheck,  # AZ-DBG-01
]

for _cls, _boundary in ((AzureCvmSkuCheck, Boundary.CVM), (AzureCvmBootCheck, Boundary.VMM),
                        (AzureCvmDiskCheck, Boundary.MEMORY),
                        (AzureSecureKeyReleaseCheck, Boundary.INPUTS),
                        (AzureAttestationPolicyCheck, Boundary.ATTESTATION),
                        (AzureCvmDebugCheck, Boundary.ATTESTATION)):
    _cls.boundary = _boundary

__all__ = ["AZURE_CVM_CHECKS"]
