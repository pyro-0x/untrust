"""GCP Confidential Space platform checks (AMD SEV / Intel TDX Confidential VMs).

First increment of untrust's v2.0 roadmap. The catalog starts with the two
highest-signal checks — attestation-bound key release and runtime attestation
state — and grows from here (bootstrap GCS input, IAM least privilege,
Confidential VM config, audit logging).
"""

from __future__ import annotations

from ...checks.base import Check
from .attestation import ConfidentialSpaceAttestationCheck
from .gcs_bootstrap import GcsBootstrapCheck
from .gcs_probe import GcsInjectionProbeCheck
from .image_signing import ConfidentialSpaceImageSigningCheck
from .keybind import ConfidentialSpaceKeyReleaseCheck
from .kms_binding import ConfidentialSpaceKmsBindingCheck
from .metadata_mutability import ConfidentialSpaceMetadataMutabilityCheck
from .sa_identity import (
    ConfidentialSpaceSaImpersonationCheck,
    ConfidentialSpaceSaKeysCheck,
)
from .vm_config import ConfidentialVmConfigCheck
from .wif_siblings import ConfidentialSpaceWifSiblingsCheck

GCP_CSPACE_CHECKS: list[type[Check]] = [
    ConfidentialSpaceKeyReleaseCheck,  # CSPACE-KEYBIND-01
    ConfidentialSpaceKmsBindingCheck,  # CSPACE-KMS-01
    GcsBootstrapCheck,  # GCS-BOOT-01
    GcsInjectionProbeCheck,  # GCS-BOOT-02 (active)
    ConfidentialVmConfigCheck,  # CSPACE-VM-01
    ConfidentialSpaceAttestationCheck,  # CSPACE-ATT-01
    # --- Tier-1 attestation-bypass checks (parallel paths) ---
    ConfidentialSpaceMetadataMutabilityCheck,  # CSPACE-META-01
    ConfidentialSpaceSaImpersonationCheck,  # CSPACE-SA-01
    ConfidentialSpaceSaKeysCheck,  # CSPACE-SAKEY-01
    ConfidentialSpaceWifSiblingsCheck,  # CSPACE-WIF-02
    ConfidentialSpaceImageSigningCheck,  # CSPACE-IMG-01
]

__all__ = [
    "GCP_CSPACE_CHECKS",
    "ConfidentialSpaceKeyReleaseCheck",
    "ConfidentialSpaceKmsBindingCheck",
    "GcsBootstrapCheck",
    "GcsInjectionProbeCheck",
    "ConfidentialVmConfigCheck",
    "ConfidentialSpaceAttestationCheck",
    "ConfidentialSpaceMetadataMutabilityCheck",
    "ConfidentialSpaceSaImpersonationCheck",
    "ConfidentialSpaceSaKeysCheck",
    "ConfidentialSpaceWifSiblingsCheck",
    "ConfidentialSpaceImageSigningCheck",
]
