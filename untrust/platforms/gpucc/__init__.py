"""NVIDIA GPU Confidential Computing platform — Hopper/Blackwell CC surface.

untrust's third platform. Same thesis as the Nitro and Confidential Space
auditors, sharpened for confidential AI: the GPU root-of-trust and its signed
attestation report are sound, but the deployment leaks along the three boundaries
attestation does not cover — the untrusted **inputs** the workload loads
(weights/data), the **runtime memory** those secrets pass through, and the
untrusted **VMM/host** that controls the launch. See ``README.md`` for the
threat model and the deliberate blind spots.
"""

from __future__ import annotations

from ...checks.base import Check
from .attestation import GpuAttestationCheck
from .cc_mode import GpuCcModeCheck
from .cert_chain import GpuCertChainCheck
from .cvm_binding import GpuCvmBindingCheck
from .decrypt_location import GpuDecryptLocationCheck
from .dma_session import GpuDmaSessionCheck
from .launch_mutability import GpuLaunchMutabilityCheck
from .model_bootstrap import GpuModelBootstrapCheck
from .ready_state import GpuReadyStateCheck
from .rim_measurement import GpuRimPinningCheck
from .vram_encryption import GpuVramEncryptionCheck

GPUCC_CHECKS: list[type[Check]] = [
    # A. GPU attestation & verification
    GpuAttestationCheck,  # GPUCC-ATT-01
    GpuRimPinningCheck,  # GPUCC-RIM-01
    GpuCertChainCheck,  # GPUCC-CERT-01
    # B. CC mode & runtime posture
    GpuCcModeCheck,  # GPUCC-MODE-01
    GpuReadyStateCheck,  # GPUCC-READY-01
    # C. Inputs / boot-time state
    GpuModelBootstrapCheck,  # GPUCC-MODEL-01
    GpuDecryptLocationCheck,  # GPUCC-DECRYPT-01
    # D. Runtime memory
    GpuVramEncryptionCheck,  # GPUCC-VRAM-01
    GpuDmaSessionCheck,  # GPUCC-DMA-01
    # E. Runtime VMM / untrusted host
    GpuLaunchMutabilityCheck,  # GPUCC-VMM-META-01
    # F. Underlying CVM
    GpuCvmBindingCheck,  # GPUCC-CVM-01
]

__all__ = [
    "GPUCC_CHECKS",
    "GpuAttestationCheck",
    "GpuRimPinningCheck",
    "GpuCertChainCheck",
    "GpuCcModeCheck",
    "GpuReadyStateCheck",
    "GpuModelBootstrapCheck",
    "GpuDecryptLocationCheck",
    "GpuVramEncryptionCheck",
    "GpuDmaSessionCheck",
    "GpuLaunchMutabilityCheck",
    "GpuCvmBindingCheck",
]
