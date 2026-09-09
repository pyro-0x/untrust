"""NVIDIA GPU Confidential Computing platform — Hopper/Blackwell CC surface.

untrust's third platform. Same thesis as the Nitro and Confidential Space
auditors, sharpened for confidential AI: the GPU root-of-trust and its signed
attestation report are sound, but the deployment leaks along the boundaries
attestation does not cover — the untrusted **inputs** the workload loads
(weights/data), the **runtime memory** those secrets pass through, the untrusted
**VMM/host** that controls the launch, and the second **CVM** TEE the GPU is
attached to. See ``README.md`` for the threat model and the deliberate blind spots.
"""

from __future__ import annotations

from ...checks.base import Assurance, Boundary, Check
from .attestation import GpuAttestationCheck
from .cc_mode import GpuCcModeCheck
from .cert_chain import GpuCertChainCheck
from .cvm_binding import GpuCvmBindingCheck
from .decrypt_location import GpuDecryptLocationCheck
from .dma_session import GpuDmaSessionCheck
from .failopen import GpuFailOpenCheck
from .gpu_cvm_bind import GpuCvmBindCheck
from .input_safety import GpuModelInputCheck
from .key_hygiene import GpuKeyHygieneCheck
from .launch_mutability import GpuLaunchMutabilityCheck
from .model_bootstrap import GpuModelBootstrapCheck
from .ready_state import GpuReadyStateCheck
from .reattest import GpuReattestCheck
from .rim_measurement import GpuRimPinningCheck
from .signature_verify import GpuSignatureVerifyCheck
from .vram_encryption import GpuVramEncryptionCheck

GPUCC_CHECKS: list[type[Check]] = [
    # A. GPU attestation & verification
    GpuAttestationCheck,  # GPUCC-ATT-01
    GpuRimPinningCheck,  # GPUCC-RIM-01
    GpuCertChainCheck,  # GPUCC-CERT-01
    GpuSignatureVerifyCheck,  # GPUCC-SIGVERIFY-01
    GpuReattestCheck,  # GPUCC-REATTEST-01
    GpuFailOpenCheck,  # GPUCC-FAILOPEN-01
    # B. CC mode & runtime posture
    GpuCcModeCheck,  # GPUCC-MODE-01
    GpuReadyStateCheck,  # GPUCC-READY-01
    # C. Inputs / boot-time state
    GpuModelBootstrapCheck,  # GPUCC-MODEL-01
    GpuModelInputCheck,  # GPUCC-INPUT-01
    GpuDecryptLocationCheck,  # GPUCC-DECRYPT-01
    # D. Runtime memory
    GpuVramEncryptionCheck,  # GPUCC-VRAM-01
    GpuDmaSessionCheck,  # GPUCC-DMA-01
    # E. Runtime VMM / untrusted host
    GpuLaunchMutabilityCheck,  # GPUCC-VMM-META-01
    # F. Underlying CVM (second TEE)
    GpuCvmBindingCheck,  # GPUCC-CVM-01
    GpuCvmBindCheck,  # GPUCC-BIND-01
    # G. Key & identity hygiene
    GpuKeyHygieneCheck,  # GPUCC-KEY-01
]

# --- Evidence tiering (see checks.base.Assurance) --------------------------
# How much a PASS from each check can be trusted — the honest counterweight to the
# pass-count. Report-reading checks are REPORT_DERIVED; the probe is PROBED; the
# rest only confirm an operator-authored policy/config (DECLARED — a lying policy
# passes). REPORT_DERIVED is trustworthy only as far as the report signature is
# verified: each depends on GPUCC-SIGVERIFY-01, and the runner flags "unverified
# report" when that hasn't passed. RIM-01 is DECLARED by default but PROMOTES itself
# to REPORT_DERIVED at runtime when it cross-checks golden values against the report.
ASSURANCE_BY_ID: dict[str, Assurance] = {
    "GPUCC-ATT-01": Assurance.REPORT_DERIVED,
    "GPUCC-VRAM-01": Assurance.REPORT_DERIVED,
    "GPUCC-DMA-01": Assurance.REPORT_DERIVED,
    "GPUCC-CVM-01": Assurance.REPORT_DERIVED,
    "GPUCC-BIND-01": Assurance.REPORT_DERIVED,
    "GPUCC-MODEL-01": Assurance.PROBED,
    "GPUCC-RIM-01": Assurance.DECLARED,  # promotes to REPORT_DERIVED when values checked
    "GPUCC-CERT-01": Assurance.DECLARED,
    "GPUCC-SIGVERIFY-01": Assurance.DECLARED,
    "GPUCC-REATTEST-01": Assurance.DECLARED,
    "GPUCC-FAILOPEN-01": Assurance.DECLARED,
    "GPUCC-MODE-01": Assurance.DECLARED,
    "GPUCC-READY-01": Assurance.DECLARED,
    "GPUCC-INPUT-01": Assurance.DECLARED,
    "GPUCC-DECRYPT-01": Assurance.DECLARED,
    "GPUCC-VMM-META-01": Assurance.DECLARED,
    "GPUCC-KEY-01": Assurance.DECLARED,
}

# Report-derived verdicts are only as trustworthy as the report's signature check.
_SIG = ("GPUCC-SIGVERIFY-01",)
ASSURANCE_DEPENDS_ON: dict[str, tuple[str, ...]] = {
    "GPUCC-ATT-01": _SIG,
    "GPUCC-VRAM-01": _SIG,
    "GPUCC-DMA-01": _SIG,
    "GPUCC-CVM-01": _SIG,
    "GPUCC-BIND-01": _SIG,
    "GPUCC-RIM-01": _SIG,
}

# Which trust boundary each check audits (the untrust/DEF CON thesis). Surfaced in
# `list-checks` so the output explains *why* each check exists, not just what it is.
BOUNDARY_BY_ID: dict[str, Boundary] = {
    "GPUCC-ATT-01": Boundary.ATTESTATION,
    "GPUCC-RIM-01": Boundary.ATTESTATION,
    "GPUCC-CERT-01": Boundary.ATTESTATION,
    "GPUCC-SIGVERIFY-01": Boundary.ATTESTATION,
    "GPUCC-REATTEST-01": Boundary.ATTESTATION,
    "GPUCC-FAILOPEN-01": Boundary.ATTESTATION,
    "GPUCC-MODE-01": Boundary.ATTESTATION,
    "GPUCC-READY-01": Boundary.ATTESTATION,
    "GPUCC-MODEL-01": Boundary.INPUTS,
    "GPUCC-INPUT-01": Boundary.INPUTS,
    "GPUCC-DECRYPT-01": Boundary.INPUTS,
    "GPUCC-KEY-01": Boundary.INPUTS,
    "GPUCC-VRAM-01": Boundary.MEMORY,
    "GPUCC-DMA-01": Boundary.MEMORY,
    "GPUCC-VMM-META-01": Boundary.VMM,
    "GPUCC-CVM-01": Boundary.CVM,
    "GPUCC-BIND-01": Boundary.CVM,
}

# Stamp tier, dependency, and boundary onto each check class (KeyError = untagged).
for _cls in GPUCC_CHECKS:
    _cls.assurance = ASSURANCE_BY_ID[_cls.check_id]
    _cls.boundary = BOUNDARY_BY_ID[_cls.check_id]
    _cls.assurance_depends_on = ASSURANCE_DEPENDS_ON.get(_cls.check_id, ())

__all__ = [
    "GPUCC_CHECKS",
    "ASSURANCE_BY_ID",
    "BOUNDARY_BY_ID",
    "GpuAttestationCheck",
    "GpuRimPinningCheck",
    "GpuCertChainCheck",
    "GpuCcModeCheck",
    "GpuReadyStateCheck",
    "GpuModelBootstrapCheck",
    "GpuModelInputCheck",
    "GpuDecryptLocationCheck",
    "GpuVramEncryptionCheck",
    "GpuDmaSessionCheck",
    "GpuLaunchMutabilityCheck",
    "GpuCvmBindingCheck",
    "GpuCvmBindCheck",
    "GpuSignatureVerifyCheck",
    "GpuReattestCheck",
    "GpuFailOpenCheck",
    "GpuKeyHygieneCheck",
]
