"""Host attestation platform: verify SEV-SNP reports and TPM2 quotes offline.

The other platforms audit the deployment around a TEE. This one checks the
attestation evidence itself, the way a relying party must before trusting a
host: the signing key chains to a pinned vendor root, the signature verifies,
the evidence carries the verifier's nonce, the host is not in a debug or
insecure-boot state, the TCB is above an anti-rollback floor, and the launch
measurement or PCRs match a pinned baseline. The verdict logic lives in
``verify.py`` so a non-scanner service can reuse it. See ``README.md``.
"""

from __future__ import annotations

from ...checks.base import Assurance, Boundary, Check
from .checks import (
    HostChainCheck,
    HostDebugCheck,
    HostMeasurementCheck,
    HostNonceCheck,
    HostSignatureCheck,
    HostTcbCheck,
)

HOST_CHECKS: list[type[Check]] = [
    HostChainCheck,  # HOST-CHAIN-01
    HostSignatureCheck,  # HOST-SIG-01
    HostNonceCheck,  # HOST-NONCE-01
    HostDebugCheck,  # HOST-DEBUG-01
    HostTcbCheck,  # HOST-TCB-01
    HostMeasurementCheck,  # HOST-MEAS-01
]

# Every verdict is read from the evidence, so each one is only as good as the
# signature check, and the signature is only as good as the chain to a pinned root.
_TRUST = ("HOST-CHAIN-01", "HOST-SIG-01")
ASSURANCE_DEPENDS_ON: dict[str, tuple[str, ...]] = {
    "HOST-CHAIN-01": (),
    "HOST-SIG-01": ("HOST-CHAIN-01",),
    "HOST-NONCE-01": _TRUST,
    "HOST-DEBUG-01": _TRUST,
    "HOST-TCB-01": _TRUST,
    "HOST-MEAS-01": _TRUST,
}

for _cls in HOST_CHECKS:
    _cls.assurance = Assurance.REPORT_DERIVED
    _cls.boundary = Boundary.ATTESTATION
    _cls.assurance_depends_on = ASSURANCE_DEPENDS_ON[_cls.check_id]

__all__ = ["HOST_CHECKS", "ASSURANCE_DEPENDS_ON"]
