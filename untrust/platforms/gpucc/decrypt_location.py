"""GPUCC-DECRYPT-01: model/data decryption happens inside the TEE, not host RAM.

NVIDIA's own documented gap: during envelope decryption, the plaintext DEK and
the decrypted model weights can briefly exist in **untrusted host RAM** before
being DMA'd into encrypted VRAM. Since the host OS/hypervisor is untrusted and
can read host memory, a deployment that decrypts weights host-side hands the
adversary the very secrets CC is meant to protect. This is the runtime-memory
face of the DEF CON boot-time-input boundary: attestation proves the code, but
*where the input is decrypted* decides whether it is ever exposed.

Input: the key-release policy's ``decrypt_location`` — ``tee`` (decrypt inside the
attested CVM/GPU) vs ``host`` (decrypt in host-visible memory).
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_decrypt_location(policy: dict[str, Any]) -> dict[str, Any]:
    """Assess where model/data decryption occurs relative to the trust boundary."""
    location = str(policy.get("decrypt_location", "")).strip().lower()
    in_tee = location in ("tee", "enclave", "cvm", "gpu")
    issues: list[str] = []
    if not location:
        issues.append("decrypt_location is unset (cannot confirm decryption stays inside the TEE)")
    elif not in_tee:
        issues.append(
            f"decryption occurs in '{location}' — the plaintext DEK and weights transit "
            f"untrusted host memory before reaching encrypted VRAM"
        )
    return {
        "decrypt_location": location or None,
        "in_tee": in_tee,
        "issues": issues,
        "passed": not issues,
    }


class GpuDecryptLocationCheck(Check):
    check_id = "GPUCC-DECRYPT-01"
    title = "Model/data decryption occurs inside the TEE, not untrusted host RAM"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_kbs_policy:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-kbs-policy specified; skipping check.",
            )
        try:
            policy = load_json_file(target.gpu_kbs_policy)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse key-release policy: {e}",
            )
        v = analyze_decrypt_location(policy)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="Decryption is not confined to the TEE: "
                + "; ".join(v["issues"])
                + ".",
                remediation=(
                    "Release the DEK only into the attested CVM/GPU and decrypt weights "
                    "inside the TEE (or stream ciphertext into VRAM and decrypt on-GPU), "
                    "so the plaintext DEK and model never exist in host-readable memory."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Model/data decryption is confined to the TEE.",
            evidence=v,
        )
