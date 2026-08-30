"""GPUCC-CERT-01: the device certificate chain is validated to the NVIDIA RoT.

Every genuine NVIDIA CC GPU signs its attestation report with a device identity
key whose certificate chains to an **on-die hardware root of trust** anchored in
the NVIDIA Device Identity CA. If the relying party does not validate that chain
(or trusts a self-signed / operator-supplied cert), an emulated or forged GPU can
present fabricated evidence. The GPU analog of Nitro's signed-EIF (ENCLAVE-04) /
Confidential Space image-signing (CSPACE-IMG-01).

Input: the verifier policy's ``cert_chain_to_nvidia_root`` flag.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_cert_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Assess whether the verifier validates the device cert chain to NVIDIA's RoT."""
    chain_ok = bool(policy.get("cert_chain_to_nvidia_root", False))
    issues: list[str] = []
    if not chain_ok:
        issues.append(
            "verifier does not validate the device certificate chain to the NVIDIA "
            "root of trust — forged/emulated GPU evidence would be accepted"
        )
    return {
        "cert_chain_to_nvidia_root": chain_ok,
        "issues": issues,
        "passed": not issues,
    }


class GpuCertChainCheck(Check):
    check_id = "GPUCC-CERT-01"
    title = "Device certificate chain is validated to the NVIDIA root of trust"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_verifier_policy:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-verifier-policy specified; skipping check.",
            )
        try:
            policy = load_json_file(target.gpu_verifier_policy)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse verifier policy: {e}",
            )
        v = analyze_cert_policy(policy)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="Device cert chain is not validated to NVIDIA's RoT: "
                + "; ".join(v["issues"])
                + ".",
                remediation=(
                    "Enable full certificate-chain validation to the NVIDIA Device "
                    "Identity CA in the verifier/NRAS policy; never trust a self-signed "
                    "or operator-supplied device certificate."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Verifier validates the device cert chain to the NVIDIA root of trust.",
            evidence=v,
        )
