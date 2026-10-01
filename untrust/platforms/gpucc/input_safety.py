"""GPUCC-INPUT-01: model weights are loaded safely, not deserialized as code.

GPUCC-MODEL-01 stops an attacker from *placing* a file outside the model dir
(object-name path traversal). It does nothing about the file *content*. Model
weights are attacker-controlled data that originate outside the attestation
boundary, and most inference servers deserialize them with pickle / ``torch.load``
(``torch.load`` uses pickle internally; ``weights_only=False`` was the default
before torch 2.6). A crafted checkpoint's ``__reduce__`` runs arbitrary code the
instant it is loaded — RCE as the attested workload, and it passes every other
check because the GPU attestation certifies the *loader code*, never the *weights*.

This is a distinct entry primitive from traversal: the object NAME is innocent,
the CONTENT executes (see the lab's live DESER-01 finding).

Input: the key-release policy's ``model_input`` block —
``loader`` (e.g. 'safetensors' | 'torch_weights_only' | 'pickle' | 'torch_load'),
``signed_manifest`` (bool), ``verify_digests_before_load`` (bool).
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file

# Loaders that execute arbitrary code while deserializing (the RCE sink).
UNSAFE_LOADERS = {
    "pickle",
    "torch_load",
    "torch",
    "joblib",
    "dill",
    "cloudpickle",
    "numpy_allow_pickle",
    "keras_h5",
}
# Data-only loaders that cannot execute code from the file.
SAFE_LOADERS = {"safetensors", "torch_weights_only", "gguf", "onnx"}


def analyze_model_input(policy: dict[str, Any]) -> dict[str, Any]:
    """Flag code-executing weight loaders and unauthenticated weight bytes."""
    block = policy.get("model_input") or {}
    loader = str(block.get("loader", "")).strip().lower()
    signed = bool(block.get("signed_manifest", False))
    verify_digests = bool(block.get("verify_digests_before_load", False))

    issues: list[str] = []
    unsafe_loader = False
    if not block or not loader:
        unsafe_loader = True
        issues.append(
            "no model-load policy declared (loader unknown — assumed to deserialize "
            "as code; pickle/torch.load run arbitrary code on load)"
        )
    elif loader in UNSAFE_LOADERS:
        unsafe_loader = True
        issues.append(
            f"weights loaded via '{loader}' — deserialization executes arbitrary code on "
            f"load (a crafted checkpoint is RCE as the attested workload)"
        )
    elif loader not in SAFE_LOADERS:
        unsafe_loader = True
        issues.append(
            f"unrecognized loader '{loader}' — cannot confirm it is data-only; treat as "
            f"code-executing until proven otherwise"
        )

    if not signed:
        issues.append("no signed model manifest (weight bytes are unauthenticated)")
    if not verify_digests:
        issues.append("per-object digests are not verified before load")

    return {
        "loader": loader or None,
        "signed_manifest": signed,
        "verify_digests_before_load": verify_digests,
        "unsafe_loader": unsafe_loader,
        "issues": issues,
        "passed": not issues,
    }


class GpuModelInputCheck(Check):
    check_id = "GPUCC-INPUT-01"
    title = "Model weights are loaded safely (not deserialized as code)"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_kbs_policy:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-kbs-policy specified; skipping check.",
            )
        try:
            policy = load_json_file(target.gpu_kbs_policy)
        except Exception as e:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse key-release policy: {e}",
            )
        v = analyze_model_input(policy)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.FAIL,
                severity=Severity.CRITICAL if v["unsafe_loader"] else self.severity,
                summary="Model weights are not loaded safely: " + "; ".join(v["issues"]) + ".",
                remediation=(
                    "Load weights with a data-only format (safetensors) or "
                    "torch.load(weights_only=True); never unpickle untrusted checkpoints. "
                    "Verify a signed model manifest with per-object digests before load, "
                    "inside the TEE. Decouple code from data."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id, title=self.title, status=Status.PASS,
            severity=self.severity,
            summary=(
                f"Weights loaded via a data-only loader ('{v['loader']}') with a signed, "
                f"digest-verified manifest."
            ),
            evidence=v,
        )
