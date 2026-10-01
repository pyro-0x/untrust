"""GPUCC-KEY-01: the model/data key and workload identity are not a bypass.

Attestation-bound key release (GPUCC-READY-01) is defeated if the key or the
workload identity can be reached some other way. This ports the Confidential Space
SA-bypass family (CSPACE-SA-01/SAKEY-01) to the GPU workload and adds the
GPU-specific DEK-in-env mistake:

  * DEK supplied via host env (our lab's ``MODEL_DEK``) — the untrusted host hands
    the workload the key directly, no attestation needed.
  * no key rotation — a long-lived DEK stolen once decrypts forever.
  * workload SA has user-managed keys — a permanent exported credential.
  * principals can impersonate the workload SA — mint its identity and reach the
    key/data with no attestation.

Input: the key-release policy — ``dek_source`` (only 'kbs' passes), ``key_rotation_days``
(null/0 = none), ``sa_user_managed_keys`` (count), ``sa_impersonators`` (list).
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file


def analyze_key_hygiene(policy: dict[str, Any]) -> dict[str, Any]:
    """Flag host-supplied DEKs, missing rotation, and SA-identity bypasses."""
    dek_source = str(policy.get("dek_source", "")).strip().lower()
    rotation = policy.get("key_rotation_days")
    sa_keys = int(policy.get("sa_user_managed_keys", 0) or 0)
    impersonators = list(policy.get("sa_impersonators") or [])

    issues: list[str] = []
    if dek_source == "env":
        issues.append("the DEK is supplied via host env (the untrusted host hands over the key)")
    elif dek_source != "kbs":
        # Only an attestation-gated KBS release counts; file, metadata, host, or an
        # undeclared source can hand over the key without attestation.
        issues.append(
            f"the DEK source is '{dek_source or 'undeclared'}', not an attestation-gated "
            "KBS (the key can be obtained without attestation)"
        )
    if not rotation:
        issues.append("no key rotation configured (a stolen long-lived DEK decrypts forever)")
    if sa_keys > 0:
        issues.append(f"workload SA has {sa_keys} user-managed key(s) (a permanent credential)")
    if impersonators:
        issues.append(
            f"{len(impersonators)} principal(s) can impersonate the workload SA: "
            f"{', '.join(impersonators)}"
        )

    return {
        "dek_source": dek_source or None,
        "key_rotation_days": rotation,
        "sa_user_managed_keys": sa_keys,
        "sa_impersonators": impersonators,
        "issues": issues,
        "passed": not issues,
    }


class GpuKeyHygieneCheck(Check):
    check_id = "GPUCC-KEY-01"
    title = "Model/data key and workload identity are not an attestation bypass"
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
        v = analyze_key_hygiene(policy)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.FAIL,
                severity=Severity.CRITICAL if v["dek_source"] == "env" else self.severity,
                summary=(
                    "The key/identity is an attestation bypass: "
                    + "; ".join(v["issues"]) + "."
                ),
                remediation=(
                    "Release the DEK only from an attestation-gated KBS (never via host "
                    "env), rotate it, remove workload-SA user-managed keys, and scope "
                    "serviceAccountTokenCreator/actAs so nothing can impersonate the workload."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id, title=self.title, status=Status.PASS,
            severity=self.severity,
            summary="DEK is KBS-released + rotated, and the workload SA can't be impersonated.",
            evidence=v,
        )
