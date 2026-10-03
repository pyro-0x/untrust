"""CSPACE-KEYBIND-01: attestation-bound key release on GCP Confidential Space.

This is the SEV-SNP analog of Nitro's KMS-01. On Confidential Space, a workload
proves itself with an attestation token and exchanges it — through a Workload
Identity Federation (WIF) provider — for access to Cloud KMS / Secret Manager.
The WIF provider's *attribute condition* (a CEL expression) is the gate. If that
condition does not bind key release to a real code measurement, the attestation
guarantee is bypassed at the key-release layer exactly as an unconditioned KMS
policy bypasses it on Nitro.

The two code-measurement bindings that matter (both must be present):

  * ``assertion.dbgstat == 'disabled-since-boot'`` — the VM is not in debug mode.
    A debug Confidential Space VM weakens the isolation you are relying on.
  * ``assertion.submods.container.image_digest`` pinned to a specific
    ``sha256:...`` — the workload *image* is fixed. Binding to identity (the
    service account / audience) without pinning the image is the Confidential
    Space equivalent of Nitro's PCR3/PCR4-only "identity_only" bypass: it proves
    *who* launched the workload, not *what code* is running.

Recommended-but-not-gating bindings (reported as additional weaknesses):
``swname == 'CONFIDENTIAL_SPACE'``, ``hwmodel`` bound to the TEE (``GCP_AMD_SEV`` or
``GCP_INTEL_TDX``), and a
``support_attributes`` constraint that keeps USABLE (debug-tooling) images out.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target


def analyze_wif_condition(condition: str | None) -> dict[str, Any]:
    """Statically analyze a WIF provider attribute condition (CEL text).

    Pure and side-effect free so it is trivially unit-testable and is shared by
    the live check and the demo. Returns a structured verdict dict.
    """
    text = condition or ""
    t = text.lower()
    has_condition = bool(text.strip())

    mentions_image_digest = "image_digest" in t
    pins_image_digest = mentions_image_digest and "sha256:" in t

    result: dict[str, Any] = {
        "has_condition": has_condition,
        # gating (code-measurement) bindings
        "binds_dbgstat": ("dbgstat" in t) and ("disabled-since-boot" in t),
        "pins_image_digest": pins_image_digest,
        "image_digest_present_only": mentions_image_digest and not pins_image_digest,
        # recommended bindings
        "binds_swname": ("swname" in t) and ("confidential_space" in t),
        "binds_hwmodel": ("hwmodel" in t) and ("gcp_amd_sev" in t or "gcp_intel_tdx" in t),
        "constrains_support_attributes": ("support_attributes" in t) and ("stable" in t),
    }

    gating_weaknesses: list[str] = []
    if not result["binds_dbgstat"]:
        gating_weaknesses.append(
            "does not require assertion.dbgstat == 'disabled-since-boot' "
            "(a debug Confidential Space VM could release the key)"
        )
    if not result["pins_image_digest"]:
        if result["image_digest_present_only"]:
            gating_weaknesses.append(
                "references image_digest but does not pin it to a specific "
                "sha256 digest (any workload image satisfies the condition)"
            )
        else:
            gating_weaknesses.append(
                "does not bind the workload image_digest — key release is gated "
                "on identity, not on a code measurement"
            )

    recommended_weaknesses: list[str] = []
    if not result["constrains_support_attributes"]:
        recommended_weaknesses.append(
            "does not constrain support_attributes (USABLE/debug-tooling images are not excluded)"
        )
    if not result["binds_swname"]:
        recommended_weaknesses.append("does not assert swname == 'CONFIDENTIAL_SPACE'")
    if not result["binds_hwmodel"]:
        recommended_weaknesses.append(
            "does not bind hwmodel to the TEE (GCP_AMD_SEV or GCP_INTEL_TDX)"
        )

    result["gating_weaknesses"] = gating_weaknesses
    result["recommended_weaknesses"] = recommended_weaknesses
    # PASS only when both code-measurement bindings are present.
    result["passed"] = has_condition and not gating_weaknesses
    return result


def _fetch_condition(target: Target) -> str | None:
    """Fetch the provider's attribute condition from GCP.

    Uses the IAM WorkloadIdentityPools API via google-api-python-client (a core
    dependency). Raises on API error so the check surfaces ERROR with actionable
    guidance.
    """
    from googleapiclient.discovery import build  # type: ignore

    # provider resource: projects/*/locations/global/workloadIdentityPools/*/providers/*
    service = build("iam", "v1", cache_discovery=False)
    provider = (
        service.projects()
        .locations()
        .workloadIdentityPools()
        .providers()
        .get(name=target.wip_provider)
        .execute()
    )
    condition: str | None = provider.get("attributeCondition")
    return condition


class ConfidentialSpaceKeyReleaseCheck(Check):
    check_id = "CSPACE-KEYBIND-01"
    title = "Confidential Space key release binds to a code measurement"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.wip_provider:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --wip-provider specified; skipping check.",
            )

        try:
            condition = _fetch_condition(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read WIF provider condition: {e}",
            )

        verdict = analyze_wif_condition(condition)

        if not verdict["has_condition"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "WIF provider has no attribute condition — any Confidential "
                    "Space token admitted to the pool can release the key, "
                    "regardless of debug status or workload image."
                ),
                remediation=_REMEDIATION,
                evidence=verdict,
            )

        if not verdict["passed"]:
            reasons = "; ".join(verdict["gating_weaknesses"])
            if verdict["recommended_weaknesses"]:
                reasons += ". Additionally, it " + "; ".join(verdict["recommended_weaknesses"])
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"WIF provider condition does not bind key release to a code "
                    f"measurement: it {reasons}."
                ),
                remediation=_REMEDIATION,
                evidence=verdict,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "WIF provider condition binds key release to dbgstat="
                "disabled-since-boot and a pinned image_digest."
            ),
            evidence=verdict,
        )


_REMEDIATION = (
    "Set an attribute condition on the WIF provider that binds every access to a "
    "code measurement, e.g.:\n"
    "  assertion.swname == 'CONFIDENTIAL_SPACE' &&\n"
    "  assertion.dbgstat == 'disabled-since-boot' &&\n"
    "  assertion.submods.container.image_digest == 'sha256:<pinned-digest>'\n"
    "Pin the image_digest to your CI-built workload image, and prefer keeping "
    "support_attributes constrained so USABLE (debug-tooling) images are "
    "excluded. Binding only the audience/service account proves identity, not "
    "code."
)
