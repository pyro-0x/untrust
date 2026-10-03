"""CSPACE-KMS-01: Cloud KMS decrypt is granted to the attested pool, not identity.

The partner to CSPACE-KEYBIND-01. KEYBIND-01 audits *what the WIF provider
condition proves*; this audits *who the key's IAM policy hands decrypt to*. Even
a perfect provider condition is moot if the Cloud KMS key grants decrypt to
``allAuthenticatedUsers`` or to a plain service account that any VM can
impersonate — the request never has to come through the attested pool at all.

A decrypt grant is only trustworthy when its member is a
``principalSet://iam.googleapis.com/.../workloadIdentityPools/...`` reference —
i.e. access is federated through Workload Identity, so the attestation token
(gated by the provider condition) is on the path. Members like ``allUsers``,
``allAuthenticatedUsers``, ``serviceAccount:``, ``user:``/``group:`` prove
identity or nothing, not attested code.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target

# Roles that confer (or contain) KMS decrypt.
DECRYPT_ROLES = frozenset(
    {
        "roles/cloudkms.cryptoKeyDecrypter",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "roles/cloudkms.admin",
        "roles/owner",
        "roles/editor",
    }
)


def _classify_member(member: str) -> str:
    m = member.strip()
    low = m.lower()
    if low in ("allusers", "allauthenticatedusers"):
        return "public"
    if m.startswith("principalSet://iam.googleapis.com/") and "/workloadidentitypools/" in low:
        # scoped to a specific attribute vs. the whole pool
        if "/attribute." in low or "/subject/" in low:
            return "attested_scoped"
        return "attested_pool"
    if m.startswith("serviceAccount:"):
        return "service_account"
    if m.startswith(("user:", "group:", "domain:")):
        return "identity"
    return "other"


def analyze_kms_bindings(bindings: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze a Cloud KMS key's IAM bindings for attestation-federated decrypt.

    ``bindings`` is the ``bindings`` array of an IAM policy: ``[{"role":..,
    "members":[..]}]``. Pure and unit-testable.
    """
    weak: list[dict] = []
    strong: list[dict] = []
    has_public = False

    for b in bindings:
        if b.get("role") not in DECRYPT_ROLES:
            continue
        for member in b.get("members", []):
            kind = _classify_member(member)
            entry = {"role": b["role"], "member": member, "kind": kind}
            if kind in ("attested_scoped", "attested_pool"):
                strong.append(entry)
            else:
                weak.append(entry)
                if kind == "public":
                    has_public = True

    return {
        "weak_grants": weak,
        "federated_grants": strong,
        "has_public": has_public,
        # PASS when nothing weak grants decrypt (either no decrypt at all, or
        # every decrypt member is Workload-Identity-federated).
        "passed": not weak,
    }


class ConfidentialSpaceKmsBindingCheck(Check):
    check_id = "CSPACE-KMS-01"
    title = "Cloud KMS decrypt is federated through the attested pool"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gcp_kms_key:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gcp-kms-key specified; skipping check.",
            )

        try:
            bindings = _fetch_kms_bindings(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read KMS key IAM policy: {e}",
            )

        verdict = analyze_kms_bindings(bindings)
        if not verdict["passed"]:
            members = ", ".join(f"{g['member']} ({g['role']})" for g in verdict["weak_grants"])
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL if verdict["has_public"] else self.severity,
                summary=(
                    f"{len(verdict['weak_grants'])} decrypt grant(s) are not "
                    f"federated through a Workload Identity pool: {members}. "
                    f"Access does not require an attestation token."
                ),
                remediation=(
                    "Grant KMS decrypt only to a principalSet:// member scoped to "
                    "the Confidential Space workload identity pool (ideally to a "
                    "specific attribute), and remove allUsers/allAuthenticatedUsers "
                    "and plain service-account grants."
                ),
                evidence=verdict,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=("All KMS decrypt grants are federated through a Workload Identity pool."),
            evidence=verdict,
        )


def _fetch_kms_bindings(target: Target) -> list[dict[str, Any]]:  # pragma: no cover - live only
    from googleapiclient.discovery import build  # type: ignore

    service = build("cloudkms", "v1", cache_discovery=False)
    policy = (
        service.projects()
        .locations()
        .keyRings()
        .cryptoKeys()
        .getIamPolicy(resource=target.gcp_kms_key)
        .execute()
    )
    bindings: list[dict[str, Any]] = policy.get("bindings", [])
    return bindings
