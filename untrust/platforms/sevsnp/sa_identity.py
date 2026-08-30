"""CSPACE-SA-01 / CSPACE-SAKEY-01: the workload service account is not a bypass.

Confidential Space binds attestation to the workload identity. But the workload
*runs as* a GCP service account, and where KMS/GCS trust that SA (the vulnerable
posture), two parallel paths reach the keys without any attestation token:

  * SA impersonation — a principal with iam.serviceAccounts.getAccessToken /
    actAs on the SA can mint tokens as it and call KMS/GCS directly.
  * SA user-managed keys — a long-lived JSON key is a permanent credential;
    steal it once and attestation is irrelevant forever.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target

# Roles on a service account that let a principal act as / mint tokens for it.
IMPERSONATION_ROLES = frozenset(
    {
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountUser",
        "roles/iam.serviceAccountOpenIdTokenCreator",
        "roles/iam.workloadIdentityUser",
        "roles/owner",
        "roles/editor",
    }
)


def analyze_sa_impersonation(bindings: list[dict[str, Any]]) -> dict[str, Any]:
    """Flag principals that can impersonate the workload SA."""
    impersonators: list[dict[str, str]] = []
    for b in bindings:
        if b.get("role") not in IMPERSONATION_ROLES:
            continue
        for m in b.get("members", []):
            low = m.strip().lower()
            kind = (
                "public"
                if low in ("allusers", "allauthenticatedusers")
                else ("service_account" if m.startswith("serviceAccount:") else "identity")
            )
            impersonators.append({"member": m, "role": b["role"], "kind": kind})
    return {
        "impersonators": impersonators,
        "has_public": any(i["kind"] == "public" for i in impersonators),
        "passed": not impersonators,
    }


def analyze_sa_keys(keys: list[dict[str, Any]]) -> dict[str, Any]:
    """Flag user-managed (long-lived) keys on the workload SA."""
    user_managed = [
        {"name": k.get("name", "").rsplit("/", 1)[-1], "valid_after": k.get("validAfterTime", "")}
        for k in keys
        if k.get("keyType") == "USER_MANAGED"
    ]
    return {
        "user_managed_keys": user_managed,
        "count": len(user_managed),
        "passed": not user_managed,
    }


class ConfidentialSpaceSaImpersonationCheck(Check):
    check_id = "CSPACE-SA-01"
    title = "Workload SA cannot be impersonated to bypass attestation"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not (target.gcp_instance and target.gcp_zone and target.gcp_project):
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="Need --gcp-instance, --gcp-zone, and --gcp-project; skipping check.",
            )
        try:
            bindings = _fetch_sa_iam(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read SA IAM policy: {e}",
            )
        v = analyze_sa_impersonation(bindings)
        if not v["passed"]:
            members = ", ".join(f"{i['member']} ({i['role']})" for i in v["impersonators"])
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL if v["has_public"] else self.severity,
                summary=(
                    f"{len(v['impersonators'])} principal(s) can impersonate the workload "
                    f"SA: {members}. They can mint tokens as the SA and reach KMS/GCS with "
                    f"no attestation."
                ),
                remediation=(
                    "Remove serviceAccountTokenCreator / serviceAccountUser / "
                    "workloadIdentityUser grants on the workload SA except where strictly "
                    "required, and never to broad/public principals."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="No principal can impersonate the workload SA.",
            evidence=v,
        )


class ConfidentialSpaceSaKeysCheck(Check):
    check_id = "CSPACE-SAKEY-01"
    title = "Workload SA has no long-lived user-managed keys"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not (target.gcp_instance and target.gcp_zone and target.gcp_project):
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="Need --gcp-instance, --gcp-zone, and --gcp-project; skipping check.",
            )
        try:
            keys = _fetch_sa_keys(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not list SA keys: {e}",
            )
        v = analyze_sa_keys(keys)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"Workload SA has {v['count']} user-managed key(s). A stolen long-lived "
                    f"key reaches KMS/GCS permanently, with no attestation."
                ),
                remediation=(
                    "Delete user-managed keys on the workload SA and disable key creation "
                    "(org policy iam.disableServiceAccountKeyCreation). The CS VM uses the "
                    "attached SA via the metadata server — it needs no exported keys."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Workload SA has no user-managed keys.",
            evidence=v,
        )


def _sa_email(target: Target) -> str:  # pragma: no cover - live only
    from googleapiclient.discovery import build  # type: ignore

    compute = build("compute", "v1", cache_discovery=False)
    instance = (
        compute.instances()
        .get(project=target.gcp_project, zone=target.gcp_zone, instance=target.gcp_instance)
        .execute()
    )
    sas = instance.get("serviceAccounts", [])
    if not sas:
        raise RuntimeError("instance has no attached service account")
    email: str = sas[0]["email"]
    return email


def _fetch_sa_iam(target: Target) -> list[dict[str, Any]]:  # pragma: no cover - live only
    from googleapiclient.discovery import build  # type: ignore
    email = _sa_email(target)
    iam = build("iam", "v1", cache_discovery=False)
    policy = (
        iam.projects()
        .serviceAccounts()
        .getIamPolicy(resource=f"projects/-/serviceAccounts/{email}")
        .execute()
    )
    bindings: list[dict[str, Any]] = policy.get("bindings", [])
    return bindings


def _fetch_sa_keys(target: Target) -> list[dict[str, Any]]:  # pragma: no cover - live only
    from googleapiclient.discovery import build  # type: ignore
    email = _sa_email(target)
    iam = build("iam", "v1", cache_discovery=False)
    resp = (
        iam.projects()
        .serviceAccounts()
        .keys()
        .list(name=f"projects/-/serviceAccounts/{email}", keyTypes="USER_MANAGED")
        .execute()
    )
    keys: list[dict[str, Any]] = resp.get("keys", [])
    return keys
