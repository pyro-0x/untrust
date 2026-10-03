"""CSPACE-META-01: the Confidential VM's metadata is not broadly mutable.

The most complete attestation bypass on Confidential Space. A principal with
``compute.instances.setMetadata`` on the CS VM can rewrite ``tee-image-reference``
/ ``tee-cmd`` / ``tee-env-*`` — making the launcher pull and run *their* image or
command as the attested workload. Attestation still "passes", now for the
attacker's code. The attacker never had to satisfy the WIF condition or the KMS
policy; they redefined what runs. This audits who can mutate the VM's metadata.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target

# Roles that confer compute.instances.setMetadata.
METADATA_ROLES = frozenset(
    {
        "roles/owner",
        "roles/editor",
        "roles/compute.admin",
        "roles/compute.instanceAdmin",
        "roles/compute.instanceAdmin.v1",
    }
)


def _classify(member: str, workload_sa: str | None) -> str:
    low = member.strip().lower()
    if low in ("allusers", "allauthenticatedusers"):
        return "public"
    if workload_sa and member == f"serviceAccount:{workload_sa}":
        return "workload_sa"  # the workload can rewrite its own image → self-bypass
    if member.startswith("serviceAccount:"):
        return "service_account"
    if member.startswith(("user:", "group:", "domain:")):
        return "identity"
    return "other"


def analyze_metadata_writers(
    bindings: list[dict[str, Any]], workload_sa: str | None = None
) -> dict[str, Any]:
    """Flag principals that can rewrite the VM's tee-* metadata.

    ``bindings`` is the instance IAM policy's bindings array. Weak = public, the
    workload's own SA (self-redefine), or any plain service account.
    """
    weak: list[dict[str, str]] = []
    for b in bindings:
        if b.get("role") not in METADATA_ROLES:
            continue
        for m in b.get("members", []):
            kind = _classify(m, workload_sa)
            if kind in ("public", "workload_sa", "service_account"):
                weak.append({"member": m, "role": b["role"], "kind": kind})
    return {
        "weak_writers": weak,
        "has_public": any(w["kind"] == "public" for w in weak),
        "self_mutate": any(w["kind"] == "workload_sa" for w in weak),
        "passed": not weak,
    }


class ConfidentialSpaceMetadataMutabilityCheck(Check):
    check_id = "CSPACE-META-01"
    title = "Confidential VM metadata is not broadly mutable"
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
            bindings, workload_sa = _fetch_instance_iam(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read instance IAM policy: {e}",
            )

        verdict = analyze_metadata_writers(bindings, workload_sa)
        if not verdict["passed"]:
            members = ", ".join(f"{w['member']} ({w['kind']})" for w in verdict["weak_writers"])
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL
                if verdict["has_public"] or verdict["self_mutate"]
                else self.severity,
                summary=(
                    f"{len(verdict['weak_writers'])} principal(s) can rewrite the VM's "
                    f"metadata (tee-image-reference/tee-cmd/tee-env): {members}. They can "
                    f"run their own code as the attested workload."
                ),
                remediation=(
                    "Restrict compute.instances.setMetadata on this instance to a tight "
                    "human-admin set; never grant metadata-mutating roles to the workload "
                    "SA or to broad/public principals. Prefer immutable, digest-pinned "
                    "deployments recreated by CI rather than in-place metadata edits."
                ),
                evidence=verdict,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="No broad/impersonatable principal can rewrite the VM's tee-* metadata.",
            evidence=verdict,
        )


def _fetch_instance_iam(  # pragma: no cover - live only
    target: Target,
) -> tuple[list[dict[str, Any]], str | None]:
    from googleapiclient.discovery import build  # type: ignore

    compute = build("compute", "v1", cache_discovery=False)
    policy = (
        compute.instances()
        .getIamPolicy(
            project=target.gcp_project, zone=target.gcp_zone, resource=target.gcp_instance
        )
        .execute()
    )
    instance = (
        compute.instances()
        .get(project=target.gcp_project, zone=target.gcp_zone, instance=target.gcp_instance)
        .execute()
    )
    sas = instance.get("serviceAccounts", [])
    workload_sa = sas[0]["email"] if sas else None
    return policy.get("bindings", []), workload_sa
