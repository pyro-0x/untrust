"""GCS-BOOT-01: bootstrap-state bucket hardening on GCP.

The GCS port of untrust's S3 bootstrap/rollback/public-access checks. A
Confidential Space workload pulls boot state from a GCS bucket; that bucket is
outside the attestation boundary, so its access control and integrity settings
are the trust boundary. This check flags, in one place:

  * Public exposure — publicAccessPrevention not 'enforced', or an allUsers /
    allAuthenticatedUsers IAM member (S3-01 analog).
  * Fine-grained ACLs — uniformBucketLevelAccess disabled, which re-opens
    per-object ACL public exposure.
  * Broad write scope — object-write roles granted to public or plain
    service-account members (BOOTSTRAP-02 analog).
  * No rollback protection — object versioning disabled and no retention policy
    (ROLLBACK-01 / AUDIT-01 analog): state can be silently overwritten or rolled
    back to an older object the workload re-loads.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target

WRITE_ROLES = frozenset(
    {
        "roles/storage.objectAdmin",
        "roles/storage.objectCreator",
        "roles/storage.legacyBucketWriter",
        "roles/storage.admin",
        "roles/owner",
        "roles/editor",
    }
)

_PUBLIC = ("allusers", "allauthenticatedusers")


def analyze_gcs_bucket(meta: dict[str, Any], bindings: list[dict[str, Any]]) -> dict[str, Any]:
    """Pure analysis of GCS bucket metadata + IAM bindings."""
    iam_cfg = meta.get("iamConfiguration", {}) or {}
    pap = iam_cfg.get("publicAccessPrevention")
    ubla = (iam_cfg.get("uniformBucketLevelAccess", {}) or {}).get("enabled", False)
    versioning = (meta.get("versioning", {}) or {}).get("enabled", False)
    has_retention = bool(meta.get("retentionPolicy"))

    issues: list[str] = []
    if pap != "enforced":
        issues.append(f"publicAccessPrevention is '{pap or 'inherited'}' (expected 'enforced')")
    if not ubla:
        issues.append("uniformBucketLevelAccess is disabled (per-object ACLs can expose state)")

    public_members: list[str] = []
    broad_writers: list[str] = []
    for b in bindings:
        role = b.get("role")
        for member in b.get("members", []):
            if member.strip().lower() in _PUBLIC:
                public_members.append(f"{member} ({role})")
            if role in WRITE_ROLES:
                low = member.strip().lower()
                if low in _PUBLIC or member.startswith("serviceAccount:"):
                    broad_writers.append(f"{member} ({role})")
    if public_members:
        issues.append("public IAM members present: " + ", ".join(public_members))
    if broad_writers:
        issues.append("object-write granted broadly: " + ", ".join(broad_writers))

    if not versioning:
        issues.append("object versioning disabled (silent overwrite / no rollback trail)")
    if not has_retention:
        issues.append("no retention policy (no WORM protection against state rollback)")

    return {
        "public_access_prevention": pap,
        "uniform_bucket_level_access": ubla,
        "versioning": versioning,
        "retention_policy": has_retention,
        "public_members": public_members,
        "broad_writers": broad_writers,
        "issues": issues,
        "passed": not issues,
    }


class GcsBootstrapCheck(Check):
    check_id = "GCS-BOOT-01"
    title = "Bootstrap-state bucket hardening"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gcs_bucket:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gcs-bucket specified; skipping check.",
            )

        try:
            meta, bindings = _fetch_bucket(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read bucket metadata/IAM: {e}",
            )

        verdict = analyze_gcs_bucket(meta, bindings)
        if not verdict["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL if verdict["public_members"] else self.severity,
                summary="Bootstrap bucket is not hardened: " + "; ".join(verdict["issues"]) + ".",
                remediation=(
                    "Set publicAccessPrevention=enforced, enable "
                    "uniformBucketLevelAccess, scope object-write to the workload "
                    "identity only, enable object versioning, and add a retention "
                    "policy (WORM) so bootstrap state cannot be rolled back."
                ),
                evidence=verdict,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "Bootstrap bucket enforces public-access prevention, scoped writes, and versioning."
            ),
            evidence=verdict,
        )


def _fetch_bucket(  # pragma: no cover - live only
    target: Target,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    from googleapiclient.discovery import build  # type: ignore

    service = build("storage", "v1", cache_discovery=False)
    meta: dict[str, Any] = service.buckets().get(bucket=target.gcs_bucket).execute()
    policy = service.buckets().getIamPolicy(bucket=target.gcs_bucket).execute()
    bindings: list[dict[str, Any]] = policy.get("bindings", [])
    return meta, bindings
