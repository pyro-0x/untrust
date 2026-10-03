"""CSPACE-IMG-01: workload image signing is enforced and the repo isn't plantable.

Confidential Space will run whatever image the metadata points at. Two gaps let
an attacker swap in their own image (which then attests as itself):

  * signing not enforced — no ``tee-signed-image-repos`` (the launcher's
    SignedImageRepos is empty), so an unsigned image is accepted.
  * writable registry — broad write on the Artifact Registry repo lets an
    attacker push a malicious tag; if the deployment references a tag (not a
    pinned digest), it gets pulled.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target

AR_WRITE_ROLES = frozenset(
    {
        "roles/artifactregistry.writer",
        "roles/artifactregistry.repoAdmin",
        "roles/artifactregistry.admin",
        "roles/owner",
        "roles/editor",
    }
)


def _broad_writer(member: str) -> bool:
    low = member.strip().lower()
    return low in ("allusers", "allauthenticatedusers") or member.startswith("serviceAccount:")


def analyze_image_signing(
    metadata_items: list[dict[str, Any]], ar_bindings: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Assess signing enforcement + Artifact Registry write scope."""
    md = {i.get("key"): i.get("value") for i in metadata_items}
    issues: list[str] = []

    if not md.get("tee-signed-image-repos"):
        issues.append("tee-signed-image-repos is not set — unsigned workload images are accepted")

    image_ref = md.get("tee-image-reference", "")
    if image_ref and "@sha256:" not in image_ref:
        issues.append(f"workload image is referenced by tag, not a pinned digest ({image_ref})")

    broad_writers: list[str] = []
    for b in ar_bindings or []:
        if b.get("role") not in AR_WRITE_ROLES:
            continue
        broad_writers += [m for m in b.get("members", []) if _broad_writer(m)]
    if broad_writers:
        issues.append("Artifact Registry repo is broadly writable: " + ", ".join(broad_writers))

    return {"issues": issues, "broad_writers": broad_writers, "passed": not issues}


class ConfidentialSpaceImageSigningCheck(Check):
    check_id = "CSPACE-IMG-01"
    title = "Workload image signing is enforced and the registry is not plantable"
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
            metadata_items, ar_bindings = _fetch_signing_inputs(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read image-signing inputs: {e}",
            )
        v = analyze_image_signing(metadata_items, ar_bindings)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="Workload image trust is incomplete: " + "; ".join(v["issues"]) + ".",
                remediation=(
                    "Set tee-signed-image-repos and cosign-sign the workload image, reference "
                    "it by @sha256 digest, and scope Artifact Registry write to CI only. "
                    "Consider Binary Authorization for the project."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Image signing is enforced and the workload image is digest-pinned.",
            evidence=v,
        )


def _fetch_signing_inputs(  # pragma: no cover - live only
    target: Target,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from googleapiclient.discovery import build  # type: ignore

    compute = build("compute", "v1", cache_discovery=False)
    instance = (
        compute.instances()
        .get(project=target.gcp_project, zone=target.gcp_zone, instance=target.gcp_instance)
        .execute()
    )
    metadata_items = (instance.get("metadata", {}) or {}).get("items", []) or []

    # Best-effort: derive the Artifact Registry repo from the image reference and
    # read its IAM. Format: LOCATION-docker.pkg.dev/PROJECT/REPO/IMAGE@sha256:...
    ar_bindings: list[dict[str, Any]] = []
    md = {i.get("key"): i.get("value") for i in metadata_items}
    ref = md.get("tee-image-reference", "")
    try:
        host, project, repo, *_ = ref.replace("@", "/").split("/")
        location = host.split("-docker.pkg.dev")[0]
        resource = f"projects/{project}/locations/{location}/repositories/{repo}"
        arsvc = build("artifactregistry", "v1", cache_discovery=False)
        policy = (
            arsvc.projects().locations().repositories().getIamPolicy(resource=resource).execute()
        )
        ar_bindings = policy.get("bindings", [])
    except Exception:
        ar_bindings = []  # image ref unparseable or no access — signing signal still applies
    return metadata_items, ar_bindings
