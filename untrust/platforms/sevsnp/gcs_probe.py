"""GCS-BOOT-02: actively probe the bootstrap bucket with injection payloads.

Where GCS-BOOT-01 *reads* the bucket's IAM/config, this check *tests* it: it
attempts to write a canary object for each payload in the injection catalog
(path traversal, encoding bypasses, absolute paths, dangerous sinks) and reports
which classes the bucket accepts, then deletes the canaries.

This is the automated form of hand-testing a bootstrap channel with different
injections. It answers the question config inspection cannot: *from the audit
identity, will the state bucket actually accept an adversarially-shaped object?*
If it does, the only remaining defense is the enclave's download routine
sanitizing the name — the exact link that failed in the Nitro FB-09 class and in
this lab's workload.

  bucket accepts adversarial writes  → FAIL (list the accepted attack classes)
  every write refused (403/denied)   → PASS (writes are not open to this identity)
"""

from __future__ import annotations

from ...checks.base import Check, Finding, Severity, Status, Target
from ...probes import ObjectStoreSurface, WriteBlocked, probe_surface

PROBE_CONTENT = b"untrust injection canary - safe to delete"


class GcsInjectionProbeCheck(Check):
    check_id = "GCS-BOOT-02"
    title = "Bootstrap bucket rejects injection-shaped object writes"
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
            surface = _gcs_surface(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not initialize GCS probe: {e}",
            )

        report = probe_surface(surface)
        evidence = report.as_evidence()

        if not report.any_vulnerable:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary=(
                    f"State bucket refused all {evidence['tested']} injection-shaped "
                    f"canary writes (writes are not open to the audit identity)."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.FAIL,
            severity=self.severity,
            summary=(
                f"State bucket accepted {len(report.vulnerable)}/{evidence['tested']} "
                f"injection-shaped object writes across classes: "
                f"{', '.join(report.vulnerable_classes)}. A bootstrap consumer that "
                f"joins these names onto a local path without sanitizing gets "
                f"arbitrary file write (boot-time RCE — the FB-09 class)."
            ),
            remediation=(
                "Scope object-write on the state bucket to the attested workload "
                "identity only (close the write surface), AND sanitize downloaded "
                "object names enclave-side: reject any name whose normalized path "
                "escapes the intended state directory, decode once and re-check, "
                "and refuse absolute paths."
            ),
            evidence=evidence,
        )


def _gcs_surface(target: Target) -> ObjectStoreSurface:  # pragma: no cover - live only
    """Build an ObjectStoreSurface backed by the target GCS bucket."""
    from google.api_core.exceptions import Forbidden, Unauthorized  # type: ignore
    from google.cloud import storage  # type: ignore

    client = storage.Client(project=target.gcp_project)
    bucket = client.bucket(target.gcs_bucket)

    def put_fn(name: str) -> None:
        try:
            bucket.blob(name).upload_from_string(
                PROBE_CONTENT, content_type="application/octet-stream"
            )
        except (Forbidden, Unauthorized) as e:
            raise WriteBlocked(str(e)) from e

    def delete_fn(name: str) -> None:
        bucket.blob(name).delete()

    return ObjectStoreSurface(put_fn, delete_fn)
