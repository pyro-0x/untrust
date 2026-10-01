"""GPUCC-MODEL-01: the model/weights bootstrap store rejects injection writes.

The DEF CON boundary, applied to confidential AI: a GPU-CC workload loads model
weights, tokenizer, and config from an object store at boot. Attestation proves
the loader code, not the *bytes it loads*. If any principal can write an
adversarially-named object (path traversal, absolute paths) into the model store
and the loader joins that name onto a local path without sanitizing, a single
object upload is boot-time model poisoning or arbitrary file write — the FB-09 /
BOOTSTRAP-01 class, now delivering attacker weights into the enclave.

This actively probes the store with the injection catalog (reusing ``probes/``)
and reports which attack classes it accepts, then deletes the canaries — exactly
like GCS-BOOT-02.
"""

from __future__ import annotations

from ...checks.base import Check, Finding, Severity, Status, Target
from ...probes import ObjectStoreSurface, WriteBlocked, probe_surface

PROBE_CONTENT = b"untrust injection canary - safe to delete"


class GpuModelBootstrapCheck(Check):
    check_id = "GPUCC-MODEL-01"
    title = "Model/weights bootstrap store rejects injection-shaped object writes"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_model_bucket:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-model-bucket specified; skipping check.",
            )
        try:
            surface = _model_store_surface(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not initialize model-store probe: {e}",
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
                    f"Model store refused all {evidence['tested']} injection-shaped canary "
                    f"writes (writes are not open to the audit identity)."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.FAIL,
            severity=self.severity,
            summary=(
                f"Model store accepted {len(report.vulnerable)}/{evidence['tested']} "
                f"injection-shaped object writes across classes: "
                f"{', '.join(report.vulnerable_classes)}. A loader that joins these names "
                f"onto a local path without sanitizing gets attacker weights or arbitrary "
                f"file write (boot-time model poisoning)."
            ),
            remediation=(
                "Scope object-write on the model store to the attested workload identity "
                "only, and sanitize downloaded object names inside the TEE: reject names "
                "whose normalized path escapes the model directory, decode once and "
                "re-check, and refuse absolute paths. Prefer digest-pinned, signed weights."
            ),
            evidence=evidence,
        )


def _model_store_surface(target: Target) -> ObjectStoreSurface:  # pragma: no cover - live only
    """Build an ObjectStoreSurface over the model-weights bucket.

    v1 backs the probe with Google Cloud Storage (``google-cloud-storage``, a core
    dependency); additional backends (S3, Azure Blob) are a fast-follow.
    """
    from google.api_core.exceptions import Forbidden, Unauthorized  # type: ignore
    from google.cloud import storage  # type: ignore

    client = storage.Client(project=target.gcp_project)
    bucket = client.bucket(target.gpu_model_bucket)

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
