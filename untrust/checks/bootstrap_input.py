"""BOOTSTRAP-01: Bootstrap supply chain — path traversal precondition.

S3 does not sanitize key names — any byte sequence is a valid key.
This means ``../`` in a key is stored literally, not resolved. The
actual path traversal happens in the *downloader* that maps S3 keys
to local filesystem paths (e.g. via os.path.join without sanitization).

This check tests the defense-in-depth precondition: can traversal-
shaped keys be written to the state bucket at all?  If the bucket
policy blocks them, the attack surface is eliminated regardless of
downloader behavior.  If they are accepted, exploitability depends
on the downloader — but the precondition for RCE is satisfied.
"""
from __future__ import annotations

import contextlib

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class BootstrapInputCheck(Check):
    check_id = "BOOTSTRAP-01"
    title = "Bootstrap supply chain — path traversal precondition"
    severity = Severity.CRITICAL

    CANARY_KEYS = [
        "app_module/../canary_untrust_probe",
        "state/../../../tmp/canary_untrust_probe",
        "prefix/..%2F..%2Fcanary_untrust_probe",
        "prefix/....//canary_untrust_probe",
    ]

    # Error codes / HTTP statuses that mean the request could not be evaluated
    # (transient or server-side). These are genuinely ambiguous — the write may
    # or may not have landed — so we surface them as ERROR rather than guessing.
    TRANSIENT_CODES = frozenset({
        "SlowDown",
        "Throttling",
        "ThrottlingException",
        "RequestTimeout",
        "RequestTimeTooSkewed",
        "ServiceUnavailable",
        "InternalError",
        "500",
        "503",
    })

    def run(self, target: Target) -> Finding:
        if not target.bucket:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No target bucket specified; skipping check.",
            )

        s3 = boto3.client("s3", region_name=target.region)
        accepted: list[str] = []
        blocked: list[str] = []
        block_reasons: dict[str, str] = {}

        for key in self.CANARY_KEYS:
            try:
                s3.put_object(
                    Bucket=target.bucket,
                    Key=key,
                    Body=b"untrust-canary-probe",
                    Metadata={"untrust": "audit-probe"},
                )
                accepted.append(key)
            except ClientError as e:
                error = e.response.get("Error", {})
                code = error.get("Code", "")
                http_status = e.response.get("ResponseMetadata", {}).get(
                    "HTTPStatusCode"
                )
                # Transient/server-side failures are ambiguous — the write may
                # or may not have landed — so we cannot conclude anything.
                is_transient = code in self.TRANSIENT_CODES or (
                    isinstance(http_status, int) and http_status >= 500
                )
                if is_transient:
                    return Finding(
                        check_id=self.check_id,
                        title=self.title,
                        status=Status.ERROR,
                        severity=self.severity,
                        summary=f"Transient S3 error during canary probe: {e}",
                    )
                # Any other client-side rejection (403 AccessDenied, or a 400
                # from a policy/encryption condition, etc.) means the object was
                # not created — the traversal-shaped write was blocked. That is
                # the security outcome we want, regardless of the exact code.
                blocked.append(key)
                block_reasons[key] = f"{code or http_status}"

        for key in accepted:
            with contextlib.suppress(ClientError):
                s3.delete_object(Bucket=target.bucket, Key=key)

        if accepted:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"Bucket allows path-traversal-shaped key writes "
                    f"({len(accepted)}/{len(self.CANARY_KEYS)} probes accepted). "
                    f"S3 does not sanitize key names by design — exploitability "
                    f"depends on the enclave's download routine, but this "
                    f"precondition is necessary for the attack."
                ),
                remediation=(
                    "Layer 1 (bucket policy): add a Deny statement that rejects "
                    "s3:PutObject when the key contains '..' path components "
                    "using an s3:prefix or StringLike condition. "
                    "Layer 2 (enclave code): sanitize downloaded key names with "
                    "os.path.normpath() and reject any resolved path that escapes "
                    "the expected directory. Both layers should be applied."
                ),
                evidence={
                    "accepted_keys": accepted,
                    "blocked_keys": blocked,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "Bucket blocks path-traversal-shaped key writes. "
                f"All {len(self.CANARY_KEYS)} canary probes were rejected "
                f"({', '.join(sorted(set(block_reasons.values())))})."
            ),
            evidence={"blocked_keys": blocked, "block_reasons": block_reasons},
        )
