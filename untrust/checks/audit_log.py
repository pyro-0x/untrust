"""AUDIT-01: S3 versioning on state bucket.

Verifies that the enclave's state bucket has versioning enabled and
that modifications would be visible through logging. Without this,
an attacker can upload a malicious file and delete the evidence.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class AuditLogCheck(Check):
    check_id = "AUDIT-01"
    title = "S3 versioning and logging on state bucket"
    severity = Severity.LOW

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
        issues: list[str] = []

        try:
            versioning = s3.get_bucket_versioning(Bucket=target.bucket)
            status = versioning.get("Status", "Disabled")
            if status != "Enabled":
                issues.append(f"S3 versioning is {status}")
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not check bucket versioning: {e}",
            )

        try:
            logging_config = s3.get_bucket_logging(Bucket=target.bucket)
            if "LoggingEnabled" not in logging_config:
                issues.append("S3 server access logging is disabled")
        except ClientError:
            issues.append("Could not determine logging status")

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=" | ".join(issues),
                remediation=(
                    "Enable S3 versioning on the state bucket to prevent silent "
                    "overwrites. Enable server access logging or CloudTrail S3 data "
                    "events to create an audit trail of all object operations. "
                    "Consider adding an S3 Object Lock retention policy for "
                    "tamper-proof state integrity."
                ),
                evidence={"issues": issues},
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Bucket has versioning enabled and logging configured.",
        )
