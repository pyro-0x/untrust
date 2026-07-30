"""S3-01: S3 public access block configuration.

Verifies that the state bucket has ``PublicAccessBlockConfiguration``
enabled on all four settings.  A missing or incomplete public access
block combined with a permissive bucket policy could expose enclave
bootstrap state to the internet.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

REQUIRED_SETTINGS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


class S3PublicAccessCheck(Check):
    check_id = "S3-01"
    title = "S3 public access block"
    severity = Severity.HIGH

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

        try:
            response = s3.get_public_access_block(Bucket=target.bucket)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                return Finding(
                    check_id=self.check_id,
                    title=self.title,
                    status=Status.FAIL,
                    severity=self.severity,
                    summary=(
                        "No PublicAccessBlockConfiguration exists on the "
                        "state bucket. Enclave bootstrap state could be "
                        "exposed via public ACLs or policies."
                    ),
                    remediation=(
                        "Enable all four PublicAccessBlock settings: "
                        "BlockPublicAcls, IgnorePublicAcls, "
                        "BlockPublicPolicy, RestrictPublicBuckets."
                    ),
                    evidence={"public_access_block": "none"},
                )
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not retrieve public access block: {e}",
            )

        config = response.get(
            "PublicAccessBlockConfiguration", {}
        )
        disabled = [
            s for s in REQUIRED_SETTINGS if not config.get(s, False)
        ]

        if disabled:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(disabled)} PublicAccessBlock setting(s) disabled: "
                    f"{', '.join(disabled)}"
                ),
                remediation=(
                    "Enable all four PublicAccessBlock settings on the "
                    "state bucket to prevent any public access path."
                ),
                evidence={
                    "disabled_settings": disabled,
                    "config": {
                        k: config.get(k, False) for k in REQUIRED_SETTINGS
                    },
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="All four PublicAccessBlock settings are enabled.",
            evidence={
                "config": {
                    k: config.get(k, False) for k in REQUIRED_SETTINGS
                },
            },
        )
