"""ROLLBACK-01: Anti-rollback protection on bootstrap state.

A Nitro Enclave has no persistent storage and re-downloads its state
from S3 on every boot (see RESTART-01). An attacker with s3:PutObject
can therefore roll the state back to an older-but-valid version — an
outdated db.key, a stale config, a previous secrets snapshot — and the
enclave will load it on the next restart. Standard encryption does not
prevent this; it is a freshness/replay problem.

S3 Object Lock (WORM) provides at-rest anti-rollback: once written,
an object version cannot be overwritten or deleted for the retention
period, so an attacker cannot silently substitute stale state. This
check verifies Object Lock is enabled on the state bucket.

This maps to the "rollback / replay" grey area that the Confidential
Computing Consortium and OWASP both assign to the deployer, not the
hardware.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class StateRollbackCheck(Check):
    check_id = "ROLLBACK-01"
    title = "Anti-rollback protection on bootstrap state"
    severity = Severity.MEDIUM

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
            response = s3.get_object_lock_configuration(Bucket=target.bucket)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "ObjectLockConfigurationNotFoundError",
                "NoSuchObjectLockConfiguration",
            ):
                return Finding(
                    check_id=self.check_id,
                    title=self.title,
                    status=Status.FAIL,
                    severity=self.severity,
                    summary=(
                        "No S3 Object Lock on the state bucket. An attacker "
                        "with s3:PutObject can roll state back to an older "
                        "version, which the enclave re-downloads and loads on "
                        "its next restart."
                    ),
                    remediation=(
                        "Enable S3 Object Lock (WORM) in COMPLIANCE or "
                        "GOVERNANCE mode with a retention period on the state "
                        "bucket. Object Lock requires versioning. This gives "
                        "at-rest anti-rollback for bootstrap state. For strong "
                        "freshness, also pin the expected version/digest from "
                        "an external monotonic source the enclave verifies at "
                        "boot."
                    ),
                    evidence={"object_lock": "none"},
                )
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not retrieve Object Lock configuration: {e}",
            )

        config = response.get("ObjectLockConfiguration", {})
        enabled = config.get("ObjectLockEnabled") == "Enabled"
        rule = config.get("Rule", {}).get("DefaultRetention", {})

        if not enabled:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "S3 Object Lock is present but not enabled on the state "
                    "bucket. Bootstrap state can be silently rolled back."
                ),
                remediation=(
                    "Enable Object Lock with a default retention rule."
                ),
                evidence={"object_lock": config},
            )

        if not rule:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "S3 Object Lock is enabled but no default retention rule "
                    "is set, so new state objects are not protected by "
                    "default."
                ),
                remediation=(
                    "Add a DefaultRetention rule (mode + period) so every "
                    "state object version is retained and cannot be rolled "
                    "back."
                ),
                evidence={"object_lock": config},
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                f"S3 Object Lock enabled with default retention "
                f"({rule.get('Mode')} {rule.get('Days', rule.get('Years'))}). "
                f"Bootstrap state is protected from rollback at rest."
            ),
            evidence={"object_lock": config},
        )
