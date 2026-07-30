"""BOOTSTRAP-02: S3 bucket write scope.

Verifies that the enclave's state bucket has a bucket policy restricting
s3:PutObject to specific principals (e.g., only the enclave's instance
role). Without this, any principal with PutObject permission on the bucket
can plant files that the enclave downloads at boot — enabling supply chain
attacks like the path traversal RCE chain.
"""
from __future__ import annotations

import json

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class BucketPolicyCheck(Check):
    check_id = "BOOTSTRAP-02"
    title = "S3 bucket write scope"
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
            response = s3.get_bucket_policy(Bucket=target.bucket)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchBucketPolicy":
                return Finding(
                    check_id=self.check_id,
                    title=self.title,
                    status=Status.FAIL,
                    severity=self.severity,
                    summary=(
                        "No bucket policy exists. Any IAM principal with s3:PutObject "
                        "permission can upload files to the state bucket."
                    ),
                    remediation=(
                        "Add a bucket policy that restricts s3:PutObject to only the "
                        "enclave's instance role ARN. Deny all other principals from "
                        "writing to the state prefix."
                    ),
                    evidence={"bucket_policy": "none"},
                )
            if code in ("AccessDenied", "AllAccessDisabled"):
                return Finding(
                    check_id=self.check_id,
                    title=self.title,
                    status=Status.ERROR,
                    severity=self.severity,
                    summary=f"Access denied reading bucket policy: {e}",
                )
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not retrieve bucket policy: {e}",
            )

        try:
            policy = json.loads(response.get("Policy", "{}"))
        except json.JSONDecodeError:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="Bucket policy is not valid JSON.",
            )

        has_put_deny = False
        has_put_condition = False

        for stmt in policy.get("Statement", []):
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            has_write_action = any(
                a in ("s3:PutObject", "s3:*", "s3:Put*") for a in actions
            )
            if not has_write_action:
                continue

            if stmt.get("Effect") == "Deny":
                has_put_deny = True
            elif stmt.get("Effect") == "Allow":
                condition = stmt.get("Condition", {})
                principal = stmt.get("Principal", {})
                if condition or (isinstance(principal, dict) and principal.get("AWS")):
                    has_put_condition = True

        if has_put_deny or has_put_condition:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary="Bucket policy restricts write access with conditions or deny statements.",
                evidence={"statement_count": len(policy.get("Statement", []))},
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.FAIL,
            severity=self.severity,
            summary=(
                "Bucket policy exists but does not restrict s3:PutObject to "
                "specific principals or conditions."
            ),
            remediation=(
                "Add a Deny statement for s3:PutObject with a Condition that "
                "excludes the enclave's instance role. Or use an Allow with a "
                "specific Principal ARN instead of wildcard."
            ),
            evidence={"statement_count": len(policy.get("Statement", []))},
        )
