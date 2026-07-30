"""S3-02: State bucket encryption and transport security.

The state bucket holds the enclave's bootstrap material. Two baseline
controls must be in place:

1. Default server-side encryption — ideally SSE-KMS with a customer
   managed key, so bucket contents are encrypted at rest under a key
   whose usage can be scoped and audited.

2. TLS-only access — a bucket policy that denies requests when
   aws:SecureTransport is false, preventing plaintext-HTTP fetches of
   state that a network attacker could read or tamper with in transit.
"""
from __future__ import annotations

import json

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


def _has_tls_only_deny(policy: dict) -> bool:
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Deny":
            continue
        condition = stmt.get("Condition", {})
        for operator in ("Bool", "BoolIfExists"):
            block = condition.get(operator, {})
            val = block.get("aws:SecureTransport")
            if val in ("false", False) or val == ["false"]:
                return True
    return False


class S3EncryptionCheck(Check):
    check_id = "S3-02"
    title = "State bucket encryption and TLS-only access"
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
        issues: list[str] = []
        evidence: dict[str, object] = {}

        # 1. Default encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=target.bucket)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            algo = ""
            for rule in rules:
                default = rule.get("ApplyServerSideEncryptionByDefault", {})
                algo = default.get("SSEAlgorithm", "")
                if algo:
                    break
            evidence["sse_algorithm"] = algo or "none"
            if not algo:
                issues.append("no default server-side encryption")
            elif algo != "aws:kms":
                issues.append(
                    f"default encryption is {algo} (SSE-KMS recommended for "
                    f"a secrets bucket)"
                )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                issues.append("no default server-side encryption")
                evidence["sse_algorithm"] = "none"
            else:
                return Finding(
                    check_id=self.check_id,
                    title=self.title,
                    status=Status.ERROR,
                    severity=self.severity,
                    summary=f"Could not read bucket encryption: {e}",
                )

        # 2. TLS-only bucket policy
        try:
            resp = s3.get_bucket_policy(Bucket=target.bucket)
            policy = json.loads(resp.get("Policy", "{}"))
            tls_only = _has_tls_only_deny(policy)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchBucketPolicy":
                tls_only = False
            else:
                return Finding(
                    check_id=self.check_id,
                    title=self.title,
                    status=Status.ERROR,
                    severity=self.severity,
                    summary=f"Could not read bucket policy: {e}",
                )
        except json.JSONDecodeError:
            tls_only = False

        evidence["tls_only_deny"] = tls_only
        if not tls_only:
            issues.append(
                "no bucket policy denying non-TLS (aws:SecureTransport) access"
            )

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="State bucket baseline issues: " + "; ".join(issues) + ".",
                remediation=(
                    "Enable default SSE-KMS encryption on the bucket and add a "
                    "bucket policy Deny with Condition "
                    "Bool aws:SecureTransport=false to force TLS."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Bucket has SSE-KMS default encryption and enforces TLS-only access.",
            evidence=evidence,
        )
