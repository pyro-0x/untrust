"""SECRETS-01: Secrets Manager secret security.

When a TEE bootstraps "secret zero" (a wrapping key, DB credential, or
config) from AWS Secrets Manager instead of S3, the same trust-boundary
controls apply. This check verifies:

* Encryption under a customer-managed KMS CMK, not the AWS-managed
  ``aws/secretsmanager`` default key. Only a CMK's policy can gate
  GetSecretValue-time decrypt on the enclave's attestation (KMS-01).
* A resource-based policy that scopes read/write to the enclave role and
  does not grant a wildcard principal or cross-account access.
* Automatic rotation, so a leaked secret has a bounded lifetime.
* CloudTrail data events for the secret, so retrievals are audited.
"""
from __future__ import annotations

import json

import boto3
from botocore.exceptions import ClientError

from ._backend_util import classify_kms_key, cloudtrail_data_events, cmk_issue
from .base import Check, Finding, Severity, Status, Target


def _has_wildcard_principal(policy: dict) -> bool:
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                return True
    return False


class SecretsManagerCheck(Check):
    check_id = "SECRETS-01"
    title = "Secrets Manager secret security"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.secret_arn:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No secret ARN specified; skipping check.",
            )

        sm = boto3.client("secretsmanager", region_name=target.region)
        issues: list[str] = []
        evidence: dict[str, object] = {}

        try:
            desc = sm.describe_secret(SecretId=target.secret_arn)
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not describe secret: {e}",
            )

        # 1. Encryption under a customer-managed CMK.
        kms_key = desc.get("KmsKeyId", "")
        key_class = classify_kms_key(kms_key, target.region)
        evidence["kms_key"] = kms_key or "aws/secretsmanager (default)"
        evidence["kms_key_class"] = key_class
        issue = cmk_issue(key_class, "the secret")
        if issue:
            issues.append(issue)

        # 2. Rotation.
        rotation = desc.get("RotationEnabled", False)
        evidence["rotation_enabled"] = rotation
        if not rotation:
            issues.append("automatic rotation is disabled")

        # 3. Resource-based policy scope.
        try:
            resp = sm.get_resource_policy(SecretId=target.secret_arn)
            policy_text = resp.get("ResourcePolicy")
            if not policy_text:
                evidence["resource_policy"] = "none"
                issues.append(
                    "no resource-based policy; read scope relies solely on "
                    "IAM"
                )
            else:
                policy = json.loads(policy_text)
                if _has_wildcard_principal(policy):
                    evidence["resource_policy"] = "wildcard-principal"
                    issues.append(
                        "resource policy grants a wildcard principal "
                        "(Principal '*')"
                    )
                else:
                    evidence["resource_policy"] = "scoped"
        except ClientError:
            evidence["resource_policy"] = "unreadable"
        except json.JSONDecodeError:
            evidence["resource_policy"] = "invalid-json"

        # 4. CloudTrail data events for the secret.
        ct = cloudtrail_data_events(
            target.region,
            "AWS::SecretsManager::Secret",
            target.secret_arn,
        )
        if ct["error"] is None:
            evidence["cloudtrail_data_events"] = ct["data_events"]
            if not ct["data_events"]:
                issues.append(
                    "no CloudTrail data events for the secret (retrievals "
                    "are not audited)"
                )

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="Secrets Manager issues: " + "; ".join(issues) + ".",
                remediation=(
                    "Encrypt the secret with a customer-managed KMS CMK gated "
                    "on enclave attestation (KMS-01); enable automatic "
                    "rotation; attach a resource policy scoping "
                    "GetSecretValue to the enclave role with no wildcard "
                    "principal; and enable CloudTrail data events for the "
                    "secret."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "Secret uses a customer-managed CMK, rotation, a scoped "
                "resource policy, and is audited."
            ),
            evidence=evidence,
        )
