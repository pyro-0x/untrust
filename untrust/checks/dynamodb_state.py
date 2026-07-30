"""DDB-01: DynamoDB state table security.

Turnkey- and nitriding-style TEE deployments keep encrypted key shares
and ciphertext in DynamoDB instead of S3. The enclave reads that state at
boot and trusts it — but attestation covers none of it, exactly like the
S3 bootstrap path. This check applies the DynamoDB equivalents of the S3
storage-plane controls:

* Encryption at rest under a customer-managed KMS CMK (not the AWS-owned
  default), so the KMS key policy can gate decrypt on enclave attestation
  (see KMS-01). DynamoDB's default encryption uses an AWS-owned key whose
  policy you cannot attach a RecipientAttestation condition to.
* Point-in-time recovery — the DynamoDB analogue of S3 versioning /
  Object Lock, giving anti-rollback and recovery from tampered writes.
* Deletion protection — prevents an attacker with control-plane access
  from dropping the table.
* A resource-based policy scoping who can write items — without one, any
  IAM principal with dynamodb:PutItem can plant state the enclave loads.
* CloudTrail data events for the table, so item reads/writes are audited.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ._backend_util import classify_kms_key, cloudtrail_data_events, cmk_issue
from .base import Check, Finding, Severity, Status, Target


class DynamoDbStateCheck(Check):
    check_id = "DDB-01"
    title = "DynamoDB state table security"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.dynamodb_table:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No DynamoDB table specified; skipping check.",
            )

        ddb = boto3.client("dynamodb", region_name=target.region)
        issues: list[str] = []
        evidence: dict[str, object] = {}

        try:
            table = ddb.describe_table(
                TableName=target.dynamodb_table
            ).get("Table", {})
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not describe DynamoDB table: {e}",
            )

        table_arn = table.get("TableArn")

        # 1. Encryption under a customer-managed CMK.
        sse = table.get("SSEDescription", {})
        kms_arn = sse.get("KMSMasterKeyArn", "")
        key_class = classify_kms_key(kms_arn, target.region)
        evidence["sse_type"] = sse.get("SSEType", "AWS_OWNED")
        evidence["kms_key"] = kms_arn or "aws-owned-default"
        evidence["kms_key_class"] = key_class
        issue = cmk_issue(key_class, "the table")
        if issue:
            issues.append(issue)

        # 2. Point-in-time recovery (anti-rollback / recovery).
        try:
            cbr = ddb.describe_continuous_backups(
                TableName=target.dynamodb_table
            )
            pitr = (
                cbr.get("ContinuousBackupsDescription", {})
                .get("PointInTimeRecoveryDescription", {})
                .get("PointInTimeRecoveryStatus")
            )
            evidence["pitr"] = pitr or "DISABLED"
            if pitr != "ENABLED":
                issues.append(
                    "point-in-time recovery is disabled (no anti-rollback / "
                    "recovery from tampered writes)"
                )
        except ClientError:
            evidence["pitr"] = "unknown"

        # 3. Deletion protection.
        deletion_protected = table.get("DeletionProtectionEnabled", False)
        evidence["deletion_protection"] = deletion_protected
        if not deletion_protected:
            issues.append("deletion protection is disabled")

        # 4. Resource-based policy scoping writes.
        if table_arn:
            try:
                ddb.get_resource_policy(ResourceArn=table_arn)
                evidence["resource_policy"] = "present"
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("PolicyNotFoundException", "ResourceNotFoundException"):
                    evidence["resource_policy"] = "none"
                    issues.append(
                        "no resource-based policy; write scope relies solely "
                        "on IAM — any principal with dynamodb:PutItem can "
                        "plant state"
                    )
                else:
                    evidence["resource_policy"] = "unreadable"

        # 5. CloudTrail data events for the table.
        ct = cloudtrail_data_events(
            target.region, "AWS::DynamoDB::Table", target.dynamodb_table
        )
        if ct["error"] is None:
            evidence["cloudtrail_data_events"] = ct["data_events"]
            if not ct["data_events"]:
                issues.append(
                    "no CloudTrail data events for the table (item "
                    "reads/writes are not audited)"
                )

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "DynamoDB state table issues: " + "; ".join(issues) + "."
                ),
                remediation=(
                    "Encrypt the table with a customer-managed KMS CMK and "
                    "gate that key on enclave attestation (KMS-01); enable "
                    "point-in-time recovery and deletion protection; attach a "
                    "resource-based policy restricting PutItem to the enclave "
                    "role; and add a CloudTrail data-event selector for the "
                    "table."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "DynamoDB state table uses a customer-managed CMK, PITR, "
                "deletion protection, a resource policy, and is audited."
            ),
            evidence=evidence,
        )
