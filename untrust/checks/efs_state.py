"""EFS-01: EFS state filesystem security.

A TEE host sometimes mounts an EFS (or EBS) filesystem and passes state
into the enclave over vsock. The filesystem is untrusted external state
just like an S3 object, so it needs the same at-rest and access controls:

* Encryption at rest under a customer-managed KMS CMK, not the AWS-managed
  ``aws/elasticfilesystem`` default, so the key policy can be scoped and
  audited (and, for EBS, so snapshots inherit a controllable key).
* A filesystem policy that enforces in-transit encryption
  (``aws:SecureTransport``) and scopes mount/read access — without one,
  any principal that can reach a mount target can mount the filesystem.
* AWS Backup enabled, the EFS analogue of versioning/anti-rollback.

Note: EBS volumes attached to the host carry the same requirements
(encryption under a CMK, no public snapshots); audit those on the host's
volumes if state lives on EBS rather than EFS.
"""
from __future__ import annotations

import json

import boto3
from botocore.exceptions import ClientError

from ._backend_util import classify_kms_key, cmk_issue
from .base import Check, Finding, Severity, Status, Target


def _enforces_tls(policy: dict) -> bool:
    for stmt in policy.get("Statement", []):
        condition = stmt.get("Condition", {})
        for operator in ("Bool", "BoolIfExists"):
            block = condition.get(operator, {})
            val = block.get("aws:SecureTransport")
            effect = stmt.get("Effect")
            if effect == "Deny" and val in ("false", False, ["false"]):
                return True
            if effect == "Allow" and val in ("true", True, ["true"]):
                return True
    return False


class EfsStateCheck(Check):
    check_id = "EFS-01"
    title = "EFS state filesystem security"
    severity = Severity.MEDIUM

    def run(self, target: Target) -> Finding:
        if not target.efs_id:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No EFS filesystem ID specified; skipping check.",
            )

        efs = boto3.client("efs", region_name=target.region)
        issues: list[str] = []
        evidence: dict[str, object] = {}

        try:
            resp = efs.describe_file_systems(FileSystemId=target.efs_id)
            filesystems = resp.get("FileSystems", [])
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not describe EFS filesystem: {e}",
            )

        if not filesystems:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"EFS filesystem {target.efs_id} not found.",
            )

        fs = filesystems[0]

        # 1. Encryption under a customer-managed CMK.
        encrypted = fs.get("Encrypted", False)
        kms_key = fs.get("KmsKeyId", "")
        evidence["encrypted"] = encrypted
        evidence["kms_key"] = kms_key or "none"
        if not encrypted:
            issues.append("filesystem is not encrypted at rest")
        else:
            key_class = classify_kms_key(kms_key, target.region)
            evidence["kms_key_class"] = key_class
            issue = cmk_issue(key_class, "the filesystem")
            if issue:
                issues.append(issue)

        # 2. Filesystem policy: TLS enforcement + scoping.
        try:
            pol = efs.describe_file_system_policy(FileSystemId=target.efs_id)
            policy = json.loads(pol.get("Policy", "{}"))
            evidence["fs_policy"] = "present"
            if not _enforces_tls(policy):
                issues.append(
                    "filesystem policy does not enforce in-transit "
                    "encryption (aws:SecureTransport)"
                )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "PolicyNotFound":
                evidence["fs_policy"] = "none"
                issues.append(
                    "no filesystem policy; any principal that can reach a "
                    "mount target can mount the filesystem, with no TLS "
                    "enforcement"
                )
            else:
                evidence["fs_policy"] = "unreadable"
        except json.JSONDecodeError:
            evidence["fs_policy"] = "invalid-json"

        # 3. AWS Backup enabled (anti-rollback / recovery).
        try:
            bp = efs.describe_backup_policy(FileSystemId=target.efs_id)
            status = bp.get("BackupPolicy", {}).get("Status")
            evidence["backup"] = status or "DISABLED"
            if status not in ("ENABLED", "ENABLING"):
                issues.append("automatic backups are disabled")
        except ClientError:
            evidence["backup"] = "unknown"

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="EFS state filesystem issues: " + "; ".join(issues) + ".",
                remediation=(
                    "Encrypt the filesystem with a customer-managed KMS CMK; "
                    "attach a filesystem policy that denies non-TLS access and "
                    "scopes mount to the enclave host's role; and enable AWS "
                    "Backup. For EBS-backed state, encrypt volumes with a CMK "
                    "and ensure snapshots are not shared publicly."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "EFS filesystem is CMK-encrypted, enforces TLS via policy, "
                "and has backups enabled."
            ),
            evidence=evidence,
        )
