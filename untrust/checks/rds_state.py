"""RDS-01: RDS/Aurora state database security.

When a TEE deployment keeps state in a relational database (RDS or
Aurora) rather than object storage, the database is the untrusted
external state the enclave connects to at boot. The relational analogues
of the S3 storage-plane controls:

* Storage encryption under a customer-managed KMS CMK (not the AWS-managed
  default), so snapshots inherit a controllable, auditable key.
* Not publicly accessible, and no security group exposing the DB port to
  0.0.0.0/0 — the network equivalent of an open bucket.
* IAM database authentication, so connections are gated by IAM/attested
  role rather than a static password the host can read.
* Deletion protection.
* No manual snapshots shared publicly (the RDS equivalent of a public
  object / public AMI).
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ._backend_util import classify_kms_key, cmk_issue
from .base import Check, Finding, Severity, Status, Target


def _open_security_groups(
    ec2: object, sg_ids: list[str]
) -> list[str]:
    """Return SG ids that allow ingress from 0.0.0.0/0 or ::/0."""
    if not sg_ids:
        return []
    open_sgs: list[str] = []
    try:
        resp = ec2.describe_security_groups(GroupIds=sg_ids)  # type: ignore[attr-defined]
    except ClientError:
        return []
    for sg in resp.get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            for rng in perm.get("IpRanges", []):
                if rng.get("CidrIp") == "0.0.0.0/0":
                    open_sgs.append(sg.get("GroupId", ""))
            for rng in perm.get("Ipv6Ranges", []):
                if rng.get("CidrIpv6") == "::/0":
                    open_sgs.append(sg.get("GroupId", ""))
    return sorted(set(open_sgs))


class RdsStateCheck(Check):
    check_id = "RDS-01"
    title = "RDS/Aurora state database security"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.db_instance:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No DB instance specified; skipping check.",
            )

        rds = boto3.client("rds", region_name=target.region)
        issues: list[str] = []
        evidence: dict[str, object] = {}

        try:
            resp = rds.describe_db_instances(
                DBInstanceIdentifier=target.db_instance
            )
            instances = resp.get("DBInstances", [])
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not describe DB instance: {e}",
            )

        if not instances:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"DB instance {target.db_instance} not found.",
            )

        db = instances[0]

        # 1. Storage encryption under a customer-managed CMK.
        encrypted = db.get("StorageEncrypted", False)
        kms_key = db.get("KmsKeyId", "")
        evidence["storage_encrypted"] = encrypted
        evidence["kms_key"] = kms_key or "none"
        if not encrypted:
            issues.append("storage is not encrypted at rest")
        else:
            key_class = classify_kms_key(kms_key, target.region)
            evidence["kms_key_class"] = key_class
            issue = cmk_issue(key_class, "storage")
            if issue:
                issues.append(issue)

        # 2. Public accessibility.
        public = db.get("PubliclyAccessible", False)
        evidence["publicly_accessible"] = public
        if public:
            issues.append("instance is publicly accessible")

        # 3. Security groups exposing the DB port.
        sg_ids = [
            g.get("VpcSecurityGroupId", "")
            for g in db.get("VpcSecurityGroups", [])
            if g.get("Status") == "active"
        ]
        ec2 = boto3.client("ec2", region_name=target.region)
        open_sgs = _open_security_groups(ec2, [s for s in sg_ids if s])
        evidence["open_security_groups"] = open_sgs
        if open_sgs:
            issues.append(
                f"{len(open_sgs)} security group(s) allow ingress from "
                f"0.0.0.0/0: {', '.join(open_sgs)}"
            )

        # 4. IAM database authentication.
        iam_auth = db.get("IAMDatabaseAuthenticationEnabled", False)
        evidence["iam_auth"] = iam_auth
        if not iam_auth:
            issues.append(
                "IAM database authentication is disabled (connections rely "
                "on a static password)"
            )

        # 5. Deletion protection.
        deletion_protected = db.get("DeletionProtection", False)
        evidence["deletion_protection"] = deletion_protected
        if not deletion_protected:
            issues.append("deletion protection is disabled")

        # 6. Publicly shared snapshots.
        public_snapshots = self._public_snapshots(rds, target.db_instance)
        if public_snapshots is not None:
            evidence["public_snapshots"] = public_snapshots
            if public_snapshots:
                issues.append(
                    f"{len(public_snapshots)} manual snapshot(s) are shared "
                    f"publicly"
                )

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "RDS/Aurora state database issues: "
                    + "; ".join(issues)
                    + "."
                ),
                remediation=(
                    "Encrypt storage with a customer-managed KMS CMK; set "
                    "PubliclyAccessible=false and remove 0.0.0.0/0 ingress; "
                    "enable IAM database authentication and deletion "
                    "protection; and ensure no snapshot is shared with 'all'."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "DB is CMK-encrypted, private, IAM-authenticated, "
                "deletion-protected, with no public snapshots."
            ),
            evidence=evidence,
        )

    @staticmethod
    def _public_snapshots(rds: object, db_id: str) -> list[str] | None:
        try:
            snaps = rds.describe_db_snapshots(  # type: ignore[attr-defined]
                DBInstanceIdentifier=db_id, SnapshotType="manual"
            ).get("DBSnapshots", [])
        except ClientError:
            return None
        public: list[str] = []
        for snap in snaps:
            snap_id = snap.get("DBSnapshotIdentifier", "")
            try:
                attrs = rds.describe_db_snapshot_attributes(  # type: ignore[attr-defined]
                    DBSnapshotIdentifier=snap_id
                )
            except ClientError:
                continue
            result = attrs.get("DBSnapshotAttributesResult", {})
            for attr in result.get("DBSnapshotAttributes", []):
                if attr.get("AttributeName") == "restore" and "all" in attr.get(
                    "AttributeValues", []
                ):
                    public.append(snap_id)
        return public
