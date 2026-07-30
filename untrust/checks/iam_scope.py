"""IAM-01: Instance role least privilege.

Verifies that the EC2 instance role does not grant wildcard ('*') resource
access on security-critical actions (S3, KMS). Overly permissive roles allow
the enclave (or an attacker who compromises it) to access any S3 bucket or
KMS key in the account, not just the intended ones.
"""
from __future__ import annotations

import json

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

CRITICAL_ACTIONS_PREFIXES = [
    "s3:",
    "kms:",
]


class IamScopeCheck(Check):
    check_id = "IAM-01"
    title = "Instance role least privilege"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.instance_id:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No instance ID specified; skipping check.",
            )

        ec2 = boto3.client("ec2", region_name=target.region)
        iam = boto3.client("iam")

        try:
            response = ec2.describe_instances(InstanceIds=[target.instance_id])
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not describe instance: {e}",
            )

        reservations = response.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Instance {target.instance_id} not found.",
            )

        instance = reservations[0]["Instances"][0]
        profile_arn = instance.get("IamInstanceProfile", {}).get("Arn", "")

        if not profile_arn:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary="No IAM instance profile attached.",
            )

        profile_name = profile_arn.split("/")[-1]

        try:
            profile_response = iam.get_instance_profile(
                InstanceProfileName=profile_name
            )
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not get instance profile: {e}",
            )

        roles = profile_response.get("InstanceProfile", {}).get("Roles", [])
        if not roles:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary="Instance profile has no roles.",
            )

        wildcard_findings: list[str] = []

        for role in roles:
            role_name = role["RoleName"]

            try:
                inline_policies = iam.list_role_policies(RoleName=role_name)
                for policy_name in inline_policies.get("PolicyNames", []):
                    policy_doc = iam.get_role_policy(
                        RoleName=role_name, PolicyName=policy_name
                    )
                    doc = policy_doc.get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    self._check_statements(
                        doc.get("Statement", []),
                        f"inline:{policy_name}",
                        wildcard_findings,
                    )
            except ClientError:
                pass

            try:
                attached = iam.list_attached_role_policies(RoleName=role_name)
                for policy in attached.get("AttachedPolicies", []):
                    try:
                        policy_detail = iam.get_policy(PolicyArn=policy["PolicyArn"])
                        version_id = policy_detail["Policy"]["DefaultVersionId"]
                        version = iam.get_policy_version(
                            PolicyArn=policy["PolicyArn"], VersionId=version_id
                        )
                        doc = version["PolicyVersion"]["Document"]
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        self._check_statements(
                            doc.get("Statement", []),
                            f"managed:{policy['PolicyName']}",
                            wildcard_findings,
                        )
                    except ClientError:
                        pass
            except ClientError:
                pass

        if wildcard_findings:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"Instance role has {len(wildcard_findings)} overly permissive "
                    f"statement(s) with wildcard Resource on S3/KMS actions."
                ),
                remediation=(
                    "Scope the instance role to the specific S3 bucket and KMS key "
                    "ARN used by the enclave. Replace Resource: '*' with the exact "
                    "ARNs. Example: arn:aws:s3:::my-state-bucket/* for S3 and "
                    "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID for KMS."
                ),
                evidence={"wildcard_statements": wildcard_findings},
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Instance role policies scope S3/KMS actions to specific resources.",
        )

    @staticmethod
    def _check_statements(
        statements: list[dict],
        policy_label: str,
        findings: list[str],
    ) -> None:
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            has_critical = any(
                any(a.lower().startswith(p) for p in CRITICAL_ACTIONS_PREFIXES)
                or a == "*"
                for a in actions
            )
            if not has_critical:
                continue

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            if "*" in resources:
                findings.append(
                    f"{policy_label}: {', '.join(actions)} on Resource: *"
                )
