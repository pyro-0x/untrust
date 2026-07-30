"""NAT-01: IMDS blocked from enclave NAT egress.

Verifies that the host's network bridge has iptables rules blocking
the enclave from reaching the EC2 Instance Metadata Service (169.254.169.254).
Without this filter, the enclave can steal the host's IAM credentials.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

IMDS_IP = "169.254.169.254"


class NatEgressCheck(Check):
    check_id = "NAT-01"
    title = "IMDS blocked from enclave NAT egress"
    severity = Severity.MEDIUM

    def run(self, target: Target) -> Finding:
        if not target.instance_id:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No instance ID specified; skipping check.",
            )

        ssm = boto3.client("ssm", region_name=target.region)

        command = (
            "iptables -L FORWARD -v -n 2>/dev/null | "
            f"grep -c '{IMDS_IP}' || echo 0"
        )

        try:
            response = ssm.send_command(
                InstanceIds=[target.instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [command]},
            )
            command_id = response["Command"]["CommandId"]
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not send SSM command: {e}",
            )

        result = None
        for _ in range(10):
            time.sleep(3)
            try:
                result = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=target.instance_id,
                )
                if result["Status"] in ("Success", "Failed"):
                    break
            except ClientError:
                continue

        if result is None or result.get("Status") not in ("Success", "Failed"):
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="SSM command did not complete within timeout.",
            )

        output = result.get("StandardOutputContent", "").strip()

        try:
            rule_count = int(output)
        except (ValueError, TypeError):
            rule_count = 0

        if rule_count == 0:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"No iptables FORWARD rule found blocking {IMDS_IP}. "
                    "The enclave can reach the host's IAM credentials via IMDS."
                ),
                remediation=(
                    f"Add: iptables -I FORWARD -d {IMDS_IP} -i tun0 -j DROP\n"
                    "This prevents the enclave from accessing the instance metadata "
                    "service through the host's NAT bridge."
                ),
                evidence={"imds_filter_rules": rule_count},
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=f"Found {rule_count} iptables rule(s) blocking IMDS from enclave traffic.",
            evidence={"imds_filter_rules": rule_count},
        )
