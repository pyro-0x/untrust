"""SSH-01: Remote access hardening.

Verifies that SSH daemon is disabled and EC2 Instance Connect is not
installed on the enclave host. SSM Session Manager provides authenticated
shell access without opening network ports. Leaving SSH or EC2 Instance
Connect enabled allows lateral movement from any principal with
ec2-instance-connect:SendSSHPublicKey permission.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class SshHardeningCheck(Check):
    check_id = "SSH-01"
    title = "Remote access hardening"
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

        ssm = boto3.client("ssm", region_name=target.region)

        command = (
            "echo SSH_STATUS=$(systemctl is-active sshd 2>/dev/null || echo inactive); "
            "echo EC2IC_INSTALLED=$(rpm -q ec2-instance-connect 2>/dev/null "
            "|| dpkg -s ec2-instance-connect 2>/dev/null "
            "|| echo not_installed); "
            "echo SSH_PORT=$(ss -tlnp 2>/dev/null | grep ':22 ' | head -1 || echo none)"
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

        ssh_active = False
        ec2ic_installed = False
        evidence: dict = {}

        for line in output.splitlines():
            if line.startswith("SSH_STATUS="):
                status_val = line.split("=", 1)[1].strip()
                evidence["ssh_status"] = status_val
                ssh_active = status_val == "active"
            elif line.startswith("EC2IC_INSTALLED="):
                val = line.split("=", 1)[1].strip()
                ec2ic_installed = "not_installed" not in val
                evidence["ec2ic_installed"] = ec2ic_installed
            elif line.startswith("SSH_PORT="):
                evidence["ssh_port"] = line.split("=", 1)[1].strip()

        issues: list[str] = []
        if ssh_active:
            issues.append("SSH daemon (sshd) is running")
        if ec2ic_installed:
            issues.append("EC2 Instance Connect is installed")

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=" | ".join(issues),
                remediation=(
                    "Disable SSH: systemctl disable --now sshd\n"
                    "Remove EC2 Instance Connect: "
                    "dnf remove -y ec2-instance-connect || "
                    "apt remove -y ec2-instance-connect\n"
                    "Use SSM Session Manager for all shell access."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="SSH is disabled and EC2 Instance Connect is not installed.",
            evidence=evidence,
        )
