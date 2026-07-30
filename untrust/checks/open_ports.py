"""PORT-01: Unexpected listening ports.

Enumerates TCP listeners on the enclave host via SSM and flags any
port that is not in the expected set.  An exposed SSH listener on
22/tcp, for example, is a common entry point for host compromise via
EC2 Instance Connect.

Expected ports on a hardened Nitro host: none (SSM uses outbound
HTTPS, not inbound listeners).  Any TCP listener is a lateral
movement surface.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

EXPECTED_PORTS: set[int] = set()


class OpenPortsCheck(Check):
    check_id = "PORT-01"
    title = "Unexpected listening TCP ports"
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
            "ss -tlnp 2>/dev/null | grep LISTEN | "
            "awk '{print $4}' | sed 's/.*://' | sort -un"
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
        if not output:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary="No TCP listeners found on the host.",
                evidence={"listening_ports": []},
            )

        ports: list[int] = []
        for line in output.splitlines():
            line = line.strip()
            if line.isdigit():
                ports.append(int(line))

        unexpected = [p for p in ports if p not in EXPECTED_PORTS]

        if unexpected:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(unexpected)} unexpected TCP port(s) listening: "
                    f"{', '.join(str(p) for p in unexpected)}"
                ),
                remediation=(
                    "A hardened enclave host should have no inbound TCP "
                    "listeners. Disable sshd and any other unnecessary "
                    "services. Use SSM Session Manager for shell access."
                ),
                evidence={
                    "unexpected_ports": unexpected,
                    "all_ports": ports,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="All listening ports are in the expected set.",
            evidence={"listening_ports": ports},
        )
