"""HOST-02: Enclave service privilege level.

Verifies that enclave-related systemd services do not run as root.
If host-side helper processes (socat bridges, logging, env export) are
compromised, running as root gives the attacker immediate full privileges
with no escalation needed.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

ENCLAVE_SERVICE_PATTERNS = [
    "enclave",
    "nitro",
    "tee",
    "socat",
]


class HostServicesCheck(Check):
    check_id = "HOST-02"
    title = "Enclave services running as root"
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

        grep_pattern = "|".join(ENCLAVE_SERVICE_PATTERNS)
        command = (
            f"systemctl list-units --type=service --all --no-pager --plain "
            f"| grep -iE '({grep_pattern})' "
            f"| awk '{{print $1}}' "
            f"| while read svc; do "
            f"user=$(systemctl show \"$svc\" -p User --value 2>/dev/null); "
            f"echo \"$svc:${{user:-root}}\"; "
            f"done || echo 'NOT_FOUND'"
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

        if output == "NOT_FOUND" or not output:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary="No enclave-related services detected.",
            )

        root_services: list[str] = []
        non_root_services: list[str] = []
        for line in output.splitlines():
            if ":" in line:
                svc, user = line.rsplit(":", 1)
                if user.strip() in ("root", ""):
                    root_services.append(svc.strip())
                else:
                    non_root_services.append(f"{svc.strip()} ({user.strip()})")

        if root_services:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(root_services)} enclave service(s) run as root: "
                    f"{', '.join(root_services)}"
                ),
                remediation=(
                    "Create a dedicated unprivileged service account (e.g., 'enclave') "
                    "and add it to the 'ne' group for enclave management. Run socat "
                    "bridges, logging, and env export services as this account. Only "
                    "nitro-cli operations require elevated privileges."
                ),
                evidence={
                    "root_services": root_services,
                    "non_root_services": non_root_services,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="All enclave services run as non-root users.",
            evidence={"non_root_services": non_root_services},
        )
