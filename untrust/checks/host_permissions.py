"""HOST-01: Sensitive file permissions on the enclave host.

Verifies that enclave-related files (EIF images, scripts, keys, databases,
environment files) are not world-readable. World-readable secrets enable
unprivileged credential theft; world-readable EIFs enable offline reverse
engineering of the enclave binary.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

SENSITIVE_PATTERNS = [
    "*.eif",
    "*.key",
    "*.pem",
    "*.db",
    "*.sqlite",
    "environment.conf",
    "*.env",
    "*.token",
    "*.secret",
    "*.conf",
    "service.config",
]

WORLD_READABLE_MODES = ("644", "645", "646", "647", "654", "655", "656", "657",
                        "664", "665", "666", "667", "674", "675", "676", "677",
                        "744", "745", "746", "747", "754", "755", "756", "757",
                        "764", "765", "766", "767", "774", "775", "776", "777")


class HostPermissionsCheck(Check):
    check_id = "HOST-01"
    title = "Sensitive file permissions on enclave host"
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

        find_args = " -o ".join(f"-name '{p}'" for p in SENSITIVE_PATTERNS)
        command = (
            f"find /opt \\( {find_args} \\) "
            "-exec stat -c '%a %n' {} \\; 2>/dev/null || echo 'NOT_FOUND'"
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
                summary="No sensitive files found in /opt, or all properly restricted.",
            )

        world_readable_files: list[str] = []
        for line in output.splitlines():
            parts = line.strip().split(" ", 1)
            if len(parts) == 2:
                mode, path = parts
                if mode in WORLD_READABLE_MODES:
                    world_readable_files.append(f"{path} ({mode})")

        if world_readable_files:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(world_readable_files)} sensitive file(s) are world-readable. "
                    "Unprivileged host processes can read secrets, keys, and enclave images."
                ),
                remediation=(
                    "Set chmod 600 on key/secret/env files and chmod 700 on scripts. "
                    "Set chmod 600 on the EIF to prevent offline reverse engineering. "
                    "Run: find /opt -name '*.eif' -o -name '*.key' -o -name 'environment.conf' "
                    "| xargs chmod 600"
                ),
                evidence={"world_readable_files": world_readable_files},
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="All sensitive files in /opt have restrictive permissions.",
        )
