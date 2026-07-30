"""EXEC-01: State prefix files lack execute permissions.

In practice, binary replacement via S3 is blocked when the download
routine creates files with 0644 permissions (no execute bit) — as
boto3's ``download_file`` does.  This check verifies that no files
downloaded into the enclave's state directory on the host have the
execute bit set — a control that prevents trivial binary replacement
attacks.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class ExecPermissionsCheck(Check):
    check_id = "EXEC-01"
    title = "State files lack execute permissions"
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
            "find /opt -type f \\( -perm /111 \\) "
            "\\( -name '*.py' -o -name '*.sh' -o -name '*.bin' "
            "-o -name '*.so' -o -name 'app_*' \\) "
            "2>/dev/null | head -20 || echo NONE"
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

        if output == "NONE" or not output:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary=(
                    "No executable state files found under /opt. "
                    "Binary replacement via S3 would be blocked."
                ),
                evidence={"executable_files": []},
            )

        exec_files = [
            f.strip() for f in output.splitlines() if f.strip()
        ]

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.FAIL,
            severity=self.severity,
            summary=(
                f"{len(exec_files)} file(s) in the state directory have "
                f"execute permissions. An attacker who can replace these "
                f"via S3 could achieve code execution on the host."
            ),
            remediation=(
                "Remove execute permissions from all files downloaded "
                "from S3: chmod -x /opt/*/app_* /opt/*/*.py. "
                "Ensure the download routine does not set the execute "
                "bit (boto3's download_file uses 0644 by default)."
            ),
            evidence={"executable_files": exec_files},
        )
