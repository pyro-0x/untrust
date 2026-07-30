"""LOG-01: Enclave log exposure.

Enclave services often log to systemd journal on the host.  If the
journal files are readable by non-root users, any unprivileged
process on the host can read enclave operational logs — which may
contain key material, tokens, error messages with secret context,
or enclave internal state.

This check inspects journal file permissions and whether the
``adm`` or ``systemd-journal`` groups grant broad read access.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class LogExposureCheck(Check):
    check_id = "LOG-01"
    title = "Enclave log exposure"
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
            "echo STORAGE=$(grep -s '^Storage=' /etc/systemd/journald.conf "
            "2>/dev/null | head -1 || echo 'Storage=auto') && "
            "echo JOURNAL_PERMS=$("
            "stat -c '%a' /var/log/journal 2>/dev/null || "
            "stat -c '%a' /run/log/journal 2>/dev/null || "
            "echo 'none') && "
            "echo JOURNAL_GROUP=$("
            "stat -c '%G' /var/log/journal 2>/dev/null || "
            "stat -c '%G' /run/log/journal 2>/dev/null || "
            "echo 'none') && "
            "echo JOURNAL_USERS=$(getent group systemd-journal 2>/dev/null "
            "| cut -d: -f4 || echo 'none')"
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

        perms = ""
        group = ""
        journal_users = ""
        for line in output.splitlines():
            if line.startswith("JOURNAL_PERMS="):
                perms = line.split("=", 1)[1].strip()
            elif line.startswith("JOURNAL_GROUP="):
                group = line.split("=", 1)[1].strip()
            elif line.startswith("JOURNAL_USERS="):
                journal_users = line.split("=", 1)[1].strip()

        issues: list[str] = []

        if perms and perms not in ("none", "700", "750"):
            world_bits = int(perms[-1]) if perms[-1].isdigit() else 0
            if world_bits >= 4:
                issues.append(
                    f"Journal directory is world-readable ({perms})"
                )

        if journal_users and journal_users != "none":
            issues.append(
                f"systemd-journal group members: {journal_users}"
            )

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"Enclave logs are accessible to non-root users: "
                    f"{' | '.join(issues)}"
                ),
                remediation=(
                    "Restrict journal access: chmod 750 /var/log/journal && "
                    "remove non-essential users from the systemd-journal "
                    "group. Consider forwarding enclave logs to a "
                    "dedicated, access-controlled log pipeline."
                ),
                evidence={
                    "journal_perms": perms,
                    "journal_group": group,
                    "journal_users": journal_users,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Journal logs are restricted to root.",
            evidence={
                "journal_perms": perms,
                "journal_group": group,
            },
        )
