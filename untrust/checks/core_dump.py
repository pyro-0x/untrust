"""CORE-01: Core dump exposure.

If core dumps are enabled on the enclave host, a crash in the enclave
parent process (or the enclave proxy) can write process memory —
including decrypted secrets, KMS plaintext, and session keys — to
the host filesystem in plaintext.

This check inspects ``kernel.core_pattern`` and the hard ulimit for
core file size.  Both must be disabled for the enclave host to be
safe from post-crash memory exposure.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class CoreDumpCheck(Check):
    check_id = "CORE-01"
    title = "Core dump exposure"
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
            "echo CORE_PATTERN=$(sysctl -n kernel.core_pattern 2>/dev/null) && "
            "echo ULIMIT_CORE=$(ulimit -Hc 2>/dev/null)"
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

        core_pattern = ""
        ulimit_core = ""
        for line in output.splitlines():
            if line.startswith("CORE_PATTERN="):
                core_pattern = line.split("=", 1)[1].strip()
            elif line.startswith("ULIMIT_CORE="):
                ulimit_core = line.split("=", 1)[1].strip()

        issues: list[str] = []

        if core_pattern and core_pattern not in ("|/bin/false", "/dev/null", ""):
            issues.append(f"kernel.core_pattern={core_pattern}")

        if ulimit_core and ulimit_core not in ("0", ""):
            issues.append(f"ulimit core={ulimit_core}")

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"Core dumps are enabled: {' | '.join(issues)}. "
                    f"A crash could write enclave secrets to host disk "
                    f"in plaintext."
                ),
                remediation=(
                    "Disable core dumps: "
                    "echo 'kernel.core_pattern=|/bin/false' >> /etc/sysctl.conf && "
                    "sysctl -p && "
                    "echo '* hard core 0' >> /etc/security/limits.conf"
                ),
                evidence={
                    "core_pattern": core_pattern,
                    "ulimit_core": ulimit_core,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="Core dumps are disabled.",
            evidence={
                "core_pattern": core_pattern,
                "ulimit_core": ulimit_core,
            },
        )
