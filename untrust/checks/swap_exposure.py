"""SWAP-01: Swap exposure.

If swap is enabled on the enclave host, the kernel may page enclave
parent process memory — including decrypted secrets held in userspace
buffers — to unencrypted disk.  This creates a persistent, silent
exposure that survives process termination.

This check runs ``swapon --show`` via SSM and flags any active swap
device.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class SwapExposureCheck(Check):
    check_id = "SWAP-01"
    title = "Swap exposure"
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

        command = "swapon --show --noheadings 2>/dev/null || echo NONE"

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

        if output in ("NONE", ""):
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary="No swap devices are active.",
                evidence={"swap_devices": []},
            )

        devices = [line.strip() for line in output.splitlines() if line.strip()]

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.FAIL,
            severity=self.severity,
            summary=(
                f"{len(devices)} swap device(s) active. Enclave process "
                f"memory could be paged to unencrypted disk."
            ),
            remediation=(
                "Disable swap: swapoff -a && "
                "remove swap entries from /etc/fstab. "
                "Enclave hosts should never use swap — secrets in "
                "userspace buffers can be silently written to disk."
            ),
            evidence={"swap_devices": devices},
        )
