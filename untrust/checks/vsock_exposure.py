"""VSOCK-01: Unauthenticated vsock service exposure.

Enumerates vsock listeners on the enclave host and checks if any
respond without authentication. Unauthenticated RPC methods exposed
over vsock have been used to extract enclave metadata, operational
keys, and application state directly from the host.

This check discovers vsock listeners and flags them for manual
review — generic authentication testing is not possible without
knowledge of the application protocol.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class VsockExposureCheck(Check):
    check_id = "VSOCK-01"
    title = "Vsock service exposure"
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
            "ss -xlnp 2>/dev/null | grep -i vsock || "
            "ss -lnp 2>/dev/null | grep -i vsock || "
            "echo NONE"
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
                summary="No vsock listeners found on the host.",
                evidence={"vsock_listeners": []},
            )

        listeners = [
            line.strip() for line in output.splitlines() if line.strip()
        ]

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.FAIL,
            severity=self.severity,
            summary=(
                f"{len(listeners)} vsock listener(s) found on the host. "
                f"Verify each service requires authentication before "
                f"processing requests."
            ),
            remediation=(
                "Ensure every vsock service validates caller identity "
                "before processing requests. Unauthenticated RPC methods "
                "exposed over vsock allow host-side extraction of enclave "
                "metadata, keys, and operational state."
            ),
            evidence={"vsock_listeners": listeners},
        )
