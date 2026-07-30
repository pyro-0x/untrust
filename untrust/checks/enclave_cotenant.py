"""ENCLAVE-03: Multi-enclave co-tenancy.

Multiple enclaves on the same host share the hugepage memory pool
and compete for CPU time.  Co-tenancy introduces resource contention
risks and potential side-channel vectors between enclaves that are
meant to be isolated from each other.

A hardened deployment should run exactly one enclave per host.
"""
from __future__ import annotations

import json
import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class EnclaveCotenantCheck(Check):
    check_id = "ENCLAVE-03"
    title = "Multi-enclave co-tenancy"
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

        command = "nitro-cli describe-enclaves 2>/dev/null || echo NOT_AVAILABLE"

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

        if output == "NOT_AVAILABLE" or not output:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="nitro-cli not available or no enclaves found.",
            )

        try:
            enclaves = json.loads(output)
        except json.JSONDecodeError:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="Could not parse nitro-cli output.",
            )

        running = [
            e for e in enclaves
            if e.get("State", "").upper() == "RUNNING"
        ]

        if len(running) > 1:
            enc_ids = [e.get("EnclaveID", "?") for e in running]
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(running)} enclaves running on the same host: "
                    f"{', '.join(enc_ids)}. Shared hugepage pool and "
                    f"CPU contention create side-channel and resource "
                    f"starvation risks."
                ),
                remediation=(
                    "Run exactly one enclave per host. Separate "
                    "workloads onto dedicated EC2 instances to "
                    "eliminate resource contention and co-tenancy "
                    "side-channels."
                ),
                evidence={
                    "running_enclaves": enc_ids,
                    "total_count": len(running),
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                f"{len(running)} enclave running. No co-tenancy risk."
            ),
            evidence={"total_count": len(running)},
        )
