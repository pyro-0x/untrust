"""ENCLAVE-02: Enclave runtime attestation (PCR values).

Verifies that the running enclave has non-zero PCR measurements,
confirming that attestation is active and the enclave image has
been measured by the Nitro hypervisor.

Zero PCR values indicate a debug enclave or a measurement failure.
This check also extracts the PCR0 hash for comparison against a
known-good EIF image hash.
"""
from __future__ import annotations

import json
import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

ZERO_PCR = "0" * 96


class EnclavePcrCheck(Check):
    check_id = "ENCLAVE-02"
    title = "Enclave PCR measurements are non-zero"
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

        if not enclaves:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="No enclaves are currently running.",
            )

        zeroed_enclaves: list[str] = []
        pcr_summary: dict[str, dict[str, str]] = {}

        for enc in enclaves:
            enc_id = enc.get("EnclaveID", "unknown")
            measurements = enc.get("Measurements", {})
            pcr0 = measurements.get("PCR0", "")
            pcr1 = measurements.get("PCR1", "")
            pcr2 = measurements.get("PCR2", "")

            pcr_summary[enc_id] = {
                "PCR0": pcr0[:16] + "..." if len(pcr0) > 16 else pcr0,
                "PCR1": pcr1[:16] + "..." if len(pcr1) > 16 else pcr1,
                "PCR2": pcr2[:16] + "..." if len(pcr2) > 16 else pcr2,
            }

            if (
                pcr0 == ZERO_PCR or pcr1 == ZERO_PCR or pcr2 == ZERO_PCR
                or (not pcr0 and not pcr1 and not pcr2)
            ):
                zeroed_enclaves.append(enc_id)

        if zeroed_enclaves:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(zeroed_enclaves)} enclave(s) have zeroed or "
                    f"missing PCR values — attestation is not active."
                ),
                remediation=(
                    "Zeroed PCR values indicate a debug enclave or a "
                    "measurement failure. Re-launch the enclave in "
                    "production mode without --debug-mode."
                ),
                evidence={
                    "zeroed_enclaves": zeroed_enclaves,
                    "pcr_values": pcr_summary,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                f"{len(enclaves)} enclave(s) have non-zero PCR values. "
                f"Attestation is active."
            ),
            evidence={"pcr_values": pcr_summary},
        )
