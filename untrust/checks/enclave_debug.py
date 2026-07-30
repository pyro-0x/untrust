"""ENCLAVE-01: Enclave debug mode.

Verifies that no Nitro Enclave is running in debug mode on the host.
Debug mode disables the attestation guarantees — PCR values are
zeroed and the enclave's console is accessible from the host.  A
debug enclave provides no confidentiality or integrity protection.
"""
from __future__ import annotations

import json
import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class EnclaveDebugCheck(Check):
    check_id = "ENCLAVE-01"
    title = "Enclave debug mode is disabled"
    severity = Severity.CRITICAL

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
                summary=(
                    "nitro-cli not available or no enclaves found. "
                    "Cannot determine debug mode status."
                ),
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
                evidence={"raw_output": output[:500]},
            )

        if not enclaves:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="No enclaves are currently running.",
            )

        debug_enclaves: list[str] = []
        for enc in enclaves:
            flags = enc.get("Flags", "")
            enc_id = enc.get("EnclaveID", "unknown")
            is_debug = (
                ("DEBUG" in flags.upper() if isinstance(flags, str) else False)
                or (
                    isinstance(flags, list)
                    and any("DEBUG" in str(f).upper() for f in flags)
                )
            )
            if is_debug:
                debug_enclaves.append(enc_id)

        if debug_enclaves:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(debug_enclaves)} enclave(s) running in debug "
                    f"mode: {', '.join(debug_enclaves)}. Attestation is "
                    f"disabled and the console is accessible."
                ),
                remediation=(
                    "Terminate debug enclaves and re-launch without the "
                    "--debug-mode flag. Debug enclaves have zeroed PCR "
                    "values and provide no confidentiality guarantees."
                ),
                evidence={
                    "debug_enclaves": debug_enclaves,
                    "total_enclaves": len(enclaves),
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                f"{len(enclaves)} enclave(s) running, none in debug mode."
            ),
            evidence={"total_enclaves": len(enclaves)},
        )
