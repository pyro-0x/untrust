"""ENCLAVE-04: Enclave booted from a signed image (PCR8).

AWS recommends signing enclave image files (EIFs) for production. A
signed EIF exposes PCR8 — the SHA384 of the signing certificate — which
lets KMS key policies trust "any image signed by our certificate"
(PCR8) instead of pinning a single image hash (PCR0). Without signing,
there is no PCR8, KMS policies cannot bind to a signing identity, and
there is no cryptographic link between the running image and your build
pipeline's signing key.

PCR8 is not reported by ``nitro-cli describe-enclaves`` — it is only
available from ``nitro-cli describe-eif``, which also reports whether
the image's signature verifies. This check locates the EIF the enclave
was launched from and inspects it.
"""
from __future__ import annotations

import json
import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

ZERO_PCR = "0" * 96


class EnclaveSignedCheck(Check):
    check_id = "ENCLAVE-04"
    title = "Enclave booted from a signed image (PCR8)"
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
            "EIF=$(ps -eo args 2>/dev/null | "
            "grep -oE -- '--eif-path[ =][^ ]+' | head -1 | "
            "sed -E 's/--eif-path[ =]//'); "
            "if [ -z \"$EIF\" ]; then "
            "EIF=$(find /opt /home /usr/share /var /root -maxdepth 6 "
            "-name '*.eif' 2>/dev/null | head -1); fi; "
            "if [ -z \"$EIF\" ]; then echo NO_EIF; "
            "else nitro-cli describe-eif --eif-path \"$EIF\" 2>/dev/null "
            "|| echo DESCRIBE_FAILED; fi"
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

        if "NO_EIF" in output:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="Could not locate an .eif file on the host to inspect.",
            )
        if "DESCRIBE_FAILED" in output or not output:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="nitro-cli describe-eif failed or is not available.",
            )

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="Could not parse nitro-cli describe-eif output.",
            )

        measurements = data.get("Measurements", {})
        pcr8 = measurements.get("PCR8", "")
        is_signed = bool(pcr8) and pcr8 != ZERO_PCR
        # describe-eif reports the signature verification result under one
        # of a few field names depending on nitro-cli version.
        sig_ok = data.get(
            "SignatureCheck",
            data.get("IsSigned", data.get("SignCheck")),
        )

        if not is_signed:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "Enclave image is unsigned (no PCR8). KMS policies cannot "
                    "bind to a signing identity, and there is no cryptographic "
                    "link between the running image and your build pipeline."
                ),
                remediation=(
                    "Build a signed EIF with nitro-cli build-enclave "
                    "--private-key and --signing-certificate (sign in CI, "
                    "never on the host), and pin PCR8 in the KMS key policy."
                ),
                evidence={"pcr8": pcr8 or "absent"},
            )

        if sig_ok is False:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "Enclave image has a PCR8 but its signature does not "
                    "verify. The image may be tampered or signed by an "
                    "unexpected certificate."
                ),
                remediation=(
                    "Rebuild and re-sign the EIF with your trusted signing "
                    "certificate; verify the signing chain in CI."
                ),
                evidence={
                    "pcr8": pcr8[:16] + "...",
                    "signature_check": sig_ok,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "Enclave booted from a signed EIF (PCR8 present"
                + (" and signature verified" if sig_ok else "")
                + ")."
            ),
            evidence={
                "pcr8": pcr8[:16] + "...",
                "signature_check": sig_ok,
            },
        )
