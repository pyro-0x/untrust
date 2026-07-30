"""ENV-01: Host-supplied configuration validation.

Verifies that the enclave validates that infrastructure config values
(bucket names, proxy URLs, KMS ARNs) delivered from the host point to
trusted resources. Without this, a compromised host can redirect the
enclave to attacker-controlled infrastructure.
"""
from __future__ import annotations

import re
import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

DANGEROUS_ENV_VARS = [
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "https_proxy",
    "http_proxy",
    "NO_PROXY",
    "ALL_PROXY",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "NODE_PATH",
]

INFRA_VARS_NEEDING_VALIDATION = {
    "BUCKET_NAME": re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$"),
    "KEY_ARN": re.compile(r"^arn:aws:kms:[a-z0-9-]+:\d{12}:key/[a-f0-9-]{36}$"),
    "BUCKET_STATE_DIR": re.compile(r"^[a-zA-Z0-9_\-/]+$"),
}


class EnvVarSemanticCheck(Check):
    check_id = "ENV-01"
    title = "Host-supplied configuration validation"
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
            "find /opt -name 'environment.conf' -o -name '*.env' -o -name 'environment' "
            "2>/dev/null | head -5 | xargs cat 2>/dev/null || echo 'NOT_FOUND'"
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

        if output == "NOT_FOUND":
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary="No host-supplied environment files found (may be hardcoded in EIF).",
            )

        dangerous_found: list[str] = []
        for var in DANGEROUS_ENV_VARS:
            pattern = rf"^{re.escape(var)}="
            if re.search(pattern, output, re.MULTILINE):
                dangerous_found.append(var)

        file_perms_command = (
            "find /opt -name 'environment.conf' -o -name '*.env' 2>/dev/null "
            "| head -5 | xargs stat -c '%a %n' 2>/dev/null || echo 'UNKNOWN'"
        )
        try:
            response2 = ssm.send_command(
                InstanceIds=[target.instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [file_perms_command]},
            )
            command_id2 = response2["Command"]["CommandId"]
            result2 = None
            for _ in range(10):
                time.sleep(3)
                try:
                    result2 = ssm.get_command_invocation(
                        CommandId=command_id2, InstanceId=target.instance_id
                    )
                    if result2["Status"] in ("Success", "Failed"):
                        break
                except ClientError:
                    continue
            perms_output = (
                result2.get("StandardOutputContent", "").strip()
                if result2 and result2.get("Status") in ("Success", "Failed")
                else "UNKNOWN"
            )
        except Exception:
            perms_output = "UNKNOWN"

        world_readable = any(
            line.startswith(("644", "666", "755", "777"))
            for line in perms_output.splitlines()
        )

        infra_warnings: list[str] = []
        for var_name, expected_pattern in INFRA_VARS_NEEDING_VALIDATION.items():
            match = re.search(rf"^{re.escape(var_name)}=(.+)$", output, re.MULTILINE)
            if match:
                value = match.group(1).strip().strip('"').strip("'")
                if not expected_pattern.match(value):
                    infra_warnings.append(
                        f"{var_name}={value} (does not match expected pattern)"
                    )
                elif var_name == "BUCKET_NAME" and target.bucket and value != target.bucket:
                    infra_warnings.append(
                        f"{var_name}={value} (does not match --target-bucket '{target.bucket}')"
                    )

        issues: list[str] = []
        if dangerous_found:
            issues.append(
                f"Dangerous env vars present: {', '.join(dangerous_found)}"
            )
        if infra_warnings:
            issues.append(
                f"Infrastructure vars need review: {'; '.join(infra_warnings)}"
            )
        if world_readable:
            issues.append("Environment file is world-readable")

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=" | ".join(issues),
                remediation=(
                    "Remove proxy-related and path-injection env vars from host-supplied "
                    "configuration. Restrict env files to root-only (chmod 600). "
                    "Implement a strict allowlist of permitted variable names with "
                    "semantic validation of values (e.g., bucket names must match "
                    "expected patterns)."
                ),
                evidence={
                    "dangerous_vars": dangerous_found,
                    "infra_warnings": infra_warnings,
                    "world_readable": world_readable,
                    "permissions": perms_output,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="No dangerous env vars found and files are properly restricted.",
        )
