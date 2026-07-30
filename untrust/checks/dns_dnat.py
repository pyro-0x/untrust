"""DNS-01: Host DNS DNAT rules.

Verifies whether the host uses iptables DNAT rules to redirect DNS traffic
from the enclave. If the enclave hardcodes a DNS resolver (e.g., 1.1.1.1)
and the host DNAT-redirects those queries, a compromised host can point DNS
at a rogue resolver and redirect enclave traffic to attacker-controlled IPs.
This is mitigated if the enclave performs TLS certificate pinning.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class DnsDnatCheck(Check):
    check_id = "DNS-01"
    title = "Host DNS DNAT rules"
    severity = Severity.LOW

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
            "iptables -t nat -L -v -n 2>/dev/null "
            "| grep -i 'dpt:53\\|DNAT.*:53\\|dns' || echo 'NONE'"
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
                summary="No DNS DNAT rules found. Enclave DNS is not redirected by the host.",
            )

        dnat_rules = [
            line.strip() for line in output.splitlines() if line.strip()
        ]

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.FAIL,
            severity=self.severity,
            summary=(
                f"Found {len(dnat_rules)} DNS DNAT rule(s). The host redirects "
                "enclave DNS queries, enabling DNS-based MITM if TLS pinning is absent."
            ),
            remediation=(
                "If the enclave performs TLS certificate pinning, this is partially "
                "mitigated. Otherwise, the enclave should resolve DNS internally or "
                "use IP addresses directly for critical endpoints. Document the DNAT "
                "dependency and its security implications."
            ),
            evidence={"dnat_rules": dnat_rules},
        )
