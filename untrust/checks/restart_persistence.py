"""RESTART-01: Crash handler re-download persistence.

If the enclave's systemd service is configured with ``Restart=always``
(or ``on-failure``) and the boot sequence re-downloads state from S3,
a single S3 write gives an attacker persistent re-exploitation across
every service restart — no further attacker interaction required.

This is what makes such a kill chain persistent: one poisoned S3
object is re-downloaded on every ``systemctl restart``,
re-compromising the enclave indefinitely.

This check inspects enclave-related systemd units for restart
policies and flags the combination of automatic restart + external
state download.
"""
from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

DANGEROUS_RESTART_POLICIES = {"always", "on-failure", "on-abnormal", "on-abort"}


class RestartPersistenceCheck(Check):
    check_id = "RESTART-01"
    title = "Crash handler re-download persistence"
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
            "for svc in $(systemctl list-units --type=service --no-legend "
            "2>/dev/null | grep -iE 'enclave|cosign|nitro|tee' "
            "| awk '{print $1}'); do "
            "restart=$(systemctl show -p Restart \"$svc\" 2>/dev/null "
            "| cut -d= -f2); "
            "execstart=$(systemctl show -p ExecStart \"$svc\" 2>/dev/null "
            "| grep -oiE 's3|download|transfer|bootstrap|fetch' | head -1); "
            "echo \"$svc:$restart:${execstart:-none}\"; "
            "done || echo NONE"
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

        if output in ("NONE", ""):
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary=(
                    "No enclave-related services found with restart "
                    "policies."
                ),
                evidence={"services": []},
            )

        risky_services: list[str] = []
        all_services: list[dict[str, str]] = []

        for line in output.splitlines():
            line = line.strip()
            if not line or line == "NONE":
                continue
            parts = line.split(":")
            if len(parts) < 3:
                continue
            svc, restart, download_hint = parts[0], parts[1], parts[2]

            all_services.append({
                "service": svc,
                "restart": restart,
                "download_hint": download_hint,
            })

            if restart.lower() in DANGEROUS_RESTART_POLICIES:
                risky_services.append(f"{svc} (Restart={restart})")

        if risky_services:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(risky_services)} enclave service(s) auto-restart "
                    f"on failure: {', '.join(risky_services)}. If the boot "
                    f"sequence re-downloads state from S3, a single "
                    f"poisoned object persists across every restart."
                ),
                remediation=(
                    "Set Restart=no or Restart=on-success for enclave "
                    "services, or ensure the boot sequence validates "
                    "integrity (signatures/checksums) of downloaded "
                    "state before loading it. Automatic restart without "
                    "input validation creates persistent re-exploitation."
                ),
                evidence={
                    "risky_services": risky_services,
                    "all_services": all_services,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="No enclave services have dangerous restart policies.",
            evidence={"all_services": all_services},
        )
