"""Check runner — discovers and executes all registered audit checks."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .checks.audit_log import AuditLogCheck
from .checks.base import Assurance, Check, Finding, Status, Target
from .checks.bootstrap_input import BootstrapInputCheck
from .checks.bucket_policy import BucketPolicyCheck
from .checks.cloudtrail_audit import CloudTrailAuditCheck
from .checks.core_dump import CoreDumpCheck
from .checks.dns_dnat import DnsDnatCheck
from .checks.dynamodb_state import DynamoDbStateCheck
from .checks.efs_state import EfsStateCheck
from .checks.enclave_cotenant import EnclaveCotenantCheck
from .checks.enclave_debug import EnclaveDebugCheck
from .checks.enclave_pcr import EnclavePcrCheck
from .checks.enclave_signed import EnclaveSignedCheck
from .checks.env_var_semantic import EnvVarSemanticCheck
from .checks.exec_permissions import ExecPermissionsCheck
from .checks.host_permissions import HostPermissionsCheck
from .checks.host_services import HostServicesCheck
from .checks.iam_scope import IamScopeCheck
from .checks.imds_enforcement import ImdsEnforcementCheck
from .checks.kms_attestation import KmsAttestationCheck
from .checks.log_exposure import LogExposureCheck
from .checks.nat_egress import NatEgressCheck
from .checks.open_ports import OpenPortsCheck
from .checks.rds_state import RdsStateCheck
from .checks.restart_persistence import RestartPersistenceCheck
from .checks.s3_encryption import S3EncryptionCheck
from .checks.s3_public_access import S3PublicAccessCheck
from .checks.secrets_manager import SecretsManagerCheck
from .checks.ssh_hardening import SshHardeningCheck
from .checks.ssm_parameter import SsmParameterCheck
from .checks.state_rollback import StateRollbackCheck
from .checks.swap_exposure import SwapExposureCheck
from .checks.vpc_isolation import VpcIsolationCheck
from .checks.vsock_exposure import VsockExposureCheck

ALL_CHECKS: list[type[Check]] = [
    BootstrapInputCheck,
    BucketPolicyCheck,
    S3PublicAccessCheck,
    S3EncryptionCheck,
    DynamoDbStateCheck,
    SecretsManagerCheck,
    SsmParameterCheck,
    EfsStateCheck,
    RdsStateCheck,
    KmsAttestationCheck,
    ImdsEnforcementCheck,
    IamScopeCheck,
    SshHardeningCheck,
    OpenPortsCheck,
    NatEgressCheck,
    HostPermissionsCheck,
    HostServicesCheck,
    ExecPermissionsCheck,
    EnvVarSemanticCheck,
    VsockExposureCheck,
    DnsDnatCheck,
    VpcIsolationCheck,
    CoreDumpCheck,
    SwapExposureCheck,
    LogExposureCheck,
    RestartPersistenceCheck,
    EnclaveDebugCheck,
    EnclavePcrCheck,
    EnclaveSignedCheck,
    EnclaveCotenantCheck,
    StateRollbackCheck,
    CloudTrailAuditCheck,
    AuditLogCheck,
]

# Checks that are NOT safe to run quietly. Two families:
#   * Mutating / attack-shaped: BOOTSTRAP-01 writes path-traversal-shaped
#     objects to the state bucket (and deletes them) — this looks like an
#     exploitation attempt to S3 data-event / GuardDuty detections.
#   * Host command execution: everything that runs shell / nitro-cli on the
#     instance via SSM AWS-RunShellScript — host EDR sees credential-access
#     and discovery bursts, and every command is logged in SSM.
# --read-only skips this set, leaving only passive read-only API describes.
INTRUSIVE_CHECK_IDS: frozenset[str] = frozenset({
    # Tier 1 — mutating + attack signature
    "BOOTSTRAP-01",
    # Tier 2 — host/enclave shell execution via SSM
    "SSH-01", "PORT-01", "NAT-01", "HOST-01", "HOST-02", "EXEC-01",
    "ENV-01", "VSOCK-01", "DNS-01", "CORE-01", "SWAP-01", "LOG-01",
    "RESTART-01", "ENCLAVE-01", "ENCLAVE-02", "ENCLAVE-03", "ENCLAVE-04",
})

def selected_checks(read_only: bool = False) -> list[type[Check]]:
    """Return the checks to run. In read-only mode, drop intrusive checks."""
    if not read_only:
        return list(ALL_CHECKS)
    return [c for c in ALL_CHECKS if c.check_id not in INTRUSIVE_CHECK_IDS]


def run_checks(target: Target, check_classes: list[type[Check]]) -> list[Finding]:
    """Execute the given checks against a target and return findings."""
    findings: list[Finding] = []
    for check_cls in check_classes:
        check = check_cls()
        try:
            finding = check.run(target)
        except Exception as e:
            finding = Finding(
                check_id=check.check_id,
                title=check.title,
                status=Status.ERROR,
                severity=check.severity,
                summary=f"Check raised an exception: {e}",
            )
        # Stamp the check's evidence tier unless the finding set one itself.
        if finding.assurance is None:
            finding.assurance = check.assurance
        findings.append(finding)

    # Second pass: a REPORT_DERIVED PASS is only as trustworthy as the report's
    # signature verification. If a check it depends on (e.g. the signature-verify
    # check) did not pass, flag the verdict as reading from an unverified report.
    passed_ids = {f.check_id for f in findings if f.status == Status.PASS}
    for check_cls, finding in zip(check_classes, findings, strict=True):
        deps = getattr(check_cls, "assurance_depends_on", ())
        if (
            deps
            and finding.status == Status.PASS
            and finding.assurance == Assurance.REPORT_DERIVED
        ):
            missing = [d for d in deps if d not in passed_ids]
            if missing:
                finding.assurance_note = (
                    "report signature not verified (" + ", ".join(missing) + " not passed)"
                )
    return findings


def run_all(target: Target, read_only: bool = False) -> list[Finding]:
    """Execute the Nitro check set (backwards-compatible default).

    When ``read_only`` is True, intrusive checks (S3 write probe and host
    shell execution via SSM) are skipped so the scan stays passive.
    """
    return run_checks(target, selected_checks(read_only))


def format_console(findings: list[Finding], target: Target) -> str:
    """Format findings for terminal display."""
    from . import __version__

    lines: list[str] = []
    lines.append(f"untrust v{__version__} — TEE Deployment Audit Report")
    lines.append(f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    target_desc = (
        target.instance_id
        or target.bucket
        or target.wip_provider
        or target.gcp_project
        or target.attestation_token
        or "unknown"
    )
    lines.append(f"Target: {target_desc}")
    lines.append("")

    # Size the ID column to the longest ID so a long one (GPUCC-SIGVERIFY-01) never
    # runs into its summary.
    id_width = max((len(f.check_id) for f in findings), default=0) + 1
    for f in findings:
        icon = {
            Status.PASS: "\033[32m[PASS]\033[0m",
            Status.FAIL: "\033[31m[FAIL]\033[0m",
            Status.SKIP: "\033[33m[SKIP]\033[0m",
            Status.ERROR: "\033[33m[ERR ]\033[0m",
        }.get(f.status, "[????]")
        tag = f"  \033[2m[{f.assurance.value}]\033[0m" if f.assurance else ""
        note = f"  \033[33m⚠ {f.assurance_note}\033[0m" if f.assurance_note else ""
        lines.append(f"{icon} {f.check_id:<{id_width}}{f.summary}{tag}{note}")

    lines.append("")
    fail_count = sum(1 for f in findings if f.status == Status.FAIL)
    total = sum(1 for f in findings if f.status != Status.SKIP)
    if fail_count > 0:
        lines.append(f"\033[31m{fail_count} of {total} checks failed.\033[0m")
    else:
        lines.append(f"\033[32mAll {total} checks passed.\033[0m")

    # Reframe PASS results by how much each verdict can actually be trusted, so a
    # high pass-count doesn't read as stronger assurance than the evidence supports.
    # A report-derived PASS whose signature was never verified counts as unverified.
    passed = [f for f in findings if f.status == Status.PASS]
    if any(f.assurance for f in passed):
        verified = sum(
            1 for f in passed
            if f.assurance == Assurance.PROBED
            or (f.assurance == Assurance.REPORT_DERIVED and not f.assurance_note)
        )
        unverified = sum(
            1 for f in passed
            if f.assurance == Assurance.REPORT_DERIVED and f.assurance_note
        )
        declared = sum(1 for f in passed if f.assurance == Assurance.DECLARED)
        parts = []
        if verified:
            parts.append(f"{verified} verified")
        if unverified:
            parts.append(f"{unverified} unverified-report")
        if declared:
            parts.append(f"{declared} self-reported")
        lines.append(
            f"\033[2mOf the passes: {', '.join(parts)} "
            f"(self-reported = a policy says so; unverified-report = report read "
            f"but its signature unchecked).\033[0m"
        )

    return "\n".join(lines)


def format_json(findings: list[Finding], target: Target) -> str:
    """Format findings as JSON for programmatic consumption."""
    from . import __version__

    report: dict[str, Any] = {
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": {
            "platform": target.platform,
            "bucket": target.bucket,
            "kms_key_id": target.kms_key_id,
            "instance_id": target.instance_id,
            "region": target.region,
            "dynamodb_table": target.dynamodb_table,
            "secret_arn": target.secret_arn,
            "parameter_path": target.parameter_path,
            "efs_id": target.efs_id,
            "db_instance": target.db_instance,
            "gcp_project": target.gcp_project,
            "wip_provider": target.wip_provider,
            "gcp_kms_key": target.gcp_kms_key,
            "gcs_bucket": target.gcs_bucket,
            "gcp_instance": target.gcp_instance,
            "gcp_zone": target.gcp_zone,
            "attestation_token": target.attestation_token,
            "gpu_attestation_report": target.gpu_attestation_report,
            "gpu_verifier_policy": target.gpu_verifier_policy,
            "gpu_cc_mode": target.gpu_cc_mode,
            "gpu_kbs_policy": target.gpu_kbs_policy,
            "gpu_model_bucket": target.gpu_model_bucket,
            "gpu_launch_config": target.gpu_launch_config,
        },
        "summary": {
            "total": len(findings),
            "pass": sum(1 for f in findings if f.status == Status.PASS),
            "fail": sum(1 for f in findings if f.status == Status.FAIL),
            "skip": sum(1 for f in findings if f.status == Status.SKIP),
            "error": sum(1 for f in findings if f.status == Status.ERROR),
        },
        "findings": [
            {
                "check_id": f.check_id,
                "title": f.title,
                "status": f.status.value,
                "severity": f.severity.value,
                "assurance": f.assurance.value if f.assurance else None,
                "assurance_note": f.assurance_note,
                "summary": f.summary,
                "remediation": f.remediation,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }
    return json.dumps(report, indent=2)
