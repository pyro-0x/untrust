"""Command-line interface for untrust."""
from __future__ import annotations

import sys

try:
    import click
except ImportError:
    print(
        "untrust requires the 'click' package. Install with: pip install click",
        file=sys.stderr,
    )
    sys.exit(1)

from . import __version__
from .checks.base import Target
from .platforms.base import PLATFORM_ALIASES, canonical_platform
from .platforms.registry import supported_platforms


def _platform(ctx: click.Context, param: click.Parameter, value: str) -> str:
    """Resolve a renamed platform to its current name, with a one-line notice."""
    name = canonical_platform(value)
    if name != value:
        click.echo(f"Note: --platform {value} is now --platform {name}.", err=True)
    return name


PLATFORM_CHOICES = click.Choice(supported_platforms() + list(PLATFORM_ALIASES))


@click.group()
@click.version_option(__version__, prog_name="untrust")
def cli() -> None:
    """untrust — TEE deployment auditor for the trust boundaries that attestation forgets."""


@cli.command()
@click.option(
    "--platform", "platform", default="nitro",
    type=PLATFORM_CHOICES, callback=_platform,
    help="TEE platform to audit (default: nitro).",
)
# --- AWS Nitro target ---
@click.option("--target-bucket", help="[nitro] S3 bucket holding the enclave's bootstrap state.")
@click.option("--kms-key-id", help="[nitro] KMS key used to decrypt enclave secrets.")
@click.option("--instance-id", help="[nitro] EC2 instance ID running the Nitro Enclave.")
@click.option("--region", default="us-west-2", help="AWS region.")
# --- AWS Nitro alternative state/secret backends ---
@click.option(
    "--dynamodb-table",
    help="[nitro] DynamoDB table holding enclave bootstrap state (alternative to S3).",
)
@click.option(
    "--secret-arn",
    help="[nitro] Secrets Manager secret ARN the enclave loads at boot.",
)
@click.option(
    "--parameter-path",
    help="[nitro] SSM Parameter Store name/prefix the enclave loads at boot.",
)
@click.option(
    "--efs-id",
    help="[nitro] EFS filesystem ID mounted for enclave state.",
)
@click.option(
    "--db-instance",
    help="[nitro] RDS/Aurora DB instance identifier holding enclave state.",
)
# --- GCP Confidential Space / SEV-SNP target ---
@click.option("--gcp-project", help="[gcp-cspace] GCP project ID.")
@click.option("--wip-provider", help="[gcp-cspace] WIF provider resource gating key release.")
@click.option("--gcp-kms-key", help="[gcp-cspace] Cloud KMS key resource to audit IAM on.")
@click.option("--gcs-bucket", help="[gcp-cspace] GCS bucket holding bootstrap state.")
@click.option("--gcp-instance", help="[gcp-cspace] Confidential VM instance name.")
@click.option("--gcp-zone", help="[gcp-cspace] Zone of the Confidential VM.")
@click.option(
    "--attestation-token", type=click.Path(),
    help="[gcp-cspace] Path to a captured Confidential Space attestation token (JWT).",
)
# --- NVIDIA GPU Confidential Computing target ---
@click.option(
    "--gpu-attestation-report", type=click.Path(),
    help="[gpu-cc] Captured GPU attestation report (JSON); nvattest outputs sit beside it.",
)
@click.option(
    "--gpu-verifier-policy", type=click.Path(),
    help="[gpu-cc] Verifier policy JSON: RIM pins, cert chain, signature, re-attest, fail-closed.",
)
@click.option(
    "--gpu-cc-mode",
    help="[gpu-cc] CC mode (nvidia-smi conf-compute -f): on|devtools|off.",
)
@click.option(
    "--gpu-kbs-policy", type=click.Path(),
    help="[gpu-cc] Key-release policy JSON: attest-before-ready, decrypt, DEK, model loading.",
)
@click.option(
    "--gpu-model-bucket",
    help="[gpu-cc] Cloud Storage bucket holding model weights (canary-write injection probe).",
)
@click.option(
    "--gpu-launch-config", type=click.Path(),
    help="[gpu-cc] Path to the CVM/GPU launch config (JSON) for the launch-mutability check.",
)
# --- Host attestation target ---
@click.option(
    "--host-evidence", type=click.Path(),
    help="[host] Evidence manifest JSON: SEV-SNP report or TPM2 quote, cert chain, PCRs.",
)
@click.option(
    "--host-baseline", type=click.Path(),
    help="[host] Baseline JSON: pinned roots, golden measurements/PCRs, TCB floor.",
)
@click.option(
    "--host-nonce",
    help="[host] Hex nonce the verifier issued; must appear in the report/quote.",
)
# --- Azure confidential VM target ---
@click.option("--azure-subscription", help="[azure-cvm] Subscription ID.")
@click.option("--azure-resource-group", help="[azure-cvm] Resource group of the VM.")
@click.option("--azure-vm", help="[azure-cvm] Confidential VM name.")
@click.option("--azure-key-vault", help="[azure-cvm] Key Vault (name or host) holding the SKR key.")
@click.option("--azure-key", help="[azure-cvm] Key whose release policy gates the workload.")
@click.option(
    "--azure-attestation-provider",
    help="[azure-cvm] MAA provider name (in the resource group) or resource ID.",
)
@click.option(
    "--azure-attestation-token", type=click.Path(),
    help="[azure-cvm] MAA token (JWT) captured inside the VM.",
)
@click.option("--output", "output_path", type=click.Path(), help="Write JSON report to this path.")
@click.option("--json", "json_output", is_flag=True, help="Print JSON output to stdout.")
@click.option(
    "--read-only", "read_only", is_flag=True,
    help=(
        "Passive scan only: skip intrusive checks (the canary-write bucket "
        "probes on every platform, and the Nitro host shell/nitro-cli checks "
        "run via SSM) to avoid tripping SOC/EDR detections."
    ),
)
@click.option(
    "--demo", is_flag=True,
    help="Run against a simulated vulnerable deployment (no cloud creds needed).",
)
def scan(
    platform: str,
    target_bucket: str | None,
    kms_key_id: str | None,
    instance_id: str | None,
    region: str,
    dynamodb_table: str | None,
    secret_arn: str | None,
    parameter_path: str | None,
    efs_id: str | None,
    db_instance: str | None,
    gcp_project: str | None,
    wip_provider: str | None,
    gcp_kms_key: str | None,
    gcs_bucket: str | None,
    gcp_instance: str | None,
    gcp_zone: str | None,
    attestation_token: str | None,
    gpu_attestation_report: str | None,
    gpu_verifier_policy: str | None,
    gpu_cc_mode: str | None,
    gpu_kbs_policy: str | None,
    gpu_model_bucket: str | None,
    gpu_launch_config: str | None,
    host_evidence: str | None,
    host_baseline: str | None,
    host_nonce: str | None,
    azure_subscription: str | None,
    azure_resource_group: str | None,
    azure_vm: str | None,
    azure_key_vault: str | None,
    azure_key: str | None,
    azure_attestation_provider: str | None,
    azure_attestation_token: str | None,
    output_path: str | None,
    json_output: bool,
    read_only: bool,
    demo: bool,
) -> None:
    """Run all audit checks against a target deployment."""
    from .platforms import checks_for, demo_for
    from .runner import format_console, format_json, passive_only, run_all, run_checks

    if demo:
        target, findings = demo_for(platform)
        click.echo(
            "\033[33m╔══════════════════════════════════════════════════╗\033[0m"
        )
        click.echo(
            "\033[33m║  SIMULATED SCAN — NO REAL DEPLOYMENT TARGETED   ║\033[0m"
        )
        click.echo(
            "\033[33m╚══════════════════════════════════════════════════╝\033[0m"
        )
        click.echo("")
        click.echo(format_console(findings, target))
        if output_path or json_output:
            report = format_json(findings, target)
            if output_path:
                with open(output_path, "w") as f:
                    f.write(report)
                click.echo(f"\nJSON report written to: {output_path}")
            if json_output:
                click.echo(report)
        return

    if platform == "nitro":
        identifiers = [
            target_bucket, kms_key_id, instance_id,
            dynamodb_table, secret_arn, parameter_path, efs_id, db_instance,
        ]
        id_hint = (
            "--target-bucket, --kms-key-id, --instance-id, --dynamodb-table, "
            "--secret-arn, --parameter-path, --efs-id, or --db-instance"
        )
    elif platform == "gpu-cc":
        identifiers = [
            gpu_attestation_report, gpu_verifier_policy, gpu_cc_mode,
            gpu_kbs_policy, gpu_model_bucket, gpu_launch_config,
        ]
        id_hint = (
            "--gpu-attestation-report, --gpu-verifier-policy, --gpu-cc-mode, "
            "--gpu-kbs-policy, --gpu-model-bucket, or --gpu-launch-config"
        )
    elif platform == "host":
        identifiers = [host_evidence]
        id_hint = "--host-evidence"
        if host_nonce:
            try:
                bytes.fromhex(host_nonce)
            except ValueError:
                click.echo("Error: --host-nonce must be hex.", err=True)
                sys.exit(1)
    elif platform == "azure-cvm":
        identifiers = [azure_vm, azure_key, azure_attestation_token]
        id_hint = "--azure-vm, --azure-key, or --azure-attestation-token"
    else:  # gcp-cspace (and future platforms)
        identifiers = [wip_provider, gcp_kms_key, gcs_bucket, gcp_instance, attestation_token]
        id_hint = (
            "--wip-provider, --gcp-kms-key, --gcs-bucket, --gcp-instance, "
            "or --attestation-token"
        )

    if not any(identifiers):
        click.echo(
            f"Error: For --platform {platform}, provide at least one of "
            f"{id_hint}.\nOr use --demo to run against a simulated environment.",
            err=True,
        )
        sys.exit(1)

    target = Target(
        platform=platform,
        bucket=target_bucket,
        kms_key_id=kms_key_id,
        instance_id=instance_id,
        region=region,
        dynamodb_table=dynamodb_table,
        secret_arn=secret_arn,
        parameter_path=parameter_path,
        efs_id=efs_id,
        db_instance=db_instance,
        gcp_project=gcp_project,
        wip_provider=wip_provider,
        gcp_kms_key=gcp_kms_key,
        gcs_bucket=gcs_bucket,
        gcp_instance=gcp_instance,
        gcp_zone=gcp_zone,
        attestation_token=attestation_token,
        gpu_attestation_report=gpu_attestation_report,
        gpu_verifier_policy=gpu_verifier_policy,
        gpu_cc_mode=gpu_cc_mode,
        gpu_kbs_policy=gpu_kbs_policy,
        gpu_model_bucket=gpu_model_bucket,
        gpu_launch_config=gpu_launch_config,
        host_evidence=host_evidence,
        host_baseline=host_baseline,
        host_nonce=host_nonce,
        azure_subscription=azure_subscription,
        azure_resource_group=azure_resource_group,
        azure_vm=azure_vm,
        azure_key_vault=azure_key_vault,
        azure_key=azure_key,
        azure_attestation_provider=azure_attestation_provider,
        azure_attestation_token=azure_attestation_token,
    )

    if read_only:
        skipped = (
            "S3 write probe + host SSM commands" if platform == "nitro"
            else "bucket canary-write probe"
        )
        click.echo(f"\033[36mREAD-ONLY MODE — skipping intrusive checks ({skipped}).\033[0m")
    if platform == "nitro":
        findings = run_all(target, read_only=read_only)
    else:
        check_classes = checks_for(platform)
        if read_only:
            check_classes = passive_only(platform, check_classes)
        findings = run_checks(target, check_classes)
    click.echo(format_console(findings, target))

    if output_path or json_output:
        report = format_json(findings, target)
        if output_path:
            with open(output_path, "w") as f:
                f.write(report)
            click.echo(f"\nJSON report written to: {output_path}")
        if json_output:
            click.echo(report)

    fail_count = sum(1 for f in findings if f.status.value == "FAIL")
    sys.exit(1 if fail_count > 0 else 0)


@cli.command(name="list-checks")
@click.option(
    "--platform", "platform", default="nitro",
    type=PLATFORM_CHOICES, callback=_platform,
    help="TEE platform whose checks to list (default: nitro).",
)
def list_checks(platform: str) -> None:
    """List all audit checks and their severity."""
    from .platforms import checks_for

    check_classes = checks_for(platform)
    # Show the boundary/assurance columns only when the platform classifies them.
    tagged = any(c.boundary or c.assurance for c in check_classes)
    click.echo(f"Platform: {platform}\n")
    if tagged:
        click.echo(f"{'CHECK':<19}{'SEVERITY':<10}{'BOUNDARY':<13}{'ASSURANCE':<19}TITLE")
        click.echo(f"{'─' * 18} {'─' * 9} {'─' * 12} {'─' * 18} {'─' * 30}")
        for check_cls in check_classes:
            c = check_cls()
            boundary = c.boundary.value if c.boundary else "-"
            assurance = c.assurance.value if c.assurance else "-"
            click.echo(
                f"{c.check_id:<19}{c.severity.value:<10}{boundary:<13}{assurance:<19}{c.title}"
            )
        click.echo(
            "\nassurance: report-derived (trust gated on the evidence signature check) · "
            "probed (actively tested) · operator-declared (a policy says so)."
        )
    else:
        click.echo(f"{'CHECK':<18}{'SEVERITY':<12}TITLE")
        click.echo(f"{'─' * 17} {'─' * 11} {'─' * 40}")
        for check_cls in check_classes:
            check = check_cls()
            click.echo(f"{check.check_id:<18}{check.severity.value:<12}{check.title}")
    click.echo(f"\n{len(check_classes)} checks available.")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
