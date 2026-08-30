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


@click.group()
@click.version_option(__version__, prog_name="untrust")
def cli() -> None:
    """untrust — TEE deployment auditor for the trust boundaries that attestation forgets."""


@cli.command()
@click.option(
    "--platform", "platform", default="nitro",
    type=click.Choice(["nitro", "sev-snp", "tdx"]),
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
@click.option("--gcp-project", help="[sev-snp] GCP project ID.")
@click.option("--wip-provider", help="[sev-snp] WIF provider resource gating key release.")
@click.option("--gcp-kms-key", help="[sev-snp] Cloud KMS key resource to audit IAM on.")
@click.option("--gcs-bucket", help="[sev-snp] GCS bucket holding bootstrap state.")
@click.option("--gcp-instance", help="[sev-snp] Confidential VM instance name.")
@click.option("--gcp-zone", help="[sev-snp] Zone of the Confidential VM.")
@click.option(
    "--attestation-token", type=click.Path(),
    help="[sev-snp] Path to a captured Confidential Space attestation token (JWT).",
)
@click.option("--output", "output_path", type=click.Path(), help="Write JSON report to this path.")
@click.option("--json", "json_output", is_flag=True, help="Print JSON output to stdout.")
@click.option(
    "--read-only", "read_only", is_flag=True,
    help=(
        "Passive scan only: skip intrusive checks (the S3 path-traversal "
        "write probe and all host shell/nitro-cli checks run via SSM) to "
        "avoid tripping SOC/EDR detections."
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
    output_path: str | None,
    json_output: bool,
    read_only: bool,
    demo: bool,
) -> None:
    """Run all audit checks against a target deployment."""
    from .platforms import checks_for, demo_for
    from .runner import format_console, format_json, run_all, run_checks

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
    else:  # sev-snp (and future platforms)
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
    )

    if platform == "nitro":
        if read_only:
            click.echo(
                "\033[36mREAD-ONLY MODE — skipping intrusive checks "
                "(S3 write probe + host SSM commands).\033[0m"
            )
        findings = run_all(target, read_only=read_only)
    else:
        findings = run_checks(target, checks_for(platform))
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
    type=click.Choice(["nitro", "sev-snp", "tdx"]),
    help="TEE platform whose checks to list (default: nitro).",
)
def list_checks(platform: str) -> None:
    """List all audit checks and their severity."""
    from .platforms import checks_for

    check_classes = checks_for(platform)
    click.echo(f"Platform: {platform}\n")
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
