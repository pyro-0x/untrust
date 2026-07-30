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
@click.option("--target-bucket", help="S3 bucket holding the enclave's bootstrap state.")
@click.option("--kms-key-id", help="KMS key used to decrypt enclave secrets.")
@click.option("--instance-id", help="EC2 instance ID running the Nitro Enclave.")
@click.option("--region", default="us-west-2", help="AWS region.")
@click.option(
    "--dynamodb-table",
    help="DynamoDB table holding enclave bootstrap state (alternative to S3).",
)
@click.option(
    "--secret-arn",
    help="Secrets Manager secret ARN the enclave loads at boot.",
)
@click.option(
    "--parameter-path",
    help="SSM Parameter Store name/prefix the enclave loads at boot.",
)
@click.option(
    "--efs-id",
    help="EFS filesystem ID mounted for enclave state.",
)
@click.option(
    "--db-instance",
    help="RDS/Aurora DB instance identifier holding enclave state.",
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
    help="Run against a simulated vulnerable deployment (no AWS needed).",
)
def scan(
    target_bucket: str | None,
    kms_key_id: str | None,
    instance_id: str | None,
    region: str,
    dynamodb_table: str | None,
    secret_arn: str | None,
    parameter_path: str | None,
    efs_id: str | None,
    db_instance: str | None,
    output_path: str | None,
    json_output: bool,
    read_only: bool,
    demo: bool,
) -> None:
    """Run all audit checks against a target deployment."""
    from .runner import format_console, format_json, run_all

    if demo:
        from .demo import run_demo
        target, findings = run_demo()
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

    if not any([
        target_bucket, kms_key_id, instance_id,
        dynamodb_table, secret_arn, parameter_path, efs_id, db_instance,
    ]):
        click.echo(
            "Error: Provide at least one target, e.g. --target-bucket, "
            "--kms-key-id, --instance-id, --dynamodb-table, --secret-arn, "
            "--parameter-path, --efs-id, or --db-instance.\n"
            "Or use --demo to run against a simulated environment.",
            err=True,
        )
        sys.exit(1)

    target = Target(
        bucket=target_bucket,
        kms_key_id=kms_key_id,
        instance_id=instance_id,
        region=region,
        dynamodb_table=dynamodb_table,
        secret_arn=secret_arn,
        parameter_path=parameter_path,
        efs_id=efs_id,
        db_instance=db_instance,
    )

    if read_only:
        click.echo(
            "\033[36mREAD-ONLY MODE — skipping intrusive checks "
            "(S3 write probe + host SSM commands).\033[0m"
        )
    findings = run_all(target, read_only=read_only)
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
def list_checks() -> None:
    """List all audit checks and their severity."""
    from .runner import ALL_CHECKS

    click.echo(f"{'CHECK':<16}{'SEVERITY':<12}TITLE")
    click.echo(f"{'─' * 15} {'─' * 11} {'─' * 40}")
    for check_cls in ALL_CHECKS:
        check = check_cls()
        click.echo(f"{check.check_id:<16}{check.severity.value:<12}{check.title}")
    click.echo(f"\n{len(ALL_CHECKS)} checks available.")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
