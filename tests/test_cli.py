"""Tests for the untrust CLI."""
from __future__ import annotations

import json

from click.testing import CliRunner

from untrust import __version__
from untrust.cli import cli


def test_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_list_checks_shows_all() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["list-checks"])
    assert result.exit_code == 0
    for cid in (
        "BOOTSTRAP-01", "BOOTSTRAP-02", "S3-01", "S3-02", "KMS-01", "IMDS-01",
        "IAM-01", "SSH-01", "PORT-01", "NAT-01", "HOST-01", "HOST-02",
        "EXEC-01", "ENV-01", "VSOCK-01", "DNS-01", "VPC-01",
        "CORE-01", "SWAP-01", "LOG-01", "RESTART-01",
        "ENCLAVE-01", "ENCLAVE-02", "ENCLAVE-03", "ENCLAVE-04",
        "ROLLBACK-01", "CLOUDTRAIL-01", "AUDIT-01",
        "DDB-01", "SECRETS-01", "SSM-01", "EFS-01", "RDS-01",
    ):
        assert cid in result.output
    assert "33 checks available" in result.output


def test_scan_demo_mode() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--demo"])
    assert result.exit_code == 0
    assert "SIMULATED SCAN" in result.output
    assert "BOOTSTRAP-01" in result.output
    assert "FAIL" in result.output
    assert "28 of 28 checks failed" in result.output


def test_scan_demo_json_output(tmp_path) -> None:
    output_file = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--demo", "--output", str(output_file)])
    assert result.exit_code == 0
    assert output_file.exists()

    report = json.loads(output_file.read_text())
    assert report["version"] == __version__
    assert report["summary"]["total"] == 28
    assert report["summary"]["fail"] == 28
    assert report["summary"]["pass"] == 0
    assert len(report["findings"]) == 28


def test_scan_no_args_errors() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"])
    assert result.exit_code == 1
    assert "--demo" in result.output


def test_read_only_flag_in_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--read-only" in result.output


def test_intrusive_ids_are_real_checks() -> None:
    from untrust.runner import ALL_CHECKS, INTRUSIVE_CHECK_IDS

    all_ids = {c.check_id for c in ALL_CHECKS}
    # Every intrusive id must correspond to a real registered check.
    assert all_ids >= INTRUSIVE_CHECK_IDS


def test_read_only_excludes_intrusive() -> None:
    from untrust.runner import (
        ALL_CHECKS,
        INTRUSIVE_CHECK_IDS,
        selected_checks,
    )

    full = selected_checks(read_only=False)
    passive = selected_checks(read_only=True)
    assert len(full) == len(ALL_CHECKS) == 33
    # 18 intrusive checks are dropped in read-only mode.
    assert len(passive) == 33 - len(INTRUSIVE_CHECK_IDS)
    passive_ids = {c.check_id for c in passive}
    # No intrusive check leaks into a read-only run.
    assert passive_ids.isdisjoint(INTRUSIVE_CHECK_IDS)
