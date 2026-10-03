"""Tests for the host attestation platform (SEV-SNP reports and TPM2 quotes)."""

from __future__ import annotations

import hashlib
import json
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from untrust.checks.base import Assurance, Status, Target
from untrust.cli import cli
from untrust.platforms import checks_for, demo_for, supported_platforms
from untrust.platforms.host import HOST_CHECKS, snp, synth, tpm
from untrust.platforms.host.chain import verify_chain
from untrust.platforms.host.verify import verify
from untrust.runner import run_checks


def _issues(fx: synth.Fixture, control: str, nonce: bytes | None = synth.NONCE) -> list[str]:
    c = verify(fx.evidence, fx.baseline, nonce).controls[control]
    assert c.passed is False, c
    return c.issues


# --- SEV-SNP -------------------------------------------------------------------


def test_snp_good_evidence_is_allowed() -> None:
    fx = synth.snp_fixture()
    verdict = verify(fx.evidence, fx.baseline, fx.nonce)
    assert verdict.allowed, verdict.to_dict()
    assert verdict.controls["tcb"].evidence["reported_tcb"] == synth.GOOD_TCB


def test_snp_report_layout_roundtrip() -> None:
    report = snp.parse_report(synth.snp_fixture(debug=True).evidence.report)
    assert report.version == 3
    assert report.debug and not report.migrate_ma
    assert report.measurement == synth.GOOD_MEASUREMENT
    assert report.report_data == synth.NONCE.ljust(64, b"\0")
    assert report.signing_key == snp.SIGNING_KEY_VCEK


def test_snp_short_report_fails_every_control_closed() -> None:
    fx = synth.snp_fixture()
    fx.evidence.report = fx.evidence.report[:100]
    verdict = verify(fx.evidence, fx.baseline, fx.nonce)
    assert not verdict.allowed
    assert all(c.passed is False for c in verdict.controls.values())


def test_snp_unpinned_root_fails_chain() -> None:
    assert "no trusted root is pinned" in _issues(synth.snp_fixture(pin_root=False), "chain")[0]


def test_snp_root_must_match_the_pin() -> None:
    fx = synth.snp_fixture()
    fx.baseline["sev-snp"]["trusted_roots_sha256"] = ["00" * 32]
    assert "not a pinned trusted root" in _issues(fx, "chain")[0]


def test_snp_chain_out_of_order_fails() -> None:
    fx = synth.snp_fixture()
    vcek, ask, ark = fx.evidence.certs
    fx.evidence.certs = [vcek, ark, ask]
    assert any("not issued by" in i for i in _issues(fx, "chain"))


def test_chain_validity_window_is_enforced() -> None:
    fx = synth.snp_fixture()
    later = datetime.now(timezone.utc) + timedelta(days=4000)
    result = verify_chain(fx.evidence.certs, fx.baseline["sev-snp"]["trusted_roots_sha256"],
                          now=later)
    assert any("validity window" in i for i in result["issues"])


def test_chain_ca_constraint_when_required() -> None:
    # AMD-style certs carry no BasicConstraints; the TPM path demands CA=true.
    fx = synth.snp_fixture()
    result = verify_chain(fx.evidence.certs, fx.baseline["sev-snp"]["trusted_roots_sha256"],
                          require_ca_constraint=True)
    assert any("is not a CA certificate" in i for i in result["issues"])


def test_snp_tampered_report_fails_signature() -> None:
    issues = _issues(synth.snp_fixture(tamper=True), "signature")
    assert "does not verify" in issues[0]


def test_snp_masked_chip_key_is_unsigned() -> None:
    fx = synth.snp_fixture()
    raw = bytearray(fx.evidence.report)
    struct.pack_into("<I", raw, 0x48, 0b10)
    fx.evidence.report = bytes(raw)
    assert "unsigned" in _issues(fx, "signature")[0]


def test_snp_debug_and_migration_agent_fail() -> None:
    issues = _issues(synth.snp_fixture(debug=True, migrate_ma=True), "debug")
    assert any("DEBUG" in i for i in issues)
    assert any("migration agent" in i for i in issues)


def test_snp_debug_can_be_explicitly_allowed() -> None:
    fx = synth.snp_fixture(debug=True)
    fx.baseline["sev-snp"]["allow_debug"] = True
    assert verify(fx.evidence, fx.baseline, fx.nonce).controls["debug"].passed is True


def test_snp_tcb_below_floor_fails() -> None:
    rolled_back = {**synth.GOOD_TCB, "microcode": 115}
    issues = _issues(synth.snp_fixture(reported_tcb=rolled_back), "tcb")
    assert issues == ["reported microcode SVN 115 is below the floor 213"]


def test_snp_vcek_for_a_different_tcb_fails() -> None:
    other = {**synth.GOOD_TCB, "snp": 30}
    assert "different TCB" in _issues(synth.snp_fixture(cert_tcb=other), "tcb")[0]


def test_snp_vcek_hwid_must_match_chip_id() -> None:
    issues = _issues(synth.snp_fixture(cert_chip_id=b"\x99" * 64), "tcb")
    assert any("CHIP_ID" in i for i in issues)


def test_snp_missing_tcb_floor_fails() -> None:
    fx = synth.snp_fixture()
    del fx.baseline["sev-snp"]["min_tcb"]
    assert "no TCB floor" in _issues(fx, "tcb")[0]


def test_snp_nonce_mismatch_and_absent_nonce() -> None:
    fx = synth.snp_fixture()
    assert "replayed" in _issues(fx, "nonce", nonce=b"\x01" * 32)[0]
    assert verify(fx.evidence, fx.baseline, None).controls["nonce"].passed is None
    assert not verify(fx.evidence, fx.baseline, None).allowed  # unproven = denied


def test_snp_measurement_must_be_pinned_and_match() -> None:
    assert "not in the pinned" in _issues(
        synth.snp_fixture(measurement=b"\x01" * 48), "measurement")[0]
    fx = synth.snp_fixture()
    fx.baseline["sev-snp"]["measurements"] = []
    assert "no golden launch measurement" in _issues(fx, "measurement")[0]


def test_no_certificates_fails_closed() -> None:
    fx = synth.snp_fixture()
    fx.evidence.certs = []
    assert not verify(fx.evidence, fx.baseline, fx.nonce).allowed


# --- TPM2 ----------------------------------------------------------------------


def test_tpm_good_evidence_is_allowed() -> None:
    fx = synth.tpm_fixture()
    verdict = verify(fx.evidence, fx.baseline, fx.nonce)
    assert verdict.allowed, verdict.to_dict()
    assert verdict.controls["debug"].evidence["secure_boot"] is True
    assert verdict.controls["measurement"].evidence["event_log_replays"] is True


def test_tpm_quote_parse() -> None:
    quote = tpm.parse_quote(synth.tpm_fixture().evidence.quote)
    assert quote.extra_data == synth.NONCE
    assert quote.selection == [("sha256", [0, 7])]
    assert quote.firmware_version == 0x0001_0002_0003_0004


def test_tpm_tampered_quote_fails_signature() -> None:
    assert "does not verify" in _issues(synth.tpm_fixture(tamper=True), "signature")[0]


def test_tpm_sha1_quote_is_rejected() -> None:
    assert "SHA-1" in _issues(synth.tpm_fixture(hash_name="sha1"), "signature")[0]


def test_tpm_unpinned_ak_ca_fails_chain() -> None:
    assert "no trusted root" in _issues(synth.tpm_fixture(pin_root=False), "chain")[0]


def test_tpm_nonce_mismatch() -> None:
    assert "replayed" in _issues(synth.tpm_fixture(extra_data=b"old"), "nonce")[0]


def test_tpm_firmware_floor() -> None:
    issues = _issues(synth.tpm_fixture(firmware_version=1), "tcb")
    assert "below the floor" in issues[0]


def test_tpm_supplied_pcrs_must_hash_to_quote() -> None:
    fx = synth.tpm_fixture()
    fx.evidence.pcrs["sha256"][7] = b"\x42" * 32  # edited after the quote was signed
    issues = _issues(fx, "measurement")
    assert "do not hash to the quoted pcrDigest" in issues[0]


def test_tpm_pcr_off_baseline_and_log_mismatch() -> None:
    fx = synth.tpm_fixture(pcr_overrides={7: b"\x42" * 32})
    issues = _issues(fx, "measurement")
    assert any("PCR sha256:7 does not match" in i for i in issues)
    assert any("does not replay" in i for i in issues)


def test_tpm_pinned_pcr_must_be_quoted() -> None:
    fx = synth.tpm_fixture(quoted_pcrs=(0,))
    assert any("not covered by the quote" in i for i in _issues(fx, "measurement"))


def test_tpm_secure_boot_off() -> None:
    fx = synth.tpm_fixture(log=synth.event_log(secure_boot=False))
    assert "Secure Boot disabled" in _issues(fx, "debug")[0]


def test_tpm_forged_secure_boot_event_data() -> None:
    fx = synth.tpm_fixture(log=synth.event_log(forge_secure_boot=True))
    assert "does not match its measured digest" in _issues(fx, "debug")[0]


def test_tpm_secure_boot_needs_quoted_pcr7() -> None:
    fx = synth.tpm_fixture(quoted_pcrs=(0,))
    assert "PCR 7 is not quoted" in _issues(fx, "debug")[0]


def test_tpm_without_event_log_leaves_debug_unassessed() -> None:
    fx = synth.tpm_fixture()
    fx.evidence.event_log = None
    verdict = verify(fx.evidence, fx.baseline, fx.nonce)
    assert verdict.controls["debug"].passed is None
    assert verdict.controls["measurement"].passed is True
    assert not verdict.allowed


def test_event_log_startup_locality_seeds_pcr0() -> None:
    locality = (struct.pack("<II", 0, tpm.EV_NO_ACTION) + struct.pack("<IH", 1, 0x000B)
                + bytes(32) + struct.pack("<I", 17) + b"StartupLocality\0\x03")
    digest = hashlib.sha256(b"crtm").digest()
    event = (struct.pack("<II", 0, 0x8) + struct.pack("<IH", 1, 0x000B) + digest
             + struct.pack("<I", 4) + b"crtm")
    log = tpm.replay_event_log(synth._spec_id_event() + locality + event)
    expected = hashlib.sha256(bytes(31) + b"\x03" + digest).digest()
    assert log.pcrs["sha256"][0] == expected


def test_event_log_requires_crypto_agile_header() -> None:
    with pytest.raises(ValueError):
        tpm.replay_event_log(b"\0" * 64)


# --- Scanner integration -------------------------------------------------------


def test_host_platform_is_registered() -> None:
    assert "host" in supported_platforms()
    ids = [c.check_id for c in checks_for("host")]
    assert ids == ["HOST-CHAIN-01", "HOST-SIG-01", "HOST-NONCE-01", "HOST-DEBUG-01",
                   "HOST-TCB-01", "HOST-MEAS-01"]
    assert all(c.assurance == Assurance.REPORT_DERIVED for c in HOST_CHECKS)


@pytest.mark.parametrize("make", [synth.snp_fixture, synth.tpm_fixture])
def test_checks_pass_on_good_evidence_files(make, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    fx = make()
    evidence, baseline = synth.write_fixture(fx, tmp_path)
    target = Target(platform="host", host_evidence=str(evidence),
                    host_baseline=str(baseline), host_nonce=fx.nonce.hex())
    findings = run_checks(target, HOST_CHECKS)
    assert [f.status for f in findings] == [Status.PASS] * 6, [f.summary for f in findings]
    assert not any(f.assurance_note for f in findings)


def test_checks_skip_error_and_fail_paths(tmp_path: Path) -> None:
    assert all(f.status == Status.SKIP
               for f in run_checks(Target(platform="host"), HOST_CHECKS))

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"type": "tdx"}))
    assert all(f.status == Status.ERROR
               for f in run_checks(Target(platform="host", host_evidence=str(bad)), HOST_CHECKS))

    evidence, _ = synth.write_fixture(synth.snp_fixture(), tmp_path / "snp")
    by_id = {f.check_id: f for f in run_checks(
        Target(platform="host", host_evidence=str(evidence)), HOST_CHECKS)}
    assert by_id["HOST-CHAIN-01"].status == Status.FAIL  # no baseline = nothing pinned
    assert by_id["HOST-NONCE-01"].status == Status.SKIP
    assert by_id["HOST-SIG-01"].assurance_note  # sig passes but its chain did not


def test_demo_runs_real_checks() -> None:
    target, findings = demo_for("host")
    status = {f.check_id: f.status for f in findings}
    assert status["HOST-SIG-01"] == Status.PASS
    assert all(s == Status.FAIL for cid, s in status.items() if cid != "HOST-SIG-01")
    assert target.host_evidence and target.host_evidence.startswith("demo://")


def test_cli_scan_host(tmp_path: Path) -> None:
    fx = synth.tpm_fixture()
    evidence, baseline = synth.write_fixture(fx, tmp_path)
    runner = CliRunner()
    out = tmp_path / "report.json"
    ok = runner.invoke(cli, ["scan", "--platform", "host", "--host-evidence", str(evidence),
                             "--host-baseline", str(baseline), "--host-nonce", fx.nonce.hex(),
                             "--output", str(out)])
    assert ok.exit_code == 0, ok.output
    report = json.loads(out.read_text())
    assert report["summary"]["pass"] == 6
    assert report["target"]["host_evidence"] == str(evidence)

    stale = runner.invoke(cli, ["scan", "--platform", "host", "--host-evidence", str(evidence),
                                "--host-baseline", str(baseline), "--host-nonce", "00" * 32])
    assert stale.exit_code == 1
    assert "HOST-NONCE-01" in stale.output

    assert runner.invoke(cli, ["scan", "--platform", "host"]).exit_code == 1
    assert runner.invoke(cli, ["scan", "--platform", "host", "--host-evidence",
                               str(evidence), "--host-nonce", "zz"]).exit_code == 1
