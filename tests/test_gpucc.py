"""Tests for the gpu-cc / NVIDIA GPU Confidential Computing platform checks."""

from __future__ import annotations

from typing import Any

from untrust.checks.base import Status, Target
from untrust.platforms import checks_for, demo_for, supported_platforms
from untrust.platforms.gpucc.attestation import GpuAttestationCheck, analyze_attestation_report
from untrust.platforms.gpucc.cc_mode import analyze_cc_mode
from untrust.platforms.gpucc.cert_chain import analyze_cert_policy
from untrust.platforms.gpucc.cvm_binding import analyze_cvm_binding
from untrust.platforms.gpucc.decrypt_location import analyze_decrypt_location
from untrust.platforms.gpucc.dma_session import analyze_dma_session
from untrust.platforms.gpucc.failopen import analyze_fail_closed
from untrust.platforms.gpucc.key_hygiene import analyze_key_hygiene
from untrust.platforms.gpucc.launch_mutability import analyze_launch_mutability
from untrust.platforms.gpucc.ready_state import analyze_key_release_policy
from untrust.platforms.gpucc.reattest import analyze_reattestation
from untrust.platforms.gpucc.rim_measurement import analyze_rim_pinning
from untrust.platforms.gpucc.signature_verify import analyze_signature_verification
from untrust.platforms.gpucc.vram_encryption import analyze_vram_encryption


def _good_report() -> dict[str, Any]:
    return {
        "cc_mode": "on",
        "gpu": {"model": "H100", "uuid": "GPU-1", "debug": False},
        "measurements": {"vbios": "x", "gsp_firmware": "y", "driver": "z"},
        "signature": {"present": True, "verified": True},
        "memory": {"vram_encryption": True, "pcie_encryption": True, "spdm_session": True},
        "cpu_tee": {"type": "tdx", "verified": True, "debug": False, "secure_boot": True},
    }


# --- registry ---------------------------------------------------------------


def test_registry_exposes_gpucc() -> None:
    assert "gpu-cc" in supported_platforms()
    assert len(checks_for("gpu-cc")) == 15


def test_gpucc_demo_covers_all_checks() -> None:
    target, findings = demo_for("gpu-cc")
    assert target.platform == "gpu-cc"
    assert len(findings) == 15
    ids = {f.check_id for f in findings}
    assert "GPUCC-ATT-01" in ids and "GPUCC-VMM-META-01" in ids
    assert {"GPUCC-SIGVERIFY-01", "GPUCC-REATTEST-01", "GPUCC-FAILOPEN-01", "GPUCC-KEY-01"} <= ids
    # the demo is a vulnerable deployment: every check fails
    assert all(f.status == Status.FAIL for f in findings)


# --- GPUCC-MODE-01 ----------------------------------------------------------


def test_cc_mode_on_passes() -> None:
    assert analyze_cc_mode("on")["passed"] is True


def test_cc_mode_devtools_fails() -> None:
    v = analyze_cc_mode("DevTools")
    assert v["passed"] is False and v["is_devtools"] is True


def test_cc_mode_off_and_unset_fail() -> None:
    assert analyze_cc_mode("off")["passed"] is False
    assert analyze_cc_mode(None)["passed"] is False


# --- GPUCC-ATT-01 -----------------------------------------------------------


def test_attestation_good_report_passes() -> None:
    assert analyze_attestation_report(_good_report())["passed"] is True


def test_attestation_devtools_fails() -> None:
    r = _good_report()
    r["cc_mode"] = "devtools"
    assert analyze_attestation_report(r)["passed"] is False


def test_attestation_unsigned_and_unknown_model_fail() -> None:
    r = _good_report()
    r["signature"] = {"present": False}
    assert analyze_attestation_report(r)["passed"] is False
    r2 = _good_report()
    r2["gpu"]["model"] = "RTX4090"
    assert analyze_attestation_report(r2)["passed"] is False


def test_attestation_check_skips_without_report() -> None:
    f = GpuAttestationCheck().run(Target(platform="gpu-cc"))
    assert f.status == Status.SKIP


# --- GPUCC-RIM-01 -----------------------------------------------------------


def test_rim_no_pinning_is_identity_only() -> None:
    v = analyze_rim_pinning({"pinned_measurements": []}, _good_report())
    assert v["passed"] is False


def test_rim_pins_required_passes() -> None:
    policy = {"pinned_measurements": ["vbios", "gsp_firmware", "driver"]}
    assert analyze_rim_pinning(policy, _good_report())["passed"] is True


def test_rim_missing_one_measurement_fails() -> None:
    policy = {"pinned_measurements": ["vbios", "driver"]}  # gsp_firmware unpinned
    assert analyze_rim_pinning(policy, _good_report())["passed"] is False


# --- GPUCC-CERT-01 ----------------------------------------------------------


def test_cert_chain_validated_passes_else_fails() -> None:
    assert analyze_cert_policy({"cert_chain_to_nvidia_root": True})["passed"] is True
    assert analyze_cert_policy({"cert_chain_to_nvidia_root": False})["passed"] is False


# --- GPUCC-READY-01 / DECRYPT-01 -------------------------------------------


def test_ready_state_requires_attest_before_and_bound() -> None:
    assert analyze_key_release_policy(
        {"attest_before_ready": True, "attestation_bound": True}
    )["passed"] is True
    assert analyze_key_release_policy(
        {"attest_before_ready": False, "attestation_bound": True}
    )["passed"] is False


def test_decrypt_location_tee_vs_host() -> None:
    assert analyze_decrypt_location({"decrypt_location": "tee"})["passed"] is True
    assert analyze_decrypt_location({"decrypt_location": "host"})["passed"] is False
    assert analyze_decrypt_location({})["passed"] is False


# --- GPUCC-VRAM-01 / DMA-01 -------------------------------------------------


def test_vram_encryption() -> None:
    assert analyze_vram_encryption(_good_report())["passed"] is True
    r = _good_report()
    r["memory"]["vram_encryption"] = False
    assert analyze_vram_encryption(r)["passed"] is False


def test_dma_session_requires_pcie_and_spdm() -> None:
    assert analyze_dma_session(_good_report())["passed"] is True
    r = _good_report()
    r["memory"]["spdm_session"] = False
    assert analyze_dma_session(r)["passed"] is False


# --- GPUCC-VMM-META-01 ------------------------------------------------------


def test_launch_mutability_pinned_and_no_weak_passes() -> None:
    v = analyze_launch_mutability(
        {"measurement_pinned": True, "mutable_by": [{"principal": "ci", "kind": "ci"}]}
    )
    assert v["passed"] is True


def test_launch_mutability_unpinned_or_host_fails() -> None:
    assert analyze_launch_mutability(
        {"measurement_pinned": False, "mutable_by": []}
    )["passed"] is False
    v = analyze_launch_mutability(
        {"measurement_pinned": True, "mutable_by": [{"principal": "vmm", "kind": "host"}]}
    )
    assert v["passed"] is False and v["has_host"] is True


# --- GPUCC-CVM-01 -----------------------------------------------------------


def test_cvm_binding_good_passes() -> None:
    assert analyze_cvm_binding(_good_report())["passed"] is True


def test_cvm_binding_non_confidential_or_debug_fails() -> None:
    r = _good_report()
    r["cpu_tee"]["type"] = "none"
    assert analyze_cvm_binding(r)["passed"] is False
    r2 = _good_report()
    r2["cpu_tee"]["debug"] = True
    assert analyze_cvm_binding(r2)["passed"] is False


# --- GPUCC-SIGVERIFY-01 / REATTEST-01 / FAILOPEN-01 -------------------------


def test_signature_verification() -> None:
    assert analyze_signature_verification({"verify_signature": True})["passed"] is True
    assert analyze_signature_verification({"verify_signature": False})["passed"] is False
    assert analyze_signature_verification({})["passed"] is False


def test_reattestation_requires_continuous_and_on_change() -> None:
    assert analyze_reattestation(
        {"continuous_attestation": True, "reattest_on_state_change": True}
    )["passed"] is True
    assert analyze_reattestation({"continuous_attestation": True})["passed"] is False
    assert analyze_reattestation({})["passed"] is False


def test_fail_closed() -> None:
    assert analyze_fail_closed({"fail_closed": True})["passed"] is True
    assert analyze_fail_closed({"fail_closed": False})["passed"] is False


# --- GPUCC-KEY-01 -----------------------------------------------------------


def test_key_hygiene_good_passes() -> None:
    v = analyze_key_hygiene(
        {"dek_source": "kbs", "key_rotation_days": 30,
         "sa_user_managed_keys": 0, "sa_impersonators": []}
    )
    assert v["passed"] is True


def test_key_hygiene_env_dek_and_sa_bypass_fail() -> None:
    v = analyze_key_hygiene({"dek_source": "env", "key_rotation_days": 30})
    assert v["passed"] is False and v["dek_source"] == "env"
    v2 = analyze_key_hygiene(
        {"dek_source": "kbs", "key_rotation_days": 30, "sa_user_managed_keys": 2}
    )
    assert v2["passed"] is False
    v3 = analyze_key_hygiene(
        {"dek_source": "kbs", "key_rotation_days": None}
    )
    assert v3["passed"] is False  # no rotation
