"""Tests for the gpu-cc / NVIDIA GPU Confidential Computing platform checks."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from untrust.checks.base import Assurance, Boundary, Status, Target
from untrust.platforms import checks_for, demo_for, supported_platforms
from untrust.platforms.gpucc import ASSURANCE_BY_ID, BOUNDARY_BY_ID
from untrust.platforms.gpucc.attestation import GpuAttestationCheck, analyze_attestation_report
from untrust.platforms.gpucc.cc_mode import GpuCcModeCheck, analyze_cc_mode
from untrust.platforms.gpucc.cert_chain import analyze_cert_policy
from untrust.platforms.gpucc.cvm_binding import analyze_cvm_binding
from untrust.platforms.gpucc.decrypt_location import analyze_decrypt_location
from untrust.platforms.gpucc.dma_session import analyze_dma_session
from untrust.platforms.gpucc.failopen import analyze_fail_closed
from untrust.platforms.gpucc.gpu_cvm_bind import analyze_gpu_cvm_binding
from untrust.platforms.gpucc.input_safety import analyze_model_input
from untrust.platforms.gpucc.key_hygiene import analyze_key_hygiene
from untrust.platforms.gpucc.launch_mutability import analyze_launch_mutability
from untrust.platforms.gpucc.ready_state import analyze_key_release_policy
from untrust.platforms.gpucc.reattest import analyze_reattestation
from untrust.platforms.gpucc.rim_measurement import GpuRimPinningCheck, analyze_rim_pinning
from untrust.platforms.gpucc.signature_verify import analyze_signature_verification
from untrust.platforms.gpucc.vram_encryption import analyze_vram_encryption


def _good_report() -> dict[str, Any]:
    return {
        "cc_mode": "on",
        "gpu": {"model": "H100", "uuid": "GPU-1", "debug": False},
        "measurements": {"driver": "610.57.04", "vbios": "96.00.d9.00.01"},
        "signature": {"present": True, "verified": True},
        "memory": {"vram_encryption": True, "pcie_encryption": True, "spdm_session": True},
        "cpu_tee": {
            "type": "tdx", "debug": False, "secure_boot": True,
            "quote": {"present": True, "intel_chained": True, "verified": True, "debug": False},
        },
        "binding": {
            "gpu_report_includes_cvm_measurement": True,
            "cvm_quote_includes_gpu_identity": True,
        },
    }


def _write(d: str, name: str, obj: dict[str, Any]) -> str:
    p = os.path.join(d, name)
    with open(p, "w") as f:
        json.dump(obj, f)
    return p


# --- registry ---------------------------------------------------------------


def test_registry_exposes_gpucc() -> None:
    assert "gpu-cc" in supported_platforms()
    assert len(checks_for("gpu-cc")) == 17


def test_gpucc_demo_covers_all_checks() -> None:
    target, findings = demo_for("gpu-cc")
    assert target.platform == "gpu-cc"
    assert len(findings) == 17
    ids = {f.check_id for f in findings}
    assert {"GPUCC-ATT-01", "GPUCC-VMM-META-01", "GPUCC-INPUT-01", "GPUCC-BIND-01"} <= ids
    assert all(f.status == Status.FAIL for f in findings)  # vulnerable deployment


# --- GPUCC-MODE-01 (+ dedup) ------------------------------------------------


def test_cc_mode_on_passes() -> None:
    assert analyze_cc_mode("on")["passed"] is True


def test_cc_mode_devtools_and_off_fail() -> None:
    assert analyze_cc_mode("DevTools")["is_devtools"] is True
    assert analyze_cc_mode("off")["passed"] is False
    assert analyze_cc_mode(None)["passed"] is False


def test_cc_mode_check_runs_when_no_report() -> None:
    f = GpuCcModeCheck().run(Target(platform="gpu-cc", gpu_cc_mode="devtools"))
    assert f.status == Status.FAIL


def test_cc_mode_check_skips_when_report_present() -> None:
    # Dedup: ATT-01 already asserts CC-On from the signed report.
    f = GpuCcModeCheck().run(
        Target(platform="gpu-cc", gpu_cc_mode="devtools", gpu_attestation_report="report.json")
    )
    assert f.status == Status.SKIP and "GPUCC-ATT-01" in f.summary


# --- GPUCC-ATT-01 -----------------------------------------------------------


def test_attestation_good_report_passes() -> None:
    assert analyze_attestation_report(_good_report())["passed"] is True


def test_attestation_devtools_unsigned_unknown_fail() -> None:
    r = _good_report()
    r["cc_mode"] = "devtools"
    assert analyze_attestation_report(r)["passed"] is False
    r2 = _good_report()
    r2["signature"] = {"present": False}
    assert analyze_attestation_report(r2)["passed"] is False
    r3 = _good_report()
    r3["gpu"]["model"] = "RTX4090"
    assert analyze_attestation_report(r3)["passed"] is False


def test_attestation_check_skips_without_report() -> None:
    assert GpuAttestationCheck().run(Target(platform="gpu-cc")).status == Status.SKIP


# --- GPUCC-RIM-01 (+ golden-value cross-check + promotion) ------------------


def test_rim_no_pinning_is_identity_only() -> None:
    assert analyze_rim_pinning({"pinned_measurements": []}, _good_report())["passed"] is False


def test_rim_pins_required_passes() -> None:
    assert analyze_rim_pinning(
        {"pinned_measurements": ["driver", "vbios"]}, _good_report()
    )["passed"] is True


def test_rim_missing_one_measurement_fails() -> None:
    assert analyze_rim_pinning(
        {"pinned_measurements": ["vbios"]}, _good_report()  # driver unpinned
    )["passed"] is False


def test_rim_required_measurements_override() -> None:
    # Blackwell/NVLink domains can declare a chip-specific measurement set.
    report = _good_report()
    report["measurements"]["nvswitch"] = "1.0"
    policy = {"required_measurements": ["driver", "vbios", "nvswitch"],
              "pinned_measurements": ["driver", "vbios"]}  # nvswitch unpinned
    assert analyze_rim_pinning(policy, report)["passed"] is False
    policy["pinned_measurements"].append("nvswitch")
    assert analyze_rim_pinning(policy, report)["passed"] is True


def test_rim_value_crosscheck_matches_passes() -> None:
    policy = {"pinned_measurements": ["driver", "vbios"],
              "expected_measurements": {"driver": "610.57.04", "vbios": "96.00.d9.00.01"}}
    v = analyze_rim_pinning(policy, _good_report())
    assert v["passed"] is True and v["values_checked"] is True and v["mismatches"] == []


def test_rim_value_mismatch_fails_as_downgrade() -> None:
    policy = {"pinned_measurements": ["driver", "vbios"],
              "expected_measurements": {"driver": "610.57.04", "vbios": "96.00.d9.00.01"}}
    report = _good_report()
    report["measurements"]["driver"] = "535.00.00"
    v = analyze_rim_pinning(policy, report)
    assert v["passed"] is False and "driver" in v["mismatches"]


def test_rim_promotes_assurance_when_values_checked() -> None:
    d = tempfile.mkdtemp()
    rp = _write(d, "report.json", _good_report())
    pp = _write(d, "policy.json", {
        "pinned_measurements": ["driver", "vbios"],
        "expected_measurements": {"driver": "610.57.04", "vbios": "96.00.d9.00.01"}})
    f = GpuRimPinningCheck().run(
        Target(platform="gpu-cc", gpu_verifier_policy=pp, gpu_attestation_report=rp))
    assert f.status == Status.PASS and f.assurance is Assurance.REPORT_DERIVED


def test_rim_name_only_stays_declared_tier() -> None:
    d = tempfile.mkdtemp()
    pp = _write(d, "policy.json", {"pinned_measurements": ["driver", "vbios"]})
    f = GpuRimPinningCheck().run(Target(platform="gpu-cc", gpu_verifier_policy=pp))
    assert f.status == Status.PASS and f.assurance is None


# --- GPUCC-CERT-01 / READY-01 / DECRYPT-01 ----------------------------------


def test_cert_chain_validated_passes_else_fails() -> None:
    assert analyze_cert_policy({"cert_chain_to_nvidia_root": True})["passed"] is True
    assert analyze_cert_policy({"cert_chain_to_nvidia_root": False})["passed"] is False


def test_ready_state_requires_attest_before_and_bound() -> None:
    assert analyze_key_release_policy(
        {"attest_before_ready": True, "attestation_bound": True})["passed"] is True
    assert analyze_key_release_policy(
        {"attest_before_ready": False, "attestation_bound": True})["passed"] is False


def test_decrypt_location_tee_vs_host() -> None:
    assert analyze_decrypt_location({"decrypt_location": "tee"})["passed"] is True
    assert analyze_decrypt_location({"decrypt_location": "host"})["passed"] is False


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
    assert analyze_launch_mutability(
        {"measurement_pinned": True, "mutable_by": [{"principal": "ci", "kind": "ci"}]}
    )["passed"] is True


def test_launch_mutability_unpinned_or_host_fails() -> None:
    v0 = analyze_launch_mutability({"measurement_pinned": False, "mutable_by": []})
    assert v0["passed"] is False
    v = analyze_launch_mutability(
        {"measurement_pinned": True, "mutable_by": [{"principal": "vmm", "kind": "host"}]})
    assert v["passed"] is False and v["has_host"] is True


# --- GPUCC-CVM-01 (real TDX quote) ------------------------------------------


def test_cvm_binding_good_passes() -> None:
    assert analyze_cvm_binding(_good_report())["passed"] is True


def test_cvm_binding_grace_arm_cca_passes() -> None:
    # NVIDIA Grace superchip (GH200/GB200): the CPU TEE is ARM CCA, not TDX/SEV-SNP.
    r = _good_report()
    r["cpu_tee"]["type"] = "arm-cca"
    r["cpu_tee"]["quote"]["intel_chained"] = False
    r["cpu_tee"]["quote"]["vendor_chained"] = True
    assert analyze_cvm_binding(r)["passed"] is True


def test_cvm_binding_missing_quote_fails() -> None:
    # A CVM asserted verified but with no vendor-signed quote is the campaign gap.
    r = _good_report()
    r["cpu_tee"].pop("quote")
    v = analyze_cvm_binding(r)
    assert v["passed"] is False and v["quote_present"] is False


def test_cvm_binding_forged_or_debug_quote_fails() -> None:
    r = _good_report()
    r["cpu_tee"]["quote"]["intel_chained"] = False
    assert analyze_cvm_binding(r)["passed"] is False
    r2 = _good_report()
    r2["cpu_tee"]["quote"]["debug"] = True
    assert analyze_cvm_binding(r2)["passed"] is False
    r3 = _good_report()
    r3["cpu_tee"]["type"] = "none"
    assert analyze_cvm_binding(r3)["passed"] is False


# --- GPUCC-BIND-01 (GPU<->CVM binding) --------------------------------------


def test_bind_good_passes() -> None:
    assert analyze_gpu_cvm_binding(_good_report())["passed"] is True


def test_bind_unbound_fails() -> None:
    r = _good_report()
    r.pop("binding")
    v = analyze_gpu_cvm_binding(r)
    assert v["passed"] is False and v["fully_unbound"] is True
    r2 = _good_report()
    r2["binding"]["cvm_quote_includes_gpu_identity"] = False
    assert analyze_gpu_cvm_binding(r2)["passed"] is False


# --- GPUCC-SIGVERIFY-01 / REATTEST-01 / FAILOPEN-01 -------------------------


def test_signature_verification() -> None:
    assert analyze_signature_verification({"verify_signature": True})["passed"] is True
    assert analyze_signature_verification({})["passed"] is False


def test_reattestation_requires_continuous_and_on_change() -> None:
    assert analyze_reattestation(
        {"continuous_attestation": True, "reattest_on_state_change": True})["passed"] is True
    assert analyze_reattestation({"continuous_attestation": True})["passed"] is False


def test_fail_closed() -> None:
    assert analyze_fail_closed({"fail_closed": True})["passed"] is True
    assert analyze_fail_closed({"fail_closed": False})["passed"] is False


# --- GPUCC-KEY-01 -----------------------------------------------------------


def test_key_hygiene_good_passes() -> None:
    assert analyze_key_hygiene(
        {"dek_source": "kbs", "key_rotation_days": 30,
         "sa_user_managed_keys": 0, "sa_impersonators": []})["passed"] is True


def test_key_hygiene_env_dek_and_sa_bypass_fail() -> None:
    assert analyze_key_hygiene({"dek_source": "env", "key_rotation_days": 30})["passed"] is False
    assert analyze_key_hygiene(
        {"dek_source": "kbs", "key_rotation_days": 30, "sa_user_managed_keys": 2}
    )["passed"] is False
    assert analyze_key_hygiene({"dek_source": "kbs", "key_rotation_days": None})["passed"] is False


# --- GPUCC-INPUT-01 (deserialization) ---------------------------------------


def test_model_input_safe_loader_passes() -> None:
    v = analyze_model_input(
        {"model_input": {"loader": "safetensors", "signed_manifest": True,
                         "verify_digests_before_load": True}})
    assert v["passed"] is True and v["unsafe_loader"] is False


def test_model_input_pickle_and_absent_are_unsafe() -> None:
    assert analyze_model_input(
        {"model_input": {"loader": "pickle", "signed_manifest": True,
                         "verify_digests_before_load": True}})["unsafe_loader"] is True
    assert analyze_model_input({})["unsafe_loader"] is True
    assert analyze_model_input(
        {"model_input": {"loader": "torch_load"}})["unsafe_loader"] is True


# --- assurance tiering + boundaries -----------------------------------------


def test_every_check_tagged_with_tier_and_boundary() -> None:
    ids = {c.check_id for c in checks_for("gpu-cc")}
    assert ids == set(ASSURANCE_BY_ID) == set(BOUNDARY_BY_ID)
    for cls in checks_for("gpu-cc"):
        assert cls.assurance is ASSURANCE_BY_ID[cls.check_id]
        assert cls.boundary is BOUNDARY_BY_ID[cls.check_id]


def test_assurance_tiers_are_honest() -> None:
    assert ASSURANCE_BY_ID["GPUCC-ATT-01"] is Assurance.REPORT_DERIVED
    assert ASSURANCE_BY_ID["GPUCC-BIND-01"] is Assurance.REPORT_DERIVED
    assert ASSURANCE_BY_ID["GPUCC-MODEL-01"] is Assurance.PROBED
    assert ASSURANCE_BY_ID["GPUCC-SIGVERIFY-01"] is Assurance.DECLARED
    tiers = list(ASSURANCE_BY_ID.values())
    assert tiers.count(Assurance.REPORT_DERIVED) == 5
    assert tiers.count(Assurance.PROBED) == 1
    assert tiers.count(Assurance.DECLARED) == 11
    assert set(BOUNDARY_BY_ID.values()) == {
        Boundary.ATTESTATION, Boundary.INPUTS, Boundary.MEMORY, Boundary.VMM, Boundary.CVM}


def test_report_derived_pass_flagged_unverified_without_sigverify() -> None:
    from untrust.runner import run_checks
    d = tempfile.mkdtemp()
    rp = _write(d, "report.json", _good_report())  # good claims, nothing verifies the signature
    findings = run_checks(
        Target(platform="gpu-cc", gpu_attestation_report=rp), checks_for("gpu-cc"))
    vram = next(f for f in findings if f.check_id == "GPUCC-VRAM-01")
    assert vram.status == Status.PASS
    assert vram.assurance is Assurance.REPORT_DERIVED
    assert vram.assurance_note and "not verified" in vram.assurance_note


def test_report_derived_pass_clean_when_sigverify_passes() -> None:
    from untrust.runner import run_checks
    d = tempfile.mkdtemp()
    rp = _write(d, "report.json", _good_report())
    pp = _write(d, "policy.json", {
        "verify_signature": True, "pinned_measurements": ["driver", "vbios"],
        "cert_chain_to_nvidia_root": True})
    findings = run_checks(
        Target(platform="gpu-cc", gpu_attestation_report=rp, gpu_verifier_policy=pp),
        checks_for("gpu-cc"))
    vram = next(f for f in findings if f.check_id == "GPUCC-VRAM-01")
    assert vram.status == Status.PASS and vram.assurance_note is None
