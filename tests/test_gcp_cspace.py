"""Tests for the gcp-cspace (GCP Confidential Space) platform checks."""

from __future__ import annotations

import base64
import json

import pytest

from untrust.checks.base import Status, Target
from untrust.platforms import checks_for, demo_for, supported_platforms
from untrust.platforms.gcp_cspace.attestation import (
    ConfidentialSpaceAttestationCheck,
    analyze_token_claims,
)
from untrust.platforms.gcp_cspace.gcs_bootstrap import analyze_gcs_bucket
from untrust.platforms.gcp_cspace.keybind import (
    ConfidentialSpaceKeyReleaseCheck,
    analyze_wif_condition,
)
from untrust.platforms.gcp_cspace.kms_binding import analyze_kms_bindings
from untrust.platforms.gcp_cspace.vm_config import analyze_instance_config

# --- registry ---------------------------------------------------------------


def test_registry_exposes_platforms() -> None:
    assert "nitro" in supported_platforms()
    assert "gcp-cspace" in supported_platforms()
    assert len(checks_for("gcp-cspace")) == 11


def test_nitro_registry_unchanged() -> None:
    # The platform layer resolves "nitro" to the runner's full check set, verbatim.
    from untrust.runner import ALL_CHECKS

    assert checks_for("nitro") == ALL_CHECKS


# --- CSPACE-KEYBIND-01: WIF condition analysis ------------------------------


def test_wif_condition_none_is_weak() -> None:
    v = analyze_wif_condition(None)
    assert v["has_condition"] is False
    assert v["passed"] is False


def test_wif_condition_identity_only_fails() -> None:
    # Proves identity (service account) but pins neither dbgstat nor image.
    cond = (
        "assertion.swname == 'CONFIDENTIAL_SPACE' && "
        "assertion.google_service_accounts.exists(sa, sa == 'x@p.iam.gserviceaccount.com')"
    )
    v = analyze_wif_condition(cond)
    assert v["passed"] is False
    assert not v["pins_image_digest"]
    assert not v["binds_dbgstat"]


def test_wif_condition_image_present_but_not_pinned_fails() -> None:
    cond = (
        "assertion.submods.container.image_digest != '' && "
        "assertion.dbgstat == 'disabled-since-boot'"
    )
    v = analyze_wif_condition(cond)
    assert v["image_digest_present_only"] is True
    assert v["passed"] is False


def test_wif_condition_fully_bound_passes() -> None:
    cond = (
        "assertion.swname == 'CONFIDENTIAL_SPACE' && "
        "assertion.dbgstat == 'disabled-since-boot' && "
        "assertion.hwmodel == 'GCP_AMD_SEV' && "
        "assertion.submods.container.image_digest == 'sha256:abc123' && "
        "assertion.submods.confidential_space.support_attributes.exists(s, s == 'STABLE')"
    )
    v = analyze_wif_condition(cond)
    assert v["binds_dbgstat"] is True
    assert v["pins_image_digest"] is True
    assert v["passed"] is True
    assert v["gating_weaknesses"] == []


@pytest.mark.parametrize("hwmodel", ["GCP_AMD_SEV", "GCP_INTEL_TDX"])
def test_wif_condition_hwmodel_binding_covers_sev_and_tdx(hwmodel: str) -> None:
    v = analyze_wif_condition(f"assertion.hwmodel == '{hwmodel}'")
    assert v["binds_hwmodel"] is True
    assert not any("hwmodel" in w for w in v["recommended_weaknesses"])


def test_keybind_check_skips_without_provider() -> None:
    f = ConfidentialSpaceKeyReleaseCheck().run(Target(platform="gcp-cspace"))
    assert f.status == Status.SKIP


# --- CSPACE-ATT-01: token claim analysis ------------------------------------


def test_token_claims_debug_and_unsigned_fails() -> None:
    v = analyze_token_claims(
        {
            "dbgstat": "enabled",
            "hwmodel": "GCP_AMD_SEV",
            "submods": {
                "container": {"image_signatures": []},
                "confidential_space": {"support_attributes": ["USABLE"]},
            },
        }
    )
    assert v["passed"] is False
    assert any("dbgstat" in i for i in v["issues"])
    assert any("USABLE" in i for i in v["issues"])
    assert any("unsigned" in i for i in v["issues"])


def test_token_claims_trusted_passes() -> None:
    v = analyze_token_claims(
        {
            "dbgstat": "disabled-since-boot",
            "hwmodel": "GCP_AMD_SEV",
            "submods": {
                "container": {
                    "image_digest": "sha256:abc",
                    "image_signatures": [{"signature": "..."}],
                },
                "confidential_space": {"support_attributes": ["STABLE"]},
            },
        }
    )
    assert v["passed"] is True
    assert v["issues"] == []


def _trusted_claims(hwmodel: str) -> dict:
    return {
        "dbgstat": "disabled-since-boot",
        "hwmodel": hwmodel,
        "submods": {
            "container": {"image_digest": "sha256:abc", "image_signatures": [{"signature": "."}]},
            "confidential_space": {"support_attributes": ["STABLE"]},
        },
    }


def test_token_claims_intel_tdx_hardware_passes() -> None:
    assert analyze_token_claims(_trusted_claims("GCP_INTEL_TDX"))["passed"] is True


@pytest.mark.parametrize("hwmodel", ["GCP_SHIELDED_VM", ""])
def test_token_claims_non_confidential_hardware_fails(hwmodel: str) -> None:
    v = analyze_token_claims(_trusted_claims(hwmodel))
    assert v["passed"] is False
    assert any("GCP_AMD_SEV or GCP_INTEL_TDX" in i for i in v["issues"])


def test_attestation_check_decodes_jwt(tmp_path) -> None:
    claims = {
        "dbgstat": "enabled",
        "hwmodel": "GCP_AMD_SEV",
        "submods": {"container": {"image_signatures": []}, "confidential_space": {}},
    }
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    token = f"header.{payload}.sig"
    token_file = tmp_path / "token.jwt"
    token_file.write_text(token)

    f = ConfidentialSpaceAttestationCheck().run(
        Target(platform="gcp-cspace", attestation_token=str(token_file))
    )
    assert f.status == Status.FAIL


# --- CSPACE-KMS-01: KMS IAM binding analysis --------------------------------


def test_kms_public_and_sa_grants_fail() -> None:
    v = analyze_kms_bindings(
        [
            {"role": "roles/cloudkms.cryptoKeyDecrypter", "members": ["allAuthenticatedUsers"]},
            {
                "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                "members": ["serviceAccount:x@p.iam.gserviceaccount.com"],
            },
        ]
    )
    assert v["passed"] is False
    assert v["has_public"] is True
    assert len(v["weak_grants"]) == 2


def test_kms_federated_principalset_passes() -> None:
    member = (
        "principalSet://iam.googleapis.com/projects/123/locations/global/"
        "workloadIdentityPools/pool/attribute.image_digest/sha256:abc"
    )
    v = analyze_kms_bindings([{"role": "roles/cloudkms.cryptoKeyDecrypter", "members": [member]}])
    assert v["passed"] is True
    assert v["federated_grants"][0]["kind"] == "attested_scoped"


def test_kms_no_decrypt_grant_passes() -> None:
    v = analyze_kms_bindings([{"role": "roles/cloudkms.viewer", "members": ["allUsers"]}])
    assert v["passed"] is True


# --- GCS-BOOT-01: bucket hardening analysis ---------------------------------


def test_gcs_open_bucket_fails() -> None:
    v = analyze_gcs_bucket(
        {
            "iamConfiguration": {
                "publicAccessPrevention": "inherited",
                "uniformBucketLevelAccess": {"enabled": False},
            },
            "versioning": {"enabled": False},
        },
        [{"role": "roles/storage.objectAdmin", "members": ["allUsers"]}],
    )
    assert v["passed"] is False
    assert v["public_members"]
    assert v["broad_writers"]


def test_gcs_hardened_bucket_passes() -> None:
    v = analyze_gcs_bucket(
        {
            "iamConfiguration": {
                "publicAccessPrevention": "enforced",
                "uniformBucketLevelAccess": {"enabled": True},
            },
            "versioning": {"enabled": True},
            "retentionPolicy": {"retentionPeriod": "86400"},
        },
        [
            {
                "role": "roles/storage.objectViewer",
                "members": ["principalSet://iam.googleapis.com/.../workloadIdentityPools/p/*"],
            }
        ],
    )
    assert v["passed"] is True
    assert v["issues"] == []


# --- CSPACE-VM-01: instance config analysis ---------------------------------


def test_vm_plain_instance_fails() -> None:
    v = analyze_instance_config(
        {
            "confidentialInstanceConfig": {"enableConfidentialCompute": False},
            "shieldedInstanceConfig": {},
        }
    )
    assert v["passed"] is False


SHIELDED = {"enableSecureBoot": True, "enableVtpm": True, "enableIntegrityMonitoring": True}
CSPACE_METADATA = {"items": [{"key": "tee-image-reference", "value": "registry/workload@sha256:x"}]}


def _vm(cc_type: str, *, cspace: bool) -> dict:
    instance = {
        "confidentialInstanceConfig": {
            "enableConfidentialCompute": True,
            "confidentialInstanceType": cc_type,
        },
        "shieldedInstanceConfig": SHIELDED,
    }
    if cspace:
        instance["metadata"] = CSPACE_METADATA
    return instance


@pytest.mark.parametrize("cc_type", ["SEV", "TDX"])
def test_vm_confidential_space_on_sev_or_tdx_passes(cc_type: str) -> None:
    v = analyze_instance_config(_vm(cc_type, cspace=True))
    assert v["passed"] is True
    assert v["runs_confidential_space"] is True
    assert v["tee"] in ("AMD SEV", "Intel TDX")


def test_vm_confidential_space_on_sev_snp_fails() -> None:
    # Confidential Space attestation rejects SEV-SNP (UNSUPPORTED_CC_TECHNOLOGY):
    # the launcher exits before the workload starts.
    v = analyze_instance_config(_vm("SEV_SNP", cspace=True))
    assert v["passed"] is False
    assert any("UNSUPPORTED_CC_TECHNOLOGY" in i for i in v["issues"])


def test_vm_plain_sev_snp_confidential_vm_passes() -> None:
    v = analyze_instance_config(_vm("SEV_SNP", cspace=False))
    assert v["passed"] is True
    assert v["tee"] == "AMD SEV-SNP" and v["runs_confidential_space"] is False


def test_vm_confidential_space_detected_from_boot_image_license() -> None:
    instance = _vm("SEV_SNP", cspace=False)
    instance["disks"] = [{"licenses": ["projects/confidential-space-images/global/licenses/x"]}]
    assert analyze_instance_config(instance)["runs_confidential_space"] is True


def test_vm_unknown_confidential_type_fails() -> None:
    v = analyze_instance_config(_vm("", cspace=True))
    assert v["passed"] is False
    assert any("expected SEV, TDX or SEV_SNP" in i for i in v["issues"])


def test_vm_shielded_boot_still_required() -> None:
    instance = _vm("TDX", cspace=True)
    instance["shieldedInstanceConfig"] = {"enableSecureBoot": False, "enableVtpm": True,
                                          "enableIntegrityMonitoring": True}
    v = analyze_instance_config(instance)
    assert v["passed"] is False and "Secure Boot is disabled" in v["issues"]


# --- demo -------------------------------------------------------------------


def test_gcp_cspace_demo_returns_findings() -> None:
    target, findings = demo_for("gcp-cspace")
    assert target.platform == "gcp-cspace"
    assert {f.check_id for f in findings} == {
        "CSPACE-KEYBIND-01",
        "CSPACE-KMS-01",
        "GCS-BOOT-01",
        "GCS-BOOT-02",
        "CSPACE-VM-01",
        "CSPACE-ATT-01",
        "CSPACE-META-01",
        "CSPACE-SA-01",
        "CSPACE-SAKEY-01",
        "CSPACE-WIF-02",
        "CSPACE-IMG-01",
    }
    assert all(f.status == Status.FAIL for f in findings)


# --- Tier-1 attestation-bypass checks --------------------------------------


def test_metadata_writers_flag_workload_sa_and_public() -> None:
    from untrust.platforms.gcp_cspace.metadata_mutability import analyze_metadata_writers

    sa = "wl@p.iam.gserviceaccount.com"
    v = analyze_metadata_writers(
        [
            {"role": "roles/compute.instanceAdmin.v1", "members": [f"serviceAccount:{sa}"]},
            {"role": "roles/owner", "members": ["allUsers"]},
        ],
        workload_sa=sa,
    )
    assert v["passed"] is False
    assert v["self_mutate"] is True
    assert v["has_public"] is True


def test_metadata_writers_pass_when_admin_only() -> None:
    from untrust.platforms.gcp_cspace.metadata_mutability import analyze_metadata_writers

    v = analyze_metadata_writers(
        [{"role": "roles/compute.instanceAdmin.v1", "members": ["group:sre@corp"]}],
        workload_sa="wl@p.iam.gserviceaccount.com",
    )
    assert v["passed"] is True


def test_sa_impersonation_and_keys() -> None:
    from untrust.platforms.gcp_cspace.sa_identity import (
        analyze_sa_impersonation,
        analyze_sa_keys,
    )

    imp = analyze_sa_impersonation(
        [{"role": "roles/iam.serviceAccountTokenCreator", "members": ["allAuthenticatedUsers"]}]
    )
    assert imp["passed"] is False and imp["has_public"] is True
    assert analyze_sa_impersonation([])["passed"] is True

    keys = analyze_sa_keys(
        [{"keyType": "USER_MANAGED", "name": "k/1"}, {"keyType": "SYSTEM_MANAGED"}]
    )
    assert keys["passed"] is False and keys["count"] == 1
    assert analyze_sa_keys([{"keyType": "SYSTEM_MANAGED"}])["passed"] is True


def test_wif_siblings_flag_weak_provider() -> None:
    from untrust.platforms.gcp_cspace.wif_siblings import analyze_providers

    v = analyze_providers(
        [
            {
                "name": ".../providers/strong",
                "oidc": {"issuerUri": "https://confidentialcomputing.googleapis.com/"},
                "attributeCondition": (
                    "assertion.dbgstat == 'disabled-since-boot' && "
                    "assertion.submods.container.image_digest == 'sha256:abc'"
                ),
            },
            {
                "name": ".../providers/legacy-ci",
                "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                "attributeCondition": None,
            },
        ],
        primary_provider_id="strong",
    )
    assert v["passed"] is False
    assert v["weak_providers"][0]["provider"] == "legacy-ci"


def test_image_signing_flags_unsigned_and_tag() -> None:
    from untrust.platforms.gcp_cspace.image_signing import analyze_image_signing

    v = analyze_image_signing(
        [{"key": "tee-image-reference", "value": "us-docker.pkg.dev/p/r/img:latest"}],
        [{"role": "roles/artifactregistry.writer", "members": ["allAuthenticatedUsers"]}],
    )
    assert v["passed"] is False
    assert any("not set" in i for i in v["issues"])  # signing not enforced
    assert any("tag" in i for i in v["issues"])  # not digest-pinned
    assert v["broad_writers"]  # broadly writable repo


def test_image_signing_passes_when_hardened() -> None:
    from untrust.platforms.gcp_cspace.image_signing import analyze_image_signing

    v = analyze_image_signing(
        [
            {"key": "tee-image-reference", "value": "us-docker.pkg.dev/p/r/img@sha256:abc"},
            {"key": "tee-signed-image-repos", "value": "us-docker.pkg.dev/p/r"},
        ],
        [{"role": "roles/artifactregistry.writer", "members": ["group:ci@corp"]}],
    )
    assert v["passed"] is True


def test_old_sev_snp_name_is_an_alias() -> None:
    from click.testing import CliRunner

    from untrust.cli import cli

    assert "sev-snp" not in supported_platforms()
    assert checks_for("sev-snp") == checks_for("gcp-cspace")
    assert demo_for("sev-snp")[0].platform == "gcp-cspace"

    result = CliRunner().invoke(cli, ["list-checks", "--platform", "sev-snp"])
    assert result.exit_code == 0
    assert "Platform: gcp-cspace" in result.output
    assert "now --platform gcp-cspace" in result.output
