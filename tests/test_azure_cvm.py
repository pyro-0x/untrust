"""Tests for the azure-cvm platform (confidential VM config, SKR policy, MAA)."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from untrust.checks.base import Status, Target
from untrust.cli import cli
from untrust.platforms import checks_for, demo_for, supported_platforms
from untrust.platforms.azure_cvm import attestation, key_release, vm_config
from untrust.runner import run_checks


def vm(size: str = "Standard_DC4as_v5", security: str = "ConfidentialVM", secure_boot=True,
       vtpm=True, encryption: str | None = "DiskWithVMGuestState") -> dict[str, Any]:
    disk: dict[str, Any] = {}
    if encryption:
        disk["securityProfile"] = {"securityEncryptionType": encryption}
    return {"properties": {
        "hardwareProfile": {"vmSize": size},
        "securityProfile": {"securityType": security, "uefiSettings": {
            "secureBootEnabled": secure_boot, "vTpmEnabled": vtpm}},
        "storageProfile": {"osDisk": {"managedDisk": disk}}}}


def key(policy: Any, exportable: bool = True, immutable: bool = True) -> dict[str, Any]:
    release = None if policy is None else {
        "data": base64.urlsafe_b64encode(json.dumps(policy).encode()).decode().rstrip("="),
        "immutable": immutable}
    return {"attributes": {"exportable": exportable}, "release_policy": release}


GOOD_BRANCH = {"authority": "https://sharedeus2.eus2.attest.azure.net", "allOf": [
    {"claim": "x-ms-isolation-tee.x-ms-attestation-type", "equals": "sevsnpvm"},
    {"claim": "x-ms-isolation-tee.x-ms-compliance-status", "equals": "azure-compliant-cvm"}]}


# --- VM -------------------------------------------------------------------------

@pytest.mark.parametrize("size,tee", [("Standard_DC4as_v5", "AMD SEV-SNP"),
                                      ("Standard_EC16ads_v5", "AMD SEV-SNP"),
                                      ("Standard_DC8es_v5", "Intel TDX"),
                                      ("Standard_D4s_v5", None)])
def test_tee_of_size(size: str, tee: str | None) -> None:
    assert vm_config.tee_of_size(size) == tee


def test_sku_requires_confidential_type_and_size() -> None:
    assert vm_config.analyze_sku(vm())["passed"]
    assert not vm_config.analyze_sku(vm(security="TrustedLaunch"))["passed"]
    assert not vm_config.analyze_sku(vm(size="Standard_D4s_v5"))["passed"]


def test_boot_and_disk() -> None:
    assert vm_config.analyze_boot(vm())["passed"]
    assert vm_config.analyze_boot(vm(secure_boot=False))["issues"] == ["Secure Boot is off"]
    assert vm_config.analyze_disk(vm())["passed"]
    assert not vm_config.analyze_disk(vm(encryption="VMGuestStateOnly"))["passed"]
    assert not vm_config.analyze_disk(vm(encryption=None))["passed"]


# --- Secure Key Release ---------------------------------------------------------

def test_release_policy_bound_to_compliant_cvm_passes() -> None:
    verdict = key_release.analyze_release_policy(key({"version": "1.0.0", "anyOf": [GOOD_BRANCH]}))
    assert verdict["passed"] and verdict["immutable"]


@pytest.mark.parametrize("policy,needle", [
    (None, "no release policy"),
    ({"version": "1.0.0", "anyOf": []}, "no anyOf"),
    ({"anyOf": [{**GOOD_BRANCH, "allOf": GOOD_BRANCH["allOf"][:1]}]}, "azure-compliant-cvm"),
    ({"anyOf": [{**GOOD_BRANCH, "authority": "https://evil.example.com"}]}, "not an MAA"),
    ({"anyOf": [GOOD_BRANCH, {"authority": GOOD_BRANCH["authority"], "allOf": [
        {"claim": "x-ms-attestation-type", "equals": "sgx"}]}]}, "branch 1"),
    # A compliance claim hidden in a nested anyOf can be bypassed by its sibling.
    ({"anyOf": [{"authority": GOOD_BRANCH["authority"], "allOf": [
        GOOD_BRANCH["allOf"][0],
        {"anyOf": [GOOD_BRANCH["allOf"][1], {"claim": "x", "equals": "y"}]}]}]},
     "azure-compliant-cvm"),
])
def test_weak_release_policies_fail(policy: Any, needle: str) -> None:
    verdict = key_release.analyze_release_policy(key(policy))
    assert not verdict["passed"]
    assert any(needle in issue for issue in verdict["issues"]), verdict["issues"]


def test_debug_claim_pinned_false_counts_as_compliance() -> None:
    branch = {"authority": GOOD_BRANCH["authority"], "allOf": [
        GOOD_BRANCH["allOf"][0],
        {"claim": "x-ms-isolation-tee.x-ms-sevsnpvm-is-debuggable", "equals": False}]}
    assert key_release.analyze_release_policy(key({"anyOf": [branch]}))["passed"]


def test_attestation_provider_trust_models() -> None:
    shared = key_release.analyze_attestation_provider("sharedeus2.eus2.attest.azure.net", None)
    assert shared["passed"] and shared["kind"] == "shared"
    host = "corp.eus2.attest.azure.net"
    isolated = {"properties": {"trustModel": "Isolated", "status": "Ready"}}
    assert key_release.analyze_attestation_provider(host, isolated)["passed"]
    aad = key_release.analyze_attestation_provider(host, {"properties": {"trustModel": "AAD"}})
    assert not aad["passed"] and "AAD" in aad["issues"][0]
    assert not key_release.analyze_attestation_provider(host, None)["passed"]


# --- MAA token ------------------------------------------------------------------

def test_claims() -> None:
    good = {"secureboot": True, "x-ms-isolation-tee": {
        "x-ms-attestation-type": "sevsnpvm", "x-ms-compliance-status": "azure-compliant-cvm",
        "x-ms-sevsnpvm-is-debuggable": False}}
    assert attestation.analyze_claims(good)["passed"]
    debug = json.loads(json.dumps(good))
    debug["x-ms-isolation-tee"]["x-ms-sevsnpvm-is-debuggable"] = True
    assert "debuggable" in attestation.analyze_claims(debug)["issues"][0]
    assert not attestation.analyze_claims({"x-ms-isolation-tee": "nope"})["passed"]


def _signed_token(claims: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    key_ = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "maa test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key_.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .sign(key_, hashes.SHA256()))

    def enc(v: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip("=")

    signing = f'{enc({"alg": "RS256", "kid": "k1"})}.{enc(claims)}'
    sig = key_.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    token = f"{signing}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"
    jwks = {"keys": [{"kid": "k1", "x5c": [base64.b64encode(
        cert.public_bytes(serialization.Encoding.DER)).decode()]}]}
    return token, jwks


class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def test_debug_check_verifies_the_token_signature(tmp_path: Any,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    claims = {"iss": "https://sharedeus2.eus2.attest.azure.net", "secureboot": True,
              "x-ms-isolation-tee": {"x-ms-attestation-type": "sevsnpvm",
                                     "x-ms-compliance-status": "azure-compliant-cvm",
                                     "x-ms-sevsnpvm-is-debuggable": False}}
    token, jwks = _signed_token(claims)
    path = tmp_path / "maa.jwt"
    path.write_text(token)
    seen: list[str] = []

    def fake_urlopen(url: str, timeout: int = 0) -> _Response:
        seen.append(url)
        return _Response(json.dumps(jwks).encode())

    monkeypatch.setattr(attestation.urllib.request, "urlopen", fake_urlopen)
    finding = attestation.AzureCvmDebugCheck().run(Target(platform="azure-cvm",
                                                          azure_attestation_token=str(path)))
    assert finding.status == Status.PASS and finding.assurance_note is None
    assert seen == ["https://sharedeus2.eus2.attest.azure.net/certs"]
    tampered = token.rsplit(".", 2)
    forged = ".".join([tampered[0], base64.urlsafe_b64encode(json.dumps(
        {**claims, "secureboot": True, "extra": 1}).encode()).decode().rstrip("="), tampered[2]])
    path.write_text(forged)
    finding = attestation.AzureCvmDebugCheck().run(Target(platform="azure-cvm",
                                                          azure_attestation_token=str(path)))
    assert finding.assurance_note and "does not match" in finding.assurance_note


# --- platform wiring ------------------------------------------------------------

def test_platform_is_registered_and_skips_without_targets() -> None:
    assert "azure-cvm" in supported_platforms()
    findings = run_checks(Target(platform="azure-cvm"), checks_for("azure-cvm"))
    assert [f.check_id for f in findings] == ["AZ-SKU-01", "AZ-BOOT-01", "AZ-DISK-01",
                                              "AZ-SKR-01", "AZ-MAA-01", "AZ-DBG-01"]
    assert {f.status for f in findings} == {Status.SKIP}


def test_live_checks_use_fetched_resources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vm_config, "_fetch_vm", lambda t: vm(secure_boot=False))
    monkeypatch.setattr(key_release, "_fetch_key",
                        lambda t: key({"anyOf": [{**GOOD_BRANCH, "authority":
                                                  "https://corp.eus2.attest.azure.net"}]}))
    monkeypatch.setattr(key_release, "_fetch_provider", lambda t: {"properties": {
        "attestUri": "https://corp.eus2.attest.azure.net", "trustModel": "AAD"}})
    target = Target(platform="azure-cvm", azure_subscription="s", azure_resource_group="g",
                    azure_vm="cvm", azure_key_vault="kv", azure_key="k",
                    azure_attestation_provider="corp")
    status = {f.check_id: f.status for f in run_checks(target, checks_for("azure-cvm"))}
    assert status == {"AZ-SKU-01": Status.PASS, "AZ-BOOT-01": Status.FAIL,
                      "AZ-DISK-01": Status.PASS, "AZ-SKR-01": Status.PASS,
                      "AZ-MAA-01": Status.FAIL, "AZ-DBG-01": Status.SKIP}


def test_demo_and_cli() -> None:
    target, findings = demo_for("azure-cvm")
    assert target.platform == "azure-cvm" and len(findings) == 6
    result = CliRunner().invoke(cli, ["scan", "--platform", "azure-cvm", "--demo", "--json"])
    assert result.exit_code in (0, 1), result.output
    assert '"AZ-SKR-01"' in result.output
    missing = CliRunner().invoke(cli, ["scan", "--platform", "azure-cvm"])
    assert missing.exit_code == 1 and "--azure-vm" in missing.output
