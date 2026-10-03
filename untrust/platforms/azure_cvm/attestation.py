"""AZ-DBG-01: the VM's own MAA token says it is not debuggable and Azure-compliant.

Run inside the CVM, the Azure guest attestation client returns an MAA token
(JWT) describing that VM. Its ``x-ms-isolation-tee`` claims carry the hardware
verdict: the attestation type, ``x-ms-compliance-status`` and, on SEV-SNP,
``x-ms-sevsnpvm-is-debuggable``. The token's RS256 signature is checked against
the issuer's published keys (``<iss>/certs``) when they can be fetched; if not,
the verdict is reported as resting on unverified claims.
"""
from __future__ import annotations

import base64
import binascii
import json
import urllib.request
from pathlib import Path
from typing import Any

from ...checks.base import Assurance, Check, Finding, Severity, Status, Target
from .key_release import MAA_HOST

MAX_TOKEN_BYTES = 64 * 1024


def _segment(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def parse_token(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    token = token.strip()
    if len(token) > MAX_TOKEN_BYTES or token.count(".") != 2:
        raise ValueError("not a JWT")
    head, body, sig = token.split(".")
    try:
        header, claims = json.loads(_segment(head)), json.loads(_segment(body))
        signature = _segment(sig)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("JWT segments are not base64url JSON") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("JWT header and claims must be objects")
    return header, claims, f"{head}.{body}".encode(), signature


def analyze_claims(claims: dict[str, Any]) -> dict[str, Any]:
    tee = claims.get("x-ms-isolation-tee") or {}
    if not isinstance(tee, dict):
        tee = {}
    kind = tee.get("x-ms-attestation-type")
    compliance = tee.get("x-ms-compliance-status")
    debuggable = tee.get("x-ms-sevsnpvm-is-debuggable")
    issues = []
    if kind not in ("sevsnpvm", "tdxvm"):
        issues.append(f"attestation type is {kind or 'missing'}, not a confidential VM")
    if compliance != "azure-compliant-cvm":
        issues.append(f"compliance status is {compliance or 'missing'}")
    if debuggable is True:
        issues.append("the SEV-SNP guest is debuggable")
    if claims.get("secureboot") is False:
        issues.append("Secure Boot is off")
    return {"attestation_type": kind, "compliance_status": compliance,
            "debuggable": debuggable, "secure_boot": claims.get("secureboot"),
            "issuer": claims.get("iss"), "vm_id": claims.get("x-ms-azurevm-vmid"),
            "issues": issues, "passed": not issues}


def verify_signature(header: dict[str, Any], signed: bytes, signature: bytes,
                     issuer: str) -> str:
    """Return 'verified', or why the signature could not be confirmed."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    host = issuer.split("//", 1)[-1].split("/", 1)[0]
    if header.get("alg") != "RS256" or not MAA_HOST.match(host):
        return "issuer is not an MAA endpoint or the token is not RS256"
    try:
        with urllib.request.urlopen(f"https://{host}/certs", timeout=15) as response:
            keys = json.loads(response.read()).get("keys", [])
    except Exception:
        return "issuer keys could not be fetched"
    for jwk in keys:
        if jwk.get("kid") != header.get("kid") or not jwk.get("x5c"):
            continue
        public = x509.load_der_x509_certificate(base64.b64decode(jwk["x5c"][0])).public_key()
        if not isinstance(public, rsa.RSAPublicKey):
            return "issuer key is not RSA"
        try:
            public.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
            return "verified"
        except InvalidSignature:
            return "signature does not match the issuer's key"
    return "token key id is not among the issuer's keys"


class AzureCvmDebugCheck(Check):
    check_id = "AZ-DBG-01"
    title = "MAA attests the VM as non-debuggable and Azure-compliant"
    severity = Severity.CRITICAL
    assurance = Assurance.REPORT_DERIVED

    def run(self, target: Target) -> Finding:
        if not target.azure_attestation_token:
            return Finding(self.check_id, self.title, Status.SKIP, self.severity,
                           "Need --azure-attestation-token (an MAA token captured in the VM); "
                           "skipping check.")
        try:
            header, claims, signed, signature = parse_token(
                Path(target.azure_attestation_token).read_text())
        except (OSError, ValueError) as e:
            return Finding(self.check_id, self.title, Status.ERROR, self.severity,
                           f"Could not read the MAA token: {e}")
        verdict = analyze_claims(claims)
        verdict["signature"] = verify_signature(header, signed, signature,
                                                str(claims.get("iss", "")))
        note = (None if verdict["signature"] == "verified"
                else f"Token signature not verified ({verdict['signature']}).")
        if verdict["passed"]:
            return Finding(self.check_id, self.title, Status.PASS, self.severity,
                           f"MAA attests a {verdict['attestation_type']} VM that is "
                           "azure-compliant-cvm and not debuggable.",
                           evidence=verdict, assurance_note=note)
        return Finding(self.check_id, self.title, Status.FAIL, self.severity,
                       "; ".join(verdict["issues"]) + ".", evidence=verdict,
                       remediation="Redeploy from an Azure confidential VM image with a "
                                   "non-debug guest policy; investigate why MAA flags it.",
                       assurance_note=note)
