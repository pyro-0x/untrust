"""GPUCC-SIGVERIFY-01: the attestation report signature is actually verified.

GPUCC-ATT-01 inspects the report's *claims*; this checks that the relying party
*cryptographically verifies the report signature* against the GPU's device key —
not merely reads the fields and trusts them. A verifier that parses claims without
checking the signature accepts a fully fabricated report. Together with
GPUCC-CERT-01 (the signer chains to NVIDIA's RoT) this closes the "attestation is
lying" surface at the crypto layer, not just the claims layer.

Input: the verifier policy's ``verify_signature`` flag.
"""

from __future__ import annotations

import hashlib
import string
from pathlib import Path
from typing import Any

from ...checks.base import Assurance, Check, Finding, Severity, Status, Target
from ._io import load_json_file


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in string.hexdigits for char in text)


def analyze_nvattest_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Validate the stable fields NVIDIA documents for JSON verifier output."""
    payload = raw.get("stdout_payload") if "stdout_payload" in raw else raw
    if not isinstance(payload, dict):
        payload = {}
    claims = payload.get("claims")
    claim_count = len(claims) if isinstance(claims, list) else 0
    detached_eat_present = bool(payload.get("detached_eat"))
    passed = (
        payload.get("result_code") == 0
        and claim_count > 0
        and detached_eat_present
    )
    return {
        "result_code": payload.get("result_code"),
        "claim_count": claim_count,
        "detached_eat_present": detached_eat_present,
        "passed": passed,
    }


def nvattest_command_nonce(raw: dict[str, Any]) -> str | None:
    """The ``--nonce`` value the retained nvattest command was invoked with."""
    command = raw.get("command") or []
    if isinstance(command, list) and "--nonce" in command:
        index = command.index("--nonce") + 1
        if index < len(command):
            return str(command[index])
    return None


def analyze_signature_verification(
    policy: dict[str, Any],
    report: dict[str, Any] | None = None,
    *,
    raw_result_digest_matches: bool | None = None,
    raw_result_valid: bool | None = None,
    receipt_matches_raw: bool | None = None,
    command_nonce_matches: bool | None = None,
) -> dict[str, Any]:
    """Assess declared verification and, when supplied, a live verifier receipt."""
    verify = bool(policy.get("verify_signature", False))
    issues: list[str] = []
    if not verify:
        issues.append(
            "verifier does not cryptographically verify the report signature "
            "(claims are trusted as-is — a fabricated report would be accepted)"
        )

    receipt = (report or {}).get("verification") or {}
    receipt_checked = report is not None
    receipt_valid = False
    if receipt_checked:
        nonce = str(receipt.get("nonce", ""))
        digest = str(receipt.get("raw_result_sha256", ""))
        claim_count = receipt.get("claim_count")
        signature_verified = bool(((report or {}).get("signature") or {}).get("verified"))
        receipt_valid = (
            receipt.get("tool") == "nvattest"
            and receipt.get("verified") is True
            and receipt.get("result_code") == 0
            and isinstance(claim_count, int)
            and not isinstance(claim_count, bool)
            and claim_count > 0
            and receipt.get("detached_eat_present") is True
            and _is_sha256(nonce)
            and _is_sha256(digest)
            and signature_verified
            and raw_result_digest_matches is True
            and raw_result_valid is True
            and receipt_matches_raw is True
            and command_nonce_matches is True
        )
        if not receipt_valid:
            issues.append(
                "captured evidence lacks a successful nvattest receipt bound to a fresh "
                "32-byte nonce and raw-result digest"
            )
    return {
        "verify_signature": verify,
        "receipt_checked": receipt_checked,
        "receipt_valid": receipt_valid,
        "verifier_tool": receipt.get("tool") or None,
        "result_code": receipt.get("result_code"),
        "raw_result_digest_matches": raw_result_digest_matches,
        "raw_result_valid": raw_result_valid,
        "receipt_matches_raw": receipt_matches_raw,
        "command_nonce_matches": command_nonce_matches,
        "issues": issues,
        "passed": not issues,
    }


class GpuSignatureVerifyCheck(Check):
    check_id = "GPUCC-SIGVERIFY-01"
    title = "The attestation report signature is cryptographically verified"
    severity = Severity.CRITICAL

    def run(self, target: Target) -> Finding:
        if not target.gpu_verifier_policy:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-verifier-policy specified; skipping check.",
            )
        try:
            policy = load_json_file(target.gpu_verifier_policy)
        except Exception as e:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse verifier policy: {e}",
            )
        report = None
        report_path_value = target.gpu_attestation_report
        if report_path_value:
            try:
                report = load_json_file(report_path_value)
            except Exception as e:
                return Finding(
                    check_id=self.check_id, title=self.title, status=Status.ERROR,
                    severity=self.severity,
                    summary=f"Could not read/parse attestation report: {e}",
                )
        digest_matches = None
        raw_result_valid = None
        receipt_matches_raw = None
        command_nonce_matches = None
        if report is not None and report_path_value is not None:
            expected_digest = str((report.get("verification") or {}).get(
                "raw_result_sha256", ""
            ))
            raw_path = Path(report_path_value).with_name("verification.json")
            digest_matches = (
                raw_path.is_file()
                and hashlib.sha256(raw_path.read_bytes()).hexdigest() == expected_digest
            )
            if raw_path.is_file():
                try:
                    raw_result = load_json_file(str(raw_path))
                except Exception:
                    raw_result = {}
                raw_analysis = analyze_nvattest_result(raw_result)
                raw_result_valid = raw_analysis["passed"]
                receipt = report.get("verification") or {}
                receipt_matches_raw = (
                    receipt.get("result_code") == raw_analysis["result_code"]
                    and receipt.get("claim_count") == raw_analysis["claim_count"]
                    and receipt.get("detached_eat_present")
                    == raw_analysis["detached_eat_present"]
                )
                # Bind the receipt to the invocation that produced the raw result,
                # so an old passing nvattest output can't be replayed under a new nonce.
                command_nonce = nvattest_command_nonce(raw_result)
                command_nonce_matches = (
                    command_nonce is not None and command_nonce == receipt.get("nonce")
                )
        v = analyze_signature_verification(
            policy,
            report,
            raw_result_digest_matches=digest_matches,
            raw_result_valid=raw_result_valid,
            receipt_matches_raw=receipt_matches_raw,
            command_nonce_matches=command_nonce_matches,
        )
        tier = Assurance.REPORT_DERIVED if v["receipt_valid"] else None
        if not v["passed"]:
            return Finding(
                check_id=self.check_id, title=self.title, status=Status.FAIL,
                severity=self.severity,
                summary="Report signature is not verified: " + "; ".join(v["issues"]) + ".",
                remediation=(
                    "Cryptographically verify the attestation report signature against "
                    "the GPU device key (and chain it to the NVIDIA RoT) before trusting "
                    "any claim in it — never parse-and-trust."
                ),
                evidence=v,
                assurance=tier,
            )
        return Finding(
            check_id=self.check_id, title=self.title, status=Status.PASS,
            severity=self.severity,
            summary="The verifier cryptographically verifies the report signature.",
            evidence=v,
            assurance=tier,
        )
