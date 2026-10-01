"""GPUCC-CUDA-01: a CUDA kernel ran after successful GPU attestation.

Configuration can claim that a workload attests before use, but this check reads
the runtime receipts that establish the actual ordering.  The CUDA challenge
receipt must point to the exact nvattest receipt captured beside the normalized
report, and that nvattest receipt must point to its retained raw verifier output.

This is still report-derived evidence: a privileged guest can rewrite local
files.  It proves the workload's control flow and artifact integrity, not that an
untrusted hypervisor cannot forge guest storage.  The runner therefore also
requires GPUCC-SIGVERIFY-01 before treating this PASS as trusted.
"""

from __future__ import annotations

import hashlib
import string
from pathlib import Path
from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file
from .signature_verify import (
    analyze_nvattest_result,
    nvattest_claims_bind,
    nvattest_command_nonce,
)


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in string.hexdigits for char in text)


def _is_uint32(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**32


def analyze_cuda_execution(
    report: dict[str, Any],
    *,
    attestation_receipt_digest_matches: bool | None = None,
    raw_result_digest_matches: bool | None = None,
    raw_result_valid: bool | None = None,
    receipt_matches_raw: bool | None = None,
    command_nonce_matches: bool | None = None,
    claims_bind_report: bool | None = None,
) -> dict[str, Any]:
    """Assess CUDA execution and its ordering after a retained nvattest result."""
    cuda = report.get("cuda_execution") or {}
    attestation = report.get("runtime_attestation") or {}
    gpu = report.get("gpu") or {}

    challenge = cuda.get("challenge")
    response = cuda.get("response")
    cuda_gpu_uuid = str(cuda.get("gpu_uuid") or "")
    report_gpu_uuid = str(gpu.get("uuid") or "")
    attestation_digest = cuda.get("attestation_receipt_sha256")
    raw_digest = attestation.get("raw_result_sha256")

    challenge_valid = _is_uint32(challenge)
    response_valid = _is_uint32(response)
    response_matches = challenge_valid and response_valid and challenge == response
    gpu_matches = bool(cuda_gpu_uuid and report_gpu_uuid and cuda_gpu_uuid == report_gpu_uuid)
    attestation_valid = (
        attestation.get("schema") == "untrust.gpucc.verification-receipt/v1"
        and attestation.get("tool") == "nvattest"
        and attestation.get("verified") is True
        and attestation.get("result_code") == 0
        and isinstance(attestation.get("claim_count"), int)
        and not isinstance(attestation.get("claim_count"), bool)
        and attestation.get("claim_count", 0) > 0
        and attestation.get("detached_eat_present") is True
        and _is_sha256(attestation.get("nonce"))
        and _is_sha256(raw_digest)
    )

    issues: list[str] = []
    if cuda.get("schema") != "untrust.gpucc.cuda-execution-receipt/v1":
        issues.append("CUDA execution receipt is absent or has an unsupported schema")
    if cuda.get("executed") is not True or not response_matches:
        issues.append("CUDA challenge did not execute successfully or its response mismatched")
    if not gpu_matches:
        issues.append("CUDA receipt GPU UUID does not match the attested GPU UUID")
    if not _is_sha256(cuda.get("ptx_sha256")):
        issues.append("CUDA receipt does not identify the executed PTX by SHA-256")
    if not _is_sha256(attestation_digest):
        issues.append("CUDA execution is not linked to an attestation receipt")
    if not attestation_valid:
        issues.append("linked runtime attestation receipt is not a successful nvattest result")
    if attestation_receipt_digest_matches is not True:
        issues.append("linked attestation receipt is missing or its SHA-256 does not match")
    if raw_result_digest_matches is not True:
        issues.append("runtime nvattest raw result is missing or its SHA-256 does not match")
    if raw_result_valid is not True:
        issues.append("runtime nvattest raw result is not a successful verifier result")
    if receipt_matches_raw is not True:
        issues.append("runtime attestation receipt does not match the retained raw result")
    if command_nonce_matches is not True:
        issues.append("runtime verifier command nonce does not match the attestation receipt")
    if claims_bind_report is not True:
        issues.append("runtime nvattest claims do not match the report's GPU and receipt nonce")

    return {
        "executed": cuda.get("executed") is True,
        "challenge_response_matches": response_matches,
        "cuda_gpu_uuid": cuda_gpu_uuid or None,
        "attested_gpu_uuid": report_gpu_uuid or None,
        "gpu_uuid_matches": gpu_matches,
        "ptx_sha256_present": _is_sha256(cuda.get("ptx_sha256")),
        "attestation_receipt_sha256": attestation_digest,
        "attestation_receipt_digest_matches": attestation_receipt_digest_matches,
        "raw_result_digest_matches": raw_result_digest_matches,
        "raw_result_valid": raw_result_valid,
        "receipt_matches_raw": receipt_matches_raw,
        "command_nonce_matches": command_nonce_matches,
        "claims_bind_report": claims_bind_report,
        "runtime_attestation_valid": attestation_valid,
        "issues": issues,
        "passed": not issues,
    }


class GpuCudaExecutionCheck(Check):
    check_id = "GPUCC-CUDA-01"
    title = "A CUDA kernel executes only after successful GPU attestation"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_attestation_report:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-attestation-report specified; skipping check.",
            )
        try:
            report_path = Path(target.gpu_attestation_report)
            report = load_json_file(str(report_path))
        except Exception as error:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/validate CUDA runtime evidence: {error}",
            )

        runtime_receipt_path = report_path.with_name("runtime-attestation.json")
        runtime_raw_path = report_path.with_name("runtime-verification.json")
        runtime_receipt: dict[str, Any] = {}
        if runtime_receipt_path.is_file():
            try:
                runtime_receipt = load_json_file(str(runtime_receipt_path))
            except Exception:
                runtime_receipt = {}
        report["runtime_attestation"] = runtime_receipt

        cuda_digest = str(
            (report.get("cuda_execution") or {}).get(
                "attestation_receipt_sha256", ""
            )
        )
        raw_digest = str(runtime_receipt.get("raw_result_sha256", ""))
        receipt_matches = (
            runtime_receipt_path.is_file()
            and hashlib.sha256(runtime_receipt_path.read_bytes()).hexdigest()
            == cuda_digest
        )
        raw_matches = (
            runtime_raw_path.is_file()
            and hashlib.sha256(runtime_raw_path.read_bytes()).hexdigest()
            == raw_digest
        )
        raw_result: dict[str, Any] = {}
        if runtime_raw_path.is_file():
            try:
                raw_result = load_json_file(str(runtime_raw_path))
            except Exception:
                raw_result = {}
        raw_analysis = analyze_nvattest_result(raw_result)
        receipt_matches_raw = (
            runtime_receipt.get("result_code") == raw_analysis["result_code"]
            and runtime_receipt.get("claim_count") == raw_analysis["claim_count"]
            and runtime_receipt.get("detached_eat_present")
            == raw_analysis["detached_eat_present"]
        )
        command_nonce = nvattest_command_nonce(raw_result)
        command_nonce_matches = (
            command_nonce is not None and command_nonce == runtime_receipt.get("nonce")
        )

        result = analyze_cuda_execution(
            report,
            attestation_receipt_digest_matches=receipt_matches,
            raw_result_digest_matches=raw_matches,
            raw_result_valid=raw_analysis["passed"],
            receipt_matches_raw=receipt_matches_raw,
            command_nonce_matches=command_nonce_matches,
            claims_bind_report=nvattest_claims_bind(
                raw_result, nonce=runtime_receipt.get("nonce"), report=report
            )["passed"],
        )
        if not result["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary="CUDA execution is not bound to successful GPU attestation: "
                + "; ".join(result["issues"])
                + ".",
                remediation=(
                    "Fail closed on nvattest, retain its raw result and receipt, then "
                    "launch CUDA only after verification succeeds. Bind the CUDA receipt "
                    "to the exact attestation receipt and require the GPU UUID to match."
                ),
                evidence=result,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "A CUDA challenge ran on the attested GPU after a successful nvattest "
                "result, with the retained evidence chain intact."
            ),
            evidence=result,
        )
