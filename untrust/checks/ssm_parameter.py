"""SSM-01: SSM Parameter Store state security.

Some TEE deployments pass bootstrap config and secrets to the enclave
through SSM Parameter Store. The two things that matter for a parameter
the enclave trusts at boot:

* It must be a ``SecureString`` — a plain ``String``/``StringList`` is
  stored and returned in cleartext, so any principal with
  ``ssm:GetParameter`` reads it directly.
* A ``SecureString`` must be encrypted under a customer-managed KMS CMK,
  not the AWS-managed ``alias/aws/ssm`` default key, so the key policy can
  gate decrypt on the enclave's attestation (KMS-01).

``target.parameter_path`` is treated as a name prefix, so a whole
namespace (e.g. ``/enclave/``) can be audited in one pass.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ._backend_util import classify_kms_key
from .base import Check, Finding, Severity, Status, Target


class SsmParameterCheck(Check):
    check_id = "SSM-01"
    title = "SSM Parameter Store state security"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.parameter_path:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No parameter path specified; skipping check.",
            )

        ssm = boto3.client("ssm", region_name=target.region)

        try:
            paginator = ssm.get_paginator("describe_parameters")
            params: list[dict] = []
            for page in paginator.paginate(
                ParameterFilters=[
                    {
                        "Key": "Name",
                        "Option": "BeginsWith",
                        "Values": [target.parameter_path],
                    }
                ]
            ):
                params.extend(page.get("Parameters", []))
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not describe parameters: {e}",
            )

        if not params:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary=(
                    f"No parameters found under '{target.parameter_path}'."
                ),
            )

        plaintext: list[str] = []
        non_cmk: list[str] = []
        unverified: list[str] = []
        key_cache: dict[str, str] = {}
        for p in params:
            name = p.get("Name", "")
            if p.get("Type") != "SecureString":
                plaintext.append(f"{name} ({p.get('Type')})")
                continue
            key_id = p.get("KeyId", "")
            if key_id not in key_cache:
                key_cache[key_id] = classify_kms_key(key_id, target.region)
            verdict = key_cache[key_id]
            if verdict == "customer":
                continue
            if verdict == "unknown":
                unverified.append(name)
            else:
                non_cmk.append(name)

        evidence: dict[str, object] = {
            "parameters_checked": len(params),
            "plaintext_parameters": plaintext,
            "non_cmk_parameters": non_cmk,
            "unverified_parameters": unverified,
        }

        issues: list[str] = []
        if plaintext:
            issues.append(
                f"{len(plaintext)} parameter(s) are plaintext String/"
                f"StringList, not SecureString"
            )
        if non_cmk:
            issues.append(
                f"{len(non_cmk)} SecureString parameter(s) use an "
                f"AWS-managed/default key, not a customer-managed CMK"
            )
        if unverified:
            issues.append(
                f"could not verify the CMK for {len(unverified)} "
                f"SecureString parameter(s) (grant kms:DescribeKey to the "
                f"audit role)"
            )

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "SSM Parameter Store issues: " + "; ".join(issues) + "."
                ),
                remediation=(
                    "Store enclave bootstrap secrets as SecureString "
                    "parameters encrypted under a customer-managed KMS CMK, "
                    "and gate that key on enclave attestation (KMS-01). Scope "
                    "ssm:GetParameter to the enclave role."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                f"All {len(params)} parameter(s) are SecureString under a "
                f"customer-managed CMK."
            ),
            evidence=evidence,
        )
