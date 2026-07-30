"""KMS-01: kms:RecipientAttestation conditions.

Verifies that *every* Allow statement in the KMS key policy that grants
kms:Decrypt (or kms:* / *) enforces attestation via a Condition block
on kms:RecipientAttestation:* keys — AND that the condition is not
trivially satisfiable.

Without these conditions, anyone with the IAM role can call Decrypt
without running inside an attested enclave — the attestation guarantee
is bypassed entirely at the KMS layer.

The check performs semantic policy evaluation, not string matching.
Beyond confirming a condition exists, it catches two subtle bypasses
that a naive "does RecipientAttestation appear?" check would miss:

1. Trivial values — an attestation condition whose expected value is
   all-zeros (the documented debug-mode workaround) or empty. In debug
   mode the Nitro hypervisor sets all PCRs to zero, so an all-zeros
   condition is satisfied by ANY debug enclave. If that policy reaches
   production, attestation is a no-op.

2. Identity-only binding — a condition that pins only PCR3 (parent IAM
   role) or PCR4 (instance ID). Those PCRs measure *who* launched the
   enclave, not *what code* runs inside it. Binding to identity without
   binding to a code measurement (PCR0/PCR1/PCR2/PCR8 or ImageSha384)
   does not prove trusted code is executing.
"""
from __future__ import annotations

import json

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target

ATTESTATION_KEY_PREFIX = "kms:RecipientAttestation:"

DECRYPT_ACTIONS = frozenset({"kms:decrypt", "kms:*", "*"})

VALID_CONDITION_OPERATORS = frozenset({
    "StringEquals",
    "StringEqualsIgnoreCase",
    "StringLike",
    "ForAnyValue:StringEquals",
    "ForAllValues:StringEquals",
    "ForAnyValue:StringEqualsIgnoreCase",
    "ForAllValues:StringEqualsIgnoreCase",
})

# PCRs (and the ImageSha384 alias for PCR0) that measure the enclave's
# code, kernel, application, or signing certificate.
CODE_MEASUREMENT_SUFFIXES = frozenset({
    "pcr0", "pcr1", "pcr2", "pcr8", "imagesha384",
})

# PCRs that measure launch identity rather than code.
IDENTITY_SUFFIXES = frozenset({"pcr3", "pcr4"})


def _grants_decrypt(statement: dict) -> bool:
    """Return True if this statement is an Allow that covers kms:Decrypt."""
    if statement.get("Effect") != "Allow":
        return False
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    return any(a.lower() in DECRYPT_ACTIONS for a in actions)


def _attestation_conditions(statement: dict) -> dict[str, list[str]]:
    """Map each attestation condition key to its expected value(s)."""
    found: dict[str, list[str]] = {}
    condition = statement.get("Condition", {})
    for operator, cond_block in condition.items():
        if operator not in VALID_CONDITION_OPERATORS:
            continue
        if not isinstance(cond_block, dict):
            continue
        for key, val in cond_block.items():
            if not key.startswith(ATTESTATION_KEY_PREFIX):
                continue
            if isinstance(val, str):
                values = [val]
            elif isinstance(val, list):
                values = [str(v) for v in val]
            else:
                values = [str(val)]
            found.setdefault(key, []).extend(values)
    return found


def _suffix(key: str) -> str:
    return key.split(":")[-1].lower()


def _is_trivial_value(value: str) -> bool:
    """True if the expected attestation value is empty or all zeros."""
    v = value.strip().lower()
    return v == "" or set(v) == {"0"}


def _classify(statement: dict) -> str:
    """Classify a single Allow+Decrypt statement's attestation posture.

    Returns one of: "protected", "none", "trivial", "identity_only".
    """
    conditions = _attestation_conditions(statement)
    if not conditions:
        return "none"

    # Keys that carry at least one non-trivial (real) expected value.
    effective_keys = [
        key for key, values in conditions.items()
        if any(not _is_trivial_value(v) for v in values)
    ]
    if not effective_keys:
        return "trivial"

    effective_suffixes = {_suffix(k) for k in effective_keys}
    if effective_suffixes & CODE_MEASUREMENT_SUFFIXES:
        return "protected"
    if effective_suffixes <= IDENTITY_SUFFIXES:
        return "identity_only"
    # A custom / locked PCR with a real value — treat as an explicit,
    # intentional binding rather than flagging it.
    return "protected"


class KmsAttestationCheck(Check):
    check_id = "KMS-01"
    title = "KMS key policy enforces RecipientAttestation"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.kms_key_id:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No KMS key ID specified; skipping check.",
            )

        kms = boto3.client("kms", region_name=target.region)

        # get_key_policy does not accept aliases; resolve to a canonical key
        # id first. describe_key accepts a key id, ARN, alias name, or alias
        # ARN, so this makes KMS-01 work regardless of how the key is named.
        try:
            key_id = kms.describe_key(KeyId=target.kms_key_id)[
                "KeyMetadata"
            ]["KeyId"]
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not resolve KMS key: {e}",
            )

        try:
            response = kms.get_key_policy(KeyId=key_id, PolicyName="default")
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not retrieve key policy: {e}",
            )

        policy_text = response.get("Policy", "")
        try:
            policy = json.loads(policy_text)
        except json.JSONDecodeError:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary="Key policy is not valid JSON.",
            )

        statements = policy.get("Statement", [])
        decrypt_stmts = [s for s in statements if _grants_decrypt(s)]

        if not decrypt_stmts:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.PASS,
                severity=self.severity,
                summary="No Allow statements grant kms:Decrypt in the key policy.",
                evidence={"total_statements": len(statements)},
            )

        buckets: dict[str, list[int]] = {
            "none": [],
            "trivial": [],
            "identity_only": [],
        }
        protected_keys: list[str] = []

        for idx, stmt in enumerate(decrypt_stmts):
            verdict = _classify(stmt)
            if verdict == "protected":
                protected_keys.extend(_attestation_conditions(stmt).keys())
            else:
                buckets[verdict].append(idx)

        weak_total = sum(len(v) for v in buckets.values())

        if weak_total:
            reasons: list[str] = []
            if buckets["none"]:
                reasons.append(
                    f"{len(buckets['none'])} lack any RecipientAttestation "
                    f"condition"
                )
            if buckets["trivial"]:
                reasons.append(
                    f"{len(buckets['trivial'])} use trivially satisfiable "
                    f"(all-zeros/empty) attestation values — a debug enclave "
                    f"would satisfy them"
                )
            if buckets["identity_only"]:
                reasons.append(
                    f"{len(buckets['identity_only'])} bind only to identity "
                    f"PCRs (PCR3/PCR4), not to a code measurement "
                    f"(PCR0/1/2/8 or ImageSha384)"
                )
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{weak_total} of {len(decrypt_stmts)} Allow+Decrypt "
                    f"statement(s) do not enforce meaningful attestation: "
                    f"{'; '.join(reasons)}."
                ),
                remediation=(
                    "Bind every Allow+Decrypt statement to a real code "
                    "measurement: StringEqualsIgnoreCase on "
                    "kms:RecipientAttestation:ImageSha384 (PCR0) or PCR8 with "
                    "the expected non-zero enclave/signing hash. Never leave "
                    "all-zeros debug values in a production policy, and do not "
                    "rely on PCR3/PCR4 alone — they identify the launcher, "
                    "not the code."
                ),
                evidence={
                    "total_decrypt_statements": len(decrypt_stmts),
                    "no_condition": len(buckets["none"]),
                    "trivial_value": len(buckets["trivial"]),
                    "identity_only": len(buckets["identity_only"]),
                    "protected_keys": sorted(set(protected_keys)),
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                f"All {len(decrypt_stmts)} Allow+Decrypt statement(s) enforce "
                f"attestation on a code measurement: "
                f"{sorted(set(protected_keys))}"
            ),
            evidence={"conditions_found": sorted(set(protected_keys))},
        )
