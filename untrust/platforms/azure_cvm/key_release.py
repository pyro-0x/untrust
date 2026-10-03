"""AZ-SKR-01 and AZ-MAA-01: keys are released only to an attested confidential VM.

Azure Secure Key Release hands an exportable Key Vault / Managed HSM key to a VM
that presents a Microsoft Azure Attestation (MAA) token satisfying the key's
release policy. The policy is the whole gate:

* AZ-SKR-01: every ``anyOf`` branch must name an MAA authority and require the
  confidential-VM attestation type (``sevsnpvm`` / ``tdxvm``) together with
  ``x-ms-compliance-status = azure-compliant-cvm`` (or the debug claim pinned to
  false). A branch that only checks the TEE type releases the key to a
  debuggable or non-compliant CVM; a non-MAA authority releases it to whatever
  that issuer signs.
* AZ-MAA-01: the authority's attestation policy must not be changeable by an
  ordinary Azure RBAC role. A custom provider in the ``AAD`` trust model lets any
  contributor rewrite what "attested" means; ``Isolated`` requires policy updates
  signed by the provider's policy-signing certificates. Shared regional providers
  run Microsoft's fixed default policy.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target

CVM_TYPES = {"sevsnpvm", "tdxvm"}
MAA_HOST = re.compile(r"^[a-z0-9-]+\.[a-z0-9]+\.attest\.azure\.net$")
SHARED_HOST = re.compile(r"^shared[a-z0-9]+\.[a-z0-9]+\.attest\.azure\.net$")


def decode_policy(release_policy: dict[str, Any] | None) -> dict[str, Any] | None:
    """Key Vault returns the policy as base64url JSON in ``release_policy.data``."""
    if not release_policy or not release_policy.get("data"):
        return None
    data = release_policy["data"]
    try:
        raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
        value = json.loads(raw)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("release policy is not base64url JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("release policy is not a JSON object")
    return value


def _conditions(node: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a branch's allOf/anyOf/claim tree into claim conditions that must hold.

    Only conditions under ``allOf`` (or a lone claim) are guaranteed; a claim inside
    a nested ``anyOf`` can be bypassed by its siblings, so it is not counted.
    """
    if "claim" in node:
        return [node]
    out: list[dict[str, Any]] = []
    for child in node.get("allOf", []) or []:
        if isinstance(child, dict):
            out.extend(_conditions(child))
    return out


def _requires(conditions: list[dict[str, Any]], claim_suffix: str, values: set[Any]) -> bool:
    return any(str(c.get("claim", "")).endswith(claim_suffix) and c.get("equals") in values
               for c in conditions)


def analyze_release_policy(key: dict[str, Any]) -> dict[str, Any]:
    attributes = key.get("attributes") or {}
    policy_meta = key.get("release_policy") or {}
    policy = decode_policy(policy_meta)
    issues: list[str] = []
    branches: list[dict[str, Any]] = []
    if policy is None:
        issues.append("key has no release policy, so it is not gated by attestation")
    else:
        anyof = policy.get("anyOf")
        if not isinstance(anyof, list) or not anyof:
            issues.append("release policy has no anyOf branches")
            anyof = []
        for index, branch in enumerate(anyof):
            if not isinstance(branch, dict):
                issues.append(f"branch {index} is not an object")
                continue
            authority = str(branch.get("authority", ""))
            host = urllib.parse.urlsplit(authority).hostname or ""
            conds = _conditions(branch)
            tee = _requires(conds, "x-ms-attestation-type", CVM_TYPES)
            compliant = (_requires(conds, "x-ms-compliance-status", {"azure-compliant-cvm"})
                         or _requires(conds, "is-debuggable", {False, "false"}))
            branch_issues = []
            if not MAA_HOST.match(host):
                branch_issues.append(f"authority {authority or '(none)'} is not an MAA endpoint")
            if not tee:
                branch_issues.append("does not require a confidential-VM attestation type")
            if not compliant:
                branch_issues.append("does not require azure-compliant-cvm (or debug off)")
            issues.extend(f"branch {index}: {i}" for i in branch_issues)
            branches.append({"authority": authority, "requires_cvm": tee,
                             "requires_compliance": compliant, "conditions": len(conds)})
    return {"exportable": attributes.get("exportable"),
            "immutable": bool(policy_meta.get("immutable")),
            "branches": branches, "issues": issues, "passed": not issues}


def authorities(key_verdict: dict[str, Any]) -> list[str]:
    return sorted({urllib.parse.urlsplit(b["authority"]).hostname or ""
                   for b in key_verdict.get("branches", []) if b.get("authority")})


def analyze_attestation_provider(host: str, provider: dict[str, Any] | None) -> dict[str, Any]:
    if SHARED_HOST.match(host):
        return {"authority": host, "kind": "shared", "trust_model": None, "issues": [],
                "passed": True}
    props = (provider or {}).get("properties") or {}
    trust = props.get("trustModel")
    issues = []
    if provider is None:
        issues.append(f"{host} is a custom provider; pass --azure-attestation-provider "
                      "so its trust model can be read")
    elif trust != "Isolated":
        issues.append(f"{host} uses the '{trust or 'AAD'}' trust model: anyone with RBAC "
                      "write on the provider can replace its attestation policy")
    if provider is not None and props.get("status") not in (None, "Ready"):
        issues.append(f"{host} status is {props.get('status')}")
    return {"authority": host, "kind": "custom", "trust_model": trust,
            "public_network_access": props.get("publicNetworkAccess"),
            "issues": issues, "passed": not issues}


def _key_ready(target: Target) -> bool:
    return bool(target.azure_key_vault and target.azure_key)


class AzureSecureKeyReleaseCheck(Check):
    check_id = "AZ-SKR-01"
    title = "Key release policy is bound to attested, compliant confidential VMs"
    severity = Severity.CRITICAL

    def run(self, target: Target) -> Finding:
        if not _key_ready(target):
            return Finding(self.check_id, self.title, Status.SKIP, self.severity,
                           "Need --azure-key-vault and --azure-key; skipping check.")
        try:
            verdict = analyze_release_policy(_fetch_key(target))
        except Exception as e:
            return Finding(self.check_id, self.title, Status.ERROR, self.severity,
                           f"Could not read the key's release policy: {e}")
        if verdict["passed"]:
            return Finding(self.check_id, self.title, Status.PASS, self.severity,
                           f"{target.azure_key}: every release branch requires an MAA-attested, "
                           "Azure-compliant confidential VM.", evidence=verdict)
        return Finding(self.check_id, self.title, Status.FAIL, self.severity,
                       f"{target.azure_key}: " + "; ".join(verdict["issues"]) + ".",
                       remediation=(
                           "Set a release policy whose every anyOf branch names an MAA authority "
                           "and requires x-ms-attestation-type (sevsnpvm/tdxvm) and "
                           "x-ms-compliance-status = azure-compliant-cvm; mark it immutable."),
                       evidence=verdict)


class AzureAttestationPolicyCheck(Check):
    check_id = "AZ-MAA-01"
    title = "Attestation policy cannot be rewritten through Azure RBAC"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not _key_ready(target):
            return Finding(self.check_id, self.title, Status.SKIP, self.severity,
                           "Need --azure-key-vault and --azure-key (the release policy names "
                           "the attestation authority); skipping check.")
        try:
            hosts = authorities(analyze_release_policy(_fetch_key(target)))
            provider = _fetch_provider(target) if target.azure_attestation_provider else None
        except Exception as e:
            return Finding(self.check_id, self.title, Status.ERROR, self.severity,
                           f"Could not read the attestation provider: {e}")
        if not hosts:
            return Finding(self.check_id, self.title, Status.SKIP, self.severity,
                           "The key's release policy names no attestation authority.")
        provider_host = urllib.parse.urlsplit(
            ((provider or {}).get("properties") or {}).get("attestUri", "")).hostname
        results = [analyze_attestation_provider(h, provider if h == provider_host else None)
                   for h in hosts]
        issues = [i for r in results for i in r["issues"]]
        evidence = {"providers": results}
        if issues:
            return Finding(self.check_id, self.title, Status.FAIL, self.severity,
                           "; ".join(issues) + ".", evidence=evidence,
                           remediation=("Use an attestation provider in the Isolated trust model "
                                        "(policy updates signed by your policy-signing "
                                        "certificates), or Microsoft's shared regional provider."))
        kinds = ", ".join(f"{r['authority']} ({r['kind']})" for r in results)
        return Finding(self.check_id, self.title, Status.PASS, self.severity,
                       f"Release is decided by {kinds}; its policy is not RBAC-editable.",
                       evidence=evidence)


def _fetch_key(target: Target) -> dict[str, Any]:  # pragma: no cover - live only
    from .arm import key

    assert target.azure_key_vault and target.azure_key
    return key(target.azure_key_vault, target.azure_key)


def _fetch_provider(target: Target) -> dict[str, Any]:  # pragma: no cover - live only
    from .arm import attestation_provider

    value = target.azure_attestation_provider or ""
    if value.startswith("/subscriptions/"):
        parts = value.strip("/").split("/")
        return attestation_provider(parts[1], parts[3], parts[-1])
    assert target.azure_subscription and target.azure_resource_group
    return attestation_provider(target.azure_subscription, target.azure_resource_group, value)
