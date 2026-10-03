"""CSPACE-WIF-02: every provider in the workload identity pool is attested.

CSPACE-KEYBIND-01 audits the *one* provider you point it at. But a pool can hold
several providers, and they all federate to the same resources. A weaker sibling
— a different OIDC issuer, or an attribute condition that doesn't pin a code
measurement — is a lateral attestation bypass: an attacker satisfies the weak
door instead of the strong one. This enumerates every provider in the pool and
flags any that is not bound to Confidential Space attestation.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from .keybind import analyze_wif_condition

CS_ISSUER = "confidentialcomputing.googleapis.com"


def analyze_providers(
    providers: list[dict[str, Any]], primary_provider_id: str | None = None
) -> dict[str, Any]:
    """Flag pool providers whose issuer/condition doesn't bind CS attestation."""
    weak: list[dict[str, Any]] = []
    for p in providers:
        if p.get("state") == "DELETED":
            continue
        pid = p.get("name", "").rsplit("/", 1)[-1]
        issuer = (p.get("oidc", {}) or {}).get("issuerUri", "")
        cond = p.get("attributeCondition")
        issues: list[str] = []
        if issuer and CS_ISSUER not in issuer:
            issues.append(f"issuer '{issuer}' is not Confidential Space")
        if not analyze_wif_condition(cond)["passed"]:
            issues.append(
                "attribute condition does not bind a code measurement (dbgstat + image_digest)"
            )
        if issues:
            weak.append(
                {"provider": pid, "is_primary": pid == primary_provider_id, "issues": issues}
            )
    return {"weak_providers": weak, "total": len(providers), "passed": not weak}


class ConfidentialSpaceWifSiblingsCheck(Check):
    check_id = "CSPACE-WIF-02"
    title = "All providers in the workload identity pool bind attestation"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.wip_provider:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --wip-provider specified; skipping check.",
            )
        try:
            providers = _fetch_pool_providers(target)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not list pool providers: {e}",
            )
        primary = target.wip_provider.rsplit("/", 1)[-1]
        v = analyze_providers(providers, primary)
        if not v["passed"]:
            names = ", ".join(
                f"{w['provider']}{' (primary)' if w['is_primary'] else ''}"
                for w in v["weak_providers"]
            )
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(v['weak_providers'])} of {v['total']} pool provider(s) do not bind "
                    f"Confidential Space attestation: {names}. A weaker sibling is a lateral "
                    f"key-release bypass."
                ),
                remediation=(
                    "Every provider in a pool that can reach the workload's resources must "
                    "use the Confidential Space issuer and pin dbgstat + image_digest. Remove "
                    "or scope any general-purpose / unconditioned sibling provider."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=f"All {v['total']} pool provider(s) bind Confidential Space attestation.",
            evidence=v,
        )


def _fetch_pool_providers(target: Target) -> list[dict[str, Any]]:  # pragma: no cover - live only
    from googleapiclient.discovery import build  # type: ignore
    pool = target.wip_provider.split("/providers/")[0]  # type: ignore[union-attr]
    iam = build("iam", "v1", cache_discovery=False)
    resp = (
        iam.projects().locations().workloadIdentityPools().providers().list(parent=pool).execute()
    )
    providers: list[dict[str, Any]] = resp.get("workloadIdentityPoolProviders", [])
    return providers
