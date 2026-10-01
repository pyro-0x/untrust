"""GPUCC-VMM-META-01: the untrusted host cannot mutate the CVM/GPU launch.

The hypervisor/VMM is untrusted and manages the CVM's lifecycle. If it can
change the launch configuration or the launch measurement after attestation — the
firmware presented, the GPU attached, the boot args — it can relaunch the workload
with attacker-chosen inputs that then re-attest *as themselves*. This is the GPU-CC
form of the Confidential-Space metadata-mutability class (CSPACE-META-01): the
attacker never breaks attestation, they redefine what is attested.

Input: the launch config — ``measurement_pinned`` (the launch measurement is
enforced/pinned) and ``mutable_by`` (principals that can change the launch/device
config, each with a ``kind``). Untrusted kinds: host/hypervisor/vmm/public and any
plain service account.
"""

from __future__ import annotations

from typing import Any

from ...checks.base import Check, Finding, Severity, Status, Target
from ._io import load_json_file

_UNTRUSTED_KINDS = frozenset({"host", "hypervisor", "vmm", "public", "service_account"})


def analyze_launch_mutability(launch: dict[str, Any]) -> dict[str, Any]:
    """Flag an unpinned launch measurement or untrusted principals that can mutate it."""
    measurement_pinned = bool(launch.get("measurement_pinned", False))
    weak_mutators: list[dict[str, str]] = []
    for m in launch.get("mutable_by", []) or []:
        kind = str(m.get("kind", "")).strip().lower()
        if kind in _UNTRUSTED_KINDS:
            weak_mutators.append({"principal": str(m.get("principal", "?")), "kind": kind})

    issues: list[str] = []
    if not measurement_pinned:
        issues.append(
            "the launch measurement is not pinned/enforced (the host can relaunch it)"
        )
    if weak_mutators:
        who = ", ".join(f"{w['principal']} ({w['kind']})" for w in weak_mutators)
        issues.append(f"untrusted principals can mutate the launch/device config: {who}")

    return {
        "measurement_pinned": measurement_pinned,
        "weak_mutators": weak_mutators,
        "has_host": any(w["kind"] in ("host", "hypervisor", "vmm") for w in weak_mutators),
        "issues": issues,
        "passed": not issues,
    }


class GpuLaunchMutabilityCheck(Check):
    check_id = "GPUCC-VMM-META-01"
    title = "The untrusted host cannot mutate the CVM/GPU launch configuration"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.gpu_launch_config:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No --gpu-launch-config specified; skipping check.",
            )
        try:
            launch = load_json_file(target.gpu_launch_config)
        except Exception as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not read/parse launch config: {e}",
            )
        v = analyze_launch_mutability(launch)
        if not v["passed"]:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL if v["has_host"] else self.severity,
                summary="The CVM/GPU launch is mutable by the untrusted host: "
                + "; ".join(v["issues"])
                + ".",
                remediation=(
                    "Pin/enforce the launch measurement and scope who can change the CVM "
                    "and GPU-attach configuration to a tight human/CI admin set; never let "
                    "the host/hypervisor identity redefine the launch. Prefer immutable, "
                    "measured, CI-recreated deployments over in-place launch edits."
                ),
                evidence=v,
            )
        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="The launch measurement is pinned and not mutable by the untrusted host.",
            evidence=v,
        )
