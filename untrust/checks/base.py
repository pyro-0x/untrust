"""Base interface for untrust audit checks.

Each check is a class that inherits from ``Check`` and implements ``run()``.
Checks return a ``Finding`` describing pass/fail, severity, and remediation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Assurance(str, Enum):
    """How much a PASS can be trusted — what evidence backs the verdict.

    A deployment auditor's checks are not equally strong, and a raw pass-count
    hides that. ``PROBED`` checks actively test the live surface. ``REPORT_DERIVED``
    checks read their verdict from the attestation report — trustworthy *only as
    far as that report's signature is verified* (see ``assurance_depends_on``); an
    unverified report is just a JSON file the untrusted host could have written.
    ``DECLARED`` checks only confirm that an operator-authored policy/config *says*
    the right thing — an honesty box: a lying policy passes. Surfacing this level
    stops a high PASS count from reading as stronger assurance than it is. Left
    ``None`` for checks that have not been classified (e.g. the Nitro set), which
    changes their output not at all.
    """
    PROBED = "probed"
    REPORT_DERIVED = "report-derived"
    DECLARED = "operator-declared"


class Boundary(str, Enum):
    """The trust boundary a check audits (the untrust/DEF CON thesis).

    Attestation proves the code, not what crosses these boundaries at/after boot:
    the ``INPUTS`` the workload loads (weights, data, keys), the runtime ``MEMORY``
    those secrets pass through, and the untrusted ``VMM`` that controls the launch —
    plus the ``ATTESTATION`` machinery itself and the underlying ``CVM``.
    """
    ATTESTATION = "attestation"
    INPUTS = "inputs"
    MEMORY = "memory"
    VMM = "vmm"
    CVM = "cvm"


@dataclass
class Finding:
    check_id: str
    title: str
    status: Status
    severity: Severity
    summary: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    # How much a PASS/FAIL can be trusted; None = unclassified (unchanged output).
    assurance: Assurance | None = None
    # Set by the runner when a REPORT_DERIVED verdict's precondition (a signature
    # verification it depends on) did not pass — i.e. the report is unverified.
    assurance_note: str | None = None


@dataclass
class Target:
    """Description of the deployment being audited.

    The original fields describe an AWS Nitro Enclaves deployment; platform is
    "nitro" by default so every existing check and caller behaves unchanged.
    ``bucket`` is the classic S3 bootstrap-state store, but a TEE can load the
    untrusted external state it trusts at boot from other backends. The same
    trust-boundary controls apply to each, so a target may name one or more
    alternative state stores in addition to (or instead of) an S3 bucket;
    checks that target a backend skip when its field is unset. The ``gcp_*``
    fields describe an AMD SEV-SNP workload running on GCP Confidential Space
    and are only read by the gcp-cspace platform checks.
    """
    # --- AWS Nitro (default platform) ---
    bucket: str | None = None
    kms_key_id: str | None = None
    instance_id: str | None = None
    region: str | None = None
    # Alternative state/secret backends (see checks/_backend_util.py).
    dynamodb_table: str | None = None
    secret_arn: str | None = None
    parameter_path: str | None = None
    efs_id: str | None = None
    db_instance: str | None = None

    # --- Platform selector ---
    platform: str = "nitro"  # one of: nitro | gcp-cspace | gpu-cc | host | azure-cvm

    # --- GCP Confidential Space / SEV-SNP ---
    gcp_project: str | None = None
    # Full resource name of the Workload Identity Federation *provider* whose
    # attribute condition gates attestation-based key release, e.g.
    # projects/123/locations/global/workloadIdentityPools/POOL/providers/PROV
    wip_provider: str | None = None
    gcp_kms_key: str | None = None  # projects/.../cryptoKeys/... to audit IAM on
    gcs_bucket: str | None = None   # bootstrap-state bucket
    gcp_instance: str | None = None  # Confidential VM instance name
    gcp_zone: str | None = None      # zone of the Confidential VM
    # Path to a sample Confidential Space attestation token (JWT) for the
    # runtime attestation checks, when a live token can be captured.
    attestation_token: str | None = None

    # --- NVIDIA GPU Confidential Computing (gpu-cc) ---
    # Path to a captured NVIDIA GPU attestation report (JSON).
    gpu_attestation_report: str | None = None
    # Path to the relying party's verifier policy (JSON): pinned RIM measurements,
    # cert-chain validation, revocation, nonce/expiry.
    gpu_verifier_policy: str | None = None
    # CC mode string as reported by `nvidia-smi conf-compute -f`: on|devtools|off.
    gpu_cc_mode: str | None = None
    # Path to the key-release / KBS policy (JSON): attest-before-ready,
    # attestation-bound release, decrypt location.
    gpu_kbs_policy: str | None = None
    # Object store holding model weights/data, for the boot-time injection probe.
    gpu_model_bucket: str | None = None
    # Path to the CVM/GPU launch config (JSON) for the launch-mutability check.
    gpu_launch_config: str | None = None

    # --- Azure confidential VM (azure-cvm) ---
    azure_subscription: str | None = None  # subscription ID
    azure_resource_group: str | None = None
    azure_vm: str | None = None  # confidential VM name
    azure_key_vault: str | None = None  # vault name or host holding the SKR key
    azure_key: str | None = None  # key whose release policy gates the workload's secret
    # MAA provider name (in the resource group) or full resource ID, for AZ-MAA-01.
    azure_attestation_provider: str | None = None
    # Path to an MAA token captured inside the VM, for AZ-DBG-01.
    azure_attestation_token: str | None = None

    # --- Host attestation (SEV-SNP report / TPM2 quote) ---
    # Path to an evidence manifest (JSON) naming the report or quote, its cert
    # chain, and for TPM2 the PCR values and event log.
    host_evidence: str | None = None
    # Path to the pinned baseline (JSON): trusted roots, golden measurements/PCRs,
    # and the TCB / firmware floor.
    host_baseline: str | None = None
    # Hex nonce the verifier issued; must appear in REPORT_DATA / extraData.
    host_nonce: str | None = None


class Check:
    """Subclass and implement ``run()`` to add a new audit."""

    check_id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    # Evidence tier for this check's verdict (see ``Assurance``). The runner stamps
    # it onto findings that don't set one themselves; None leaves output unchanged.
    assurance: Assurance | None = None
    # Which trust boundary this check audits (see ``Boundary``); None = unclassified.
    boundary: Boundary | None = None
    # Check IDs whose PASS is required for a REPORT_DERIVED verdict to be trusted.
    # A report-derived check reads a signed report; if the signature was never
    # verified (its verifier check did not pass), the runner flags the verdict as
    # unverified via ``Finding.assurance_note``.
    assurance_depends_on: tuple[str, ...] = ()

    def run(self, target: Target) -> Finding:  # pragma: no cover - abstract
        raise NotImplementedError
