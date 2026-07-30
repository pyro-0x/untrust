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


@dataclass
class Finding:
    check_id: str
    title: str
    status: Status
    severity: Severity
    summary: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Target:
    """Description of the deployment being audited.

    ``bucket`` is the classic S3 bootstrap-state store, but a TEE can load
    the untrusted external state it trusts at boot from other backends. The
    same trust-boundary controls apply to each, so a target may name one or
    more alternative state stores in addition to (or instead of) an S3
    bucket. Checks that target a backend skip when its field is unset.
    """
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


class Check:
    """Subclass and implement ``run()`` to add a new audit."""

    check_id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM

    def run(self, target: Target) -> Finding:  # pragma: no cover - abstract
        raise NotImplementedError
