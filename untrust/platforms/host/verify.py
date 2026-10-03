"""Host attestation verifier core: ``verify(evidence, baseline, nonce) -> HostVerdict``.

This module has no dependency on the scanner's Check/Finding model, so a
long-running service (an attest-then-enroll gate) can import it directly. The
``HOST-*`` checks are thin wrappers that turn each control into a finding.

Evidence is described by a JSON manifest whose paths are relative to it::

    {"type": "sev-snp", "report": "report.bin",
     "certs": ["vcek.pem", "ask.pem", "ark.pem"]}

    {"type": "tpm2", "quote": "quote.msg", "signature": "quote.sig",
     "pcrs": "pcrs.json", "certs": ["ak.pem", "ak-ca.pem"],
     "event_log": "binary_bios_measurements"}

``certs`` lists the chain leaf first; a file may hold several PEM certs. The
baseline pins what a good host looks like, one section per evidence type::

    {"sev-snp": {"trusted_roots_sha256": ["..."], "measurements": ["..."],
                 "min_tcb": {"bootloader": 3, "tee": 0, "snp": 8, "microcode": 115}},
     "tpm2": {"trusted_roots_sha256": ["..."], "pcrs": {"sha256": {"7": "..."}},
              "min_firmware_version": 0}}
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography import x509

from . import snp, tpm
from .chain import load_certs, verify_chain

CONTROLS = ("chain", "signature", "nonce", "debug", "tcb", "measurement")
EVIDENCE_TYPES = ("sev-snp", "tpm2")


@dataclass
class Evidence:
    type: str
    certs: list[x509.Certificate]
    report: bytes = b""  # sev-snp
    quote: bytes = b""  # tpm2
    signature: bytes = b""  # tpm2
    pcrs: dict[str, dict[int, bytes]] = field(default_factory=dict)  # tpm2
    event_log: bytes | None = None  # tpm2


@dataclass
class Control:
    name: str
    # True = pass, False = fail, None = not assessed (missing input / not applicable).
    passed: bool | None
    issues: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class HostVerdict:
    evidence_type: str
    controls: dict[str, Control]

    @property
    def allowed(self) -> bool:
        """Fail closed: every control must have positively passed."""
        return all(c.passed is True for c in self.controls.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "allowed": self.allowed,
            "controls": {n: {"passed": c.passed, "issues": c.issues, "evidence": c.evidence}
                         for n, c in self.controls.items()},
        }


def load_evidence(manifest_path: str | Path) -> Evidence:
    manifest_path = Path(manifest_path)
    doc = json.loads(manifest_path.read_text())
    if not isinstance(doc, dict):
        raise ValueError("evidence manifest must be a JSON object")
    kind = doc.get("type")
    if kind not in EVIDENCE_TYPES:
        raise ValueError(f"evidence type must be one of {', '.join(EVIDENCE_TYPES)}")
    base = manifest_path.parent

    def read(key: str) -> bytes:
        if not doc.get(key):
            raise ValueError(f"evidence manifest is missing '{key}'")
        return (base / str(doc[key])).read_bytes()

    certs = [c for name in doc.get("certs") or []
             for c in load_certs((base / str(name)).read_bytes())]
    if kind == "sev-snp":
        return Evidence(kind, certs, report=read("report"))
    pcrs = tpm.parse_pcrs(json.loads(read("pcrs")))
    log = read("event_log") if doc.get("event_log") else None
    return Evidence(kind, certs, quote=read("quote"), signature=read("signature"),
                    pcrs=pcrs, event_log=log)


def load_baseline(path: str | Path) -> dict[str, Any]:
    doc = json.loads(Path(path).read_text())
    if not isinstance(doc, dict):
        raise ValueError("baseline must be a JSON object")
    return doc


def _control(name: str, result: dict[str, Any]) -> Control:
    evidence = {k: v for k, v in result.items() if k not in ("issues", "passed")}
    return Control(name, result["passed"], list(result["issues"]), evidence)


def _failed(kind: str, reason: str) -> HostVerdict:
    return HostVerdict(kind, {n: Control(n, False, [reason]) for n in CONTROLS})


def verify(evidence: Evidence, baseline: dict[str, Any], nonce: bytes | None = None,
           *, now: datetime | None = None) -> HostVerdict:
    """Verify host evidence against the baseline section for its type.

    Every control is always evaluated, so one report shows every gap at once;
    ``HostVerdict.allowed`` is the fail-closed decision. This never raises: any
    unexpected error becomes a deny, so a long-running gate cannot crash open.
    """
    try:
        return _verify(evidence, baseline, nonce, now)
    except Exception as e:  # fail closed on anything
        return _failed(evidence.type, f"verification error: {type(e).__name__}: {e}")


def _verify(evidence: Evidence, baseline: dict[str, Any], nonce: bytes | None,
            now: datetime | None) -> HostVerdict:
    policy = baseline.get(evidence.type) or {}
    if not evidence.certs:
        return _failed(evidence.type, "evidence carries no signing certificate chain")
    signer = evidence.certs[0]
    chain = verify_chain(evidence.certs, policy.get("trusted_roots_sha256") or [], now=now,
                         require_ca_constraint=evidence.type == "tpm2")
    if evidence.type == "sev-snp":
        try:
            report = snp.parse_report(evidence.report)
        except (ValueError, IndexError, struct.error) as e:
            return _failed(evidence.type, f"could not parse SEV-SNP report: {e}")
        evaluate = lambda: {  # noqa: E731
            "chain": chain,
            "signature": snp.verify_signature(report, signer),
            "nonce": snp.check_nonce(report, nonce),
            "debug": snp.check_debug(report, policy),
            "tcb": snp.check_tcb(report, signer, policy),
            "measurement": snp.check_measurement(report, policy),
        }
    else:
        try:
            quote = tpm.parse_quote(evidence.quote)
            sig = tpm.parse_signature(evidence.signature)
            log = tpm.replay_event_log(evidence.event_log) if evidence.event_log else None
        except (ValueError, IndexError, struct.error, UnicodeDecodeError) as e:
            return _failed(evidence.type, f"could not parse TPM evidence: {e}")
        evaluate = lambda: {  # noqa: E731
            "chain": chain,
            "signature": tpm.verify_quote_signature(
                quote, sig, signer, require_ak_eku=policy.get("require_ak_eku", True)),
            "nonce": tpm.check_nonce(quote, nonce),
            "debug": tpm.check_secure_boot(quote, evidence.pcrs, log, policy),
            "tcb": tpm.check_tcb(quote, policy),
            "measurement": tpm.check_measurement(quote, sig, evidence.pcrs, log, policy),
        }
    try:
        results = evaluate()
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError) as e:
        # A malformed baseline (bad hex, non-numeric floor) must deny, not crash.
        return _failed(evidence.type, f"invalid baseline or evidence values: {e}")
    return HostVerdict(evidence.type, {n: _control(n, results[n]) for n in CONTROLS})
