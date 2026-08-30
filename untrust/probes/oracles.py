"""Oracles — how the engine decides an injection payload actually worked.

Each oracle takes the payload, the observation from firing it, and the surface's
benign baseline, and returns a Verdict. Oracles are surface-agnostic: the same
TimeDelayOracle scores a SQL SLEEP and an OS-command sleep.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .catalog import OracleName, Payload
from .surfaces import Observation

# Substrings that betray a database error reflecting attacker-controlled syntax.
_SQL_ERROR_SIGNATURES = (
    "sql syntax", "syntax error", "unterminated quoted string", "unclosed quotation",
    "sqlstate", "ora-0", "psql:", "sqlite3.operationalerror", "you have an error in your sql",
    "pg::", "mysql_fetch", "odbc", "quoted string not properly terminated",
    "conversion failed", "unexpected end of sql",
)


@dataclass
class Verdict:
    vulnerable: bool
    oracle: str
    detail: str


class Oracle(Protocol):
    name: str

    def evaluate(self, payload: Payload, obs: Observation, baseline: Observation) -> Verdict: ...


class AcceptedOracle:
    name = OracleName.ACCEPTED

    def evaluate(self, payload: Payload, obs: Observation, baseline: Observation) -> Verdict:
        if obs.blocked or obs.accepted is False:
            return Verdict(False, self.name, "write refused by the surface")
        return Verdict(True, self.name, "adversarial input accepted by the boundary")


class ErrorSignatureOracle:
    name = OracleName.ERROR_SIGNATURE

    def evaluate(self, payload: Payload, obs: Observation, baseline: Observation) -> Verdict:
        blob = f"{obs.error}\n{obs.body}".lower()
        hit = next((s for s in _SQL_ERROR_SIGNATURES if s in blob), None)
        if hit:
            return Verdict(True, self.name, f"error signature '{hit}' reflects injected syntax")
        return Verdict(False, self.name, "no error signature")


class BooleanDiffOracle:
    name = OracleName.BOOLEAN_DIFF

    def evaluate(self, payload: Payload, obs: Observation, baseline: Observation) -> Verdict:
        # Injectable if an always-true/operator payload executed cleanly AND
        # changed the result vs a benign lookup.
        if obs.error:
            return Verdict(False, self.name, "payload errored (not a clean boolean change)")
        if obs.body != baseline.body or (obs.status or 0) != (baseline.status or 0):
            return Verdict(True, self.name, "payload altered the result set vs baseline")
        return Verdict(False, self.name, "no observable difference from baseline")


class TimeDelayOracle:
    name = OracleName.TIME_DELAY

    def evaluate(self, payload: Payload, obs: Observation, baseline: Observation) -> Verdict:
        if obs.latency_ms is None:
            return Verdict(False, self.name, "no latency captured")
        base = baseline.latency_ms or 0.0
        threshold = max(payload.expected_delay_ms * 0.7, 1500)  # allow jitter
        if obs.latency_ms - base >= threshold:
            return Verdict(
                True, self.name,
                f"payload stalled the target {obs.latency_ms - base:.0f}ms over baseline",
            )
        return Verdict(False, self.name, "no significant delay")


class ReflectionOracle:
    name = OracleName.REFLECTION

    def evaluate(self, payload: Payload, obs: Observation, baseline: Observation) -> Verdict:
        marker = payload.expected_marker
        if marker and marker in obs.body and marker not in baseline.body:
            return Verdict(True, self.name, f"template evaluated: marker '{marker}' reflected")
        return Verdict(False, self.name, "payload not evaluated")


class OobCallbackOracle:
    """Blind classes (XXE/SSRF/blind cmdi/deserialization).

    Needs an out-of-band canary sink. ``sink_check()`` returns True if the payload
    triggered a callback. Without a configured sink this reports inconclusive.
    """
    name = OracleName.OOB_CALLBACK

    def __init__(self, sink_check: Callable[[Payload], bool] | None = None) -> None:
        self._sink_check = sink_check

    def evaluate(self, payload: Payload, obs: Observation, baseline: Observation) -> Verdict:
        if self._sink_check is None:
            return Verdict(False, self.name, "no OOB canary configured (inconclusive)")
        if self._sink_check(payload):
            return Verdict(True, self.name, "out-of-band callback received")
        return Verdict(False, self.name, "no callback")


def default_oracles() -> dict[str, Oracle]:
    return {
        OracleName.ACCEPTED: AcceptedOracle(),
        OracleName.ERROR_SIGNATURE: ErrorSignatureOracle(),
        OracleName.BOOLEAN_DIFF: BooleanDiffOracle(),
        OracleName.TIME_DELAY: TimeDelayOracle(),
        OracleName.REFLECTION: ReflectionOracle(),
        OracleName.OOB_CALLBACK: OobCallbackOracle(),
    }
