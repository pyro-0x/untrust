"""Input surfaces — pluggable adapters for the channels a TEE workload ingests.

A surface knows its ``surface_type`` (which selects the applicable payloads) and
how to deliver a payload and capture an ``Observation``. The engine and oracles
are surface-agnostic; all surface-specific behavior lives here.
"""
from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .catalog import Payload, SurfaceType


@dataclass
class Observation:
    """What a surface saw after delivering one payload."""
    accepted: bool | None = None   # object-store: was the write accepted?
    blocked: bool = False          # surface refused (403 / policy / denied)
    body: str = ""                 # response body / returned rows (stringified)
    status: int | None = None      # http status / row count
    error: str = ""                # error text surfaced by the consumer
    latency_ms: float | None = None
    note: str = ""
    # --- runtime / fuzzing fields (populated by fuzz surfaces) ---
    crashed: bool = False          # the target died on this input
    alive: bool | None = None      # target still healthy after the input
    restart_count: int | None = None  # enclave restart counter, if observable
    # --- egress/MITM fields (populated by the egress surface) ---
    handshake_completed: bool | None = None  # enclave completed TLS with a rogue endpoint
    app_data_sent: bool | None = None         # enclave sent its request over the rogue channel


class InputSurface(Protocol):
    """An untrusted input channel the TEE workload consumes."""

    surface_type: str

    def baseline(self) -> Observation: ...
    def send(self, payload: Payload) -> Observation: ...
    def cleanup(self) -> None: ...


class WriteBlocked(Exception):
    """An object-store put_fn raises this when the write is refused."""


class ObjectStoreSurface:
    """S3 / GCS bootstrap bucket. Delivers a payload as a canary object write."""

    surface_type = SurfaceType.OBJECT_STORE

    def __init__(
        self,
        put_fn: Callable[[str], None],
        delete_fn: Callable[[str], None] | None = None,
    ) -> None:
        self._put = put_fn
        self._delete = delete_fn

    def baseline(self) -> Observation:
        # A benign key; if even this is refused, writes are simply closed.
        try:
            self._put("untrust-canary-probe-baseline")
            if self._delete:
                with contextlib.suppress(Exception):
                    self._delete("untrust-canary-probe-baseline")
            return Observation(accepted=True)
        except WriteBlocked:
            return Observation(blocked=True, accepted=False)

    def send(self, payload: Payload) -> Observation:
        try:
            self._put(payload.vector)
        except WriteBlocked as e:
            return Observation(accepted=False, blocked=True, error=str(e))
        if self._delete:
            with contextlib.suppress(Exception):
                self._delete(payload.vector)
        return Observation(accepted=True)

    def cleanup(self) -> None:
        pass


class SqlSurface:
    """A relational DB the enclave queries at boot.

    ``executor(query) -> Observation`` runs one query the way the consumer would
    (string-built, to model a vulnerable consumer) and reports body/error/latency.
    ``template`` carries a ``{payload}`` slot; ``baseline_value`` is a benign
    input used for boolean-diff / timing comparison.
    """

    surface_type = SurfaceType.SQL

    def __init__(
        self,
        executor: Callable[[str], Observation],
        template: str = "SELECT * FROM config WHERE key = '{payload}'",
        baseline_value: str = "app_config",
    ) -> None:
        self._exec = executor
        self._template = template
        self._baseline_value = baseline_value

    def baseline(self) -> Observation:
        return self._exec(self._template.format(payload=self._baseline_value))

    def send(self, payload: Payload) -> Observation:
        return self._exec(self._template.format(payload=payload.vector))

    def cleanup(self) -> None:
        pass
