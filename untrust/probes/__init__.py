"""Generalized injection-probe framework for untrust.

A surface-aware test suite: pluggable input *surfaces* (object store, SQL, HTTP,
kv, vsock), a payload *catalog* tagged by attack class + applicable surface, and
per-class *oracles* that decide whether an injection actually worked. The
*engine* fires the applicable payloads at a surface and reports the vulnerable
attack classes. Adding a surface adapter pulls in every payload written for it.
"""
from .catalog import CANARY_TOKEN, CATALOG, OracleName, Payload, SurfaceType, payloads_for
from .engine import PayloadResult, ProbeReport, probe_surface
from .oracles import (
    AcceptedOracle,
    BooleanDiffOracle,
    ErrorSignatureOracle,
    OobCallbackOracle,
    ReflectionOracle,
    TimeDelayOracle,
    Verdict,
    default_oracles,
)
from .surfaces import ObjectStoreSurface, Observation, SqlSurface, WriteBlocked

__all__ = [
    # catalog
    "CATALOG",
    "CANARY_TOKEN",
    "OracleName",
    "Payload",
    "SurfaceType",
    "payloads_for",
    # surfaces
    "Observation",
    "ObjectStoreSurface",
    "SqlSurface",
    "WriteBlocked",
    # oracles
    "Verdict",
    "AcceptedOracle",
    "ErrorSignatureOracle",
    "BooleanDiffOracle",
    "TimeDelayOracle",
    "ReflectionOracle",
    "OobCallbackOracle",
    "default_oracles",
    # engine
    "probe_surface",
    "ProbeReport",
    "PayloadResult",
]
