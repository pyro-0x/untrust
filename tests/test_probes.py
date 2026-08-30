"""Tests for the generalized injection-probe framework (engine + surfaces + oracles)."""
from __future__ import annotations

from untrust.probes import (
    CATALOG,
    ObjectStoreSurface,
    Observation,
    SqlSurface,
    SurfaceType,
    WriteBlocked,
    payloads_for,
    probe_surface,
)

# --- catalog ----------------------------------------------------------------


def test_catalog_spans_multiple_surfaces_and_classes() -> None:
    classes = {p.attack_class for p in CATALOG}
    assert {"path-traversal", "sqli", "nosqli", "ssti", "cmdi"} <= classes
    assert payloads_for(SurfaceType.OBJECT_STORE)
    assert payloads_for(SurfaceType.SQL)
    # payloads are surface-scoped: SQL payloads never fire at object storage
    obj_classes = {p.attack_class for p in payloads_for(SurfaceType.OBJECT_STORE)}
    assert "sqli" not in obj_classes


# --- object-store surface (accepted oracle) ---------------------------------


def test_object_store_open_bucket_is_vulnerable() -> None:
    report = probe_surface(ObjectStoreSurface(put_fn=lambda name: None))
    assert report.surface_type == SurfaceType.OBJECT_STORE
    assert report.any_vulnerable is True
    assert "path-traversal" in report.vulnerable_classes
    # object-store report must not contain SQL results
    assert all(r.payload.attack_class != "sqli" for r in report.results)


def test_object_store_closed_bucket_is_not_vulnerable() -> None:
    def blocked(name: str) -> None:
        raise WriteBlocked("403")

    report = probe_surface(ObjectStoreSurface(put_fn=blocked))
    assert report.any_vulnerable is False
    assert report.vulnerable_classes == []


def test_object_store_deletes_accepted_canaries() -> None:
    deleted: list[str] = []
    probe_surface(ObjectStoreSurface(put_fn=lambda n: None, delete_fn=deleted.append))
    # baseline + every applicable payload gets cleaned up
    assert len(deleted) == len(payloads_for(SurfaceType.OBJECT_STORE)) + 1


# --- SQL surface (error / boolean / time oracles) ---------------------------


def _vulnerable_sql_executor(query: str) -> Observation:
    """A string-concatenating (vulnerable) DB. Models error/boolean/time signals."""
    # time-based: a sleep payload executes and stalls (blind, no error/output)
    if "pg_sleep" in query or "SLEEP(" in query or "WAITFOR" in query:
        return Observation(body="[]", latency_ms=5200.0)
    # boolean-based: an always-true condition returns every row
    if "'1'='1" in query:
        return Observation(body="[row1,row2,row3,row4]", status=4, latency_ms=6.0)
    # error-based: an unbalanced quote yields a syntax error
    if query.count("'") % 2 == 1:
        return Observation(error="ERROR: unterminated quoted string at or near ...", latency_ms=5.0)
    # benign / parameterized-looking result
    return Observation(body="[row1]", status=1, latency_ms=6.0)


def _safe_sql_executor(query: str) -> Observation:
    """A parameterized (safe) DB: payloads never change structure/behavior."""
    return Observation(body="[row1]", status=1, latency_ms=6.0)


def test_sql_injection_detected_via_multiple_oracles() -> None:
    report = probe_surface(SqlSurface(executor=_vulnerable_sql_executor))
    assert report.surface_type == SurfaceType.SQL
    assert report.any_vulnerable is True
    oracles_fired = {r.verdict.oracle for r in report.vulnerable}
    # error-signature, boolean-diff, and time-delay all independently catch it
    assert {"error-signature", "boolean-diff", "time-delay"} <= oracles_fired


def test_safe_sql_is_not_flagged() -> None:
    report = probe_surface(SqlSurface(executor=_safe_sql_executor))
    # a parameterized DB shows no error, no result change, no delay
    assert report.any_vulnerable is False
