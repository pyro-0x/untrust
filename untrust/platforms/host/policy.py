"""Strict readers for baseline values shared by the SEV-SNP and TPM2 paths."""

from __future__ import annotations

from typing import Any


def flag(baseline: dict[str, Any], key: str, default: bool) -> bool:
    """Read a boolean switch; anything but a real bool raises.

    ``bool("false")`` is True, so a string or number here could silently flip a
    security switch. Raising lets ``verify()`` turn the bad baseline into a deny.
    """
    value = baseline.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"baseline '{key}' must be true or false, not {value!r}")
    return value


# Every boolean switch per evidence type, with its default.
SWITCHES: dict[str, dict[str, bool]] = {
    "sev-snp": {"allow_debug": False, "allow_migration_agent": False, "allow_smt": True,
                "require_single_socket": False},
    "tpm2": {"require_ak_eku": True, "require_clock_safe": False,
             "require_secure_boot": True},
}


def check_switches(baseline: dict[str, Any], evidence_type: str) -> None:
    """Validate every switch for ``evidence_type`` at once, naming all bad ones.

    Controls also read their switches with ``flag()``; this pass just reports
    every malformed switch in one error, before any control runs.
    """
    bad = [f"'{key}' ({baseline[key]!r})" for key in SWITCHES.get(evidence_type, {})
           if key in baseline and not isinstance(baseline[key], bool)]
    if bad:
        raise ValueError("baseline switches must be true or false: " + ", ".join(bad))
