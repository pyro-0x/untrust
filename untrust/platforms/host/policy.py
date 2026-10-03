"""Strict readers for baseline values shared by the SEV-SNP and TPM2 paths."""

from __future__ import annotations

from typing import Any

# Every boolean switch per evidence type, with its default. This is the only
# place a switch's name and default live; ``flag()`` refuses unregistered names.
SWITCHES: dict[str, dict[str, bool]] = {
    "sev-snp": {"allow_debug": False, "allow_migration_agent": False, "allow_smt": True,
                "require_single_socket": False},
    "tpm2": {"require_ak_eku": True, "require_clock_safe": False,
             "require_secure_boot": True},
}
_DEFAULTS: dict[str, bool] = {k: v for switches in SWITCHES.values() for k, v in switches.items()}


def flag(baseline: dict[str, Any], key: str) -> bool:
    """Read a registered boolean switch; anything but a real bool raises.

    ``bool("false")`` is True, so a string or number here could silently flip a
    security switch. Raising lets ``verify()`` turn the bad baseline into a deny.
    """
    if key not in _DEFAULTS:
        raise KeyError(f"'{key}' is not a registered baseline switch")
    value = baseline.get(key, _DEFAULTS[key])
    if not isinstance(value, bool):
        raise ValueError(f"baseline '{key}' must be true or false, not {value!r}")
    return value


def section(baseline: dict[str, Any], evidence_type: str) -> dict[str, Any]:
    """The baseline section for ``evidence_type``; absent means empty, not-an-object denies."""
    value = baseline.get(evidence_type)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"baseline section '{evidence_type}' must be an object, "
                         f"not {value!r}")
    return value


def check_switches(baseline: dict[str, Any], evidence_type: str) -> None:
    """Validate every switch for ``evidence_type`` at once, naming all bad ones.

    Controls also read their switches with ``flag()``; this pass just reports
    every malformed switch in one error, before any control runs.
    """
    bad = [f"'{key}' ({baseline[key]!r})" for key in SWITCHES.get(evidence_type, {})
           if key in baseline and not isinstance(baseline[key], bool)]
    if bad:
        raise ValueError("baseline switches must be true or false: " + ", ".join(bad))
