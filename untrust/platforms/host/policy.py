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
