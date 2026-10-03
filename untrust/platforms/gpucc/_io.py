"""Shared JSON-loading helper for the gpu-cc checks.

The GPU-CC checks consume two kinds of captured evidence as JSON files: the
NVIDIA attestation report and the relying-party verifier / key-release policy.
There is no single universal schema; each check's docstring names the exact
fields untrust reads, and a real integration maps its report/policy onto that
shape (the file-based analog of how ``gcp_cspace`` consumes a captured token).
"""

from __future__ import annotations

import json
from typing import Any


def load_json_file(path: str) -> dict[str, Any]:
    """Load a JSON object from ``path``; raise if it is not a top-level object."""
    with open(path) as f:
        data: Any = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object at the top level")
    return data
