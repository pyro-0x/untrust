"""Platform enum shared across the registry and CLI."""
from __future__ import annotations

from enum import Enum


class Platform(str, Enum):
    NITRO = "nitro"
    SEV_SNP = "sev-snp"
    GPU_CC = "gpu-cc"
    TDX = "tdx"

    @classmethod
    def choices(cls) -> list[str]:
        return [p.value for p in cls]
