"""Platform enum shared across the registry and CLI."""
from __future__ import annotations

from enum import Enum


class Platform(str, Enum):
    NITRO = "nitro"
    GCP_CSPACE = "gcp-cspace"
    GPU_CC = "gpu-cc"
    HOST = "host"
    AZURE_CVM = "azure-cvm"
    TDX = "tdx"

    @classmethod
    def choices(cls) -> list[str]:
        return [p.value for p in cls]


# Old platform names still accepted so saved configs and scripts keep working.
# "sev-snp" named the GCP Confidential Space audit before the host platform
# began verifying raw SEV-SNP reports.
PLATFORM_ALIASES: dict[str, str] = {"sev-snp": Platform.GCP_CSPACE.value}


def canonical_platform(platform: str) -> str:
    return PLATFORM_ALIASES.get(platform, platform)


def platform_names(platform: str) -> set[str]:
    """``platform`` plus every alias that resolves to it."""
    name = canonical_platform(platform)
    return {name, *(a for a, target in PLATFORM_ALIASES.items() if target == name)}
