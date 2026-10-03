"""Maps each platform to its check set and demo fixture.

Adding a platform = adding one entry here plus a package under ``platforms/``.
Nitro's entry reuses the existing ``runner.ALL_CHECKS`` list verbatim, so the
Nitro audit is byte-for-byte what it was before the platform layer existed.
"""
from __future__ import annotations

from collections.abc import Callable

from ..checks.base import Check, Finding, Target
from .base import Platform, canonical_platform


def _nitro_checks() -> list[type[Check]]:
    from ..runner import ALL_CHECKS
    return ALL_CHECKS


def _nitro_demo() -> tuple[Target, list[Finding]]:
    from ..demo import run_demo
    return run_demo()


def _gcp_cspace_checks() -> list[type[Check]]:
    from .gcp_cspace import GCP_CSPACE_CHECKS
    return GCP_CSPACE_CHECKS


def _gcp_cspace_demo() -> tuple[Target, list[Finding]]:
    from .gcp_cspace.demo import run_gcp_cspace_demo
    return run_gcp_cspace_demo()


def _gpucc_checks() -> list[type[Check]]:
    from .gpucc import GPUCC_CHECKS
    return GPUCC_CHECKS


def _gpucc_demo() -> tuple[Target, list[Finding]]:
    from .gpucc.demo import run_gpucc_demo
    return run_gpucc_demo()


def _host_checks() -> list[type[Check]]:
    from .host import HOST_CHECKS
    return HOST_CHECKS


def _host_demo() -> tuple[Target, list[Finding]]:
    from .host.demo import run_host_demo
    return run_host_demo()


def _azure_cvm_checks() -> list[type[Check]]:
    from .azure_cvm import AZURE_CVM_CHECKS
    return AZURE_CVM_CHECKS


def _azure_cvm_demo() -> tuple[Target, list[Finding]]:
    from .azure_cvm.demo import run_azure_cvm_demo
    return run_azure_cvm_demo()


# platform -> (lazy check-list loader, lazy demo loader)
_ChecksLoader = Callable[[], list[type[Check]]]
_DemoLoader = Callable[[], tuple[Target, list[Finding]]]

_REGISTRY: dict[str, tuple[_ChecksLoader, _DemoLoader]] = {
    Platform.NITRO.value: (_nitro_checks, _nitro_demo),
    Platform.GCP_CSPACE.value: (_gcp_cspace_checks, _gcp_cspace_demo),
    Platform.GPU_CC.value: (_gpucc_checks, _gpucc_demo),
    Platform.HOST.value: (_host_checks, _host_demo),
    Platform.AZURE_CVM.value: (_azure_cvm_checks, _azure_cvm_demo),
    # Platform.TDX.value: (_tdx_checks, _tdx_demo),  # future
}


def supported_platforms() -> list[str]:
    return list(_REGISTRY.keys())


def checks_for(platform: str) -> list[type[Check]]:
    platform = canonical_platform(platform)
    if platform not in _REGISTRY:
        raise ValueError(
            f"Unknown platform '{platform}'. Supported: {', '.join(supported_platforms())}"
        )
    return _REGISTRY[platform][0]()


def demo_for(platform: str) -> tuple[Target, list[Finding]]:
    platform = canonical_platform(platform)
    if platform not in _REGISTRY:
        raise ValueError(
            f"Unknown platform '{platform}'. Supported: {', '.join(supported_platforms())}"
        )
    return _REGISTRY[platform][1]()
