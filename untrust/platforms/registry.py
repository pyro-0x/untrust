"""Maps each platform to its check set and demo fixture.

Adding a platform = adding one entry here plus a package under ``platforms/``.
Nitro's entry reuses the existing ``runner.ALL_CHECKS`` list verbatim, so the
Nitro audit is byte-for-byte what it was before the platform layer existed.
"""
from __future__ import annotations

from collections.abc import Callable

from ..checks.base import Check, Finding, Target
from .base import Platform


def _nitro_checks() -> list[type[Check]]:
    from ..runner import ALL_CHECKS
    return ALL_CHECKS


def _nitro_demo() -> tuple[Target, list[Finding]]:
    from ..demo import run_demo
    return run_demo()


def _sevsnp_checks() -> list[type[Check]]:
    from .sevsnp import SEVSNP_CHECKS
    return SEVSNP_CHECKS


def _sevsnp_demo() -> tuple[Target, list[Finding]]:
    from .sevsnp.demo import run_sevsnp_demo
    return run_sevsnp_demo()


def _gpucc_checks() -> list[type[Check]]:
    from .gpucc import GPUCC_CHECKS
    return GPUCC_CHECKS


def _gpucc_demo() -> tuple[Target, list[Finding]]:
    from .gpucc.demo import run_gpucc_demo
    return run_gpucc_demo()


# platform -> (lazy check-list loader, lazy demo loader)
_ChecksLoader = Callable[[], list[type[Check]]]
_DemoLoader = Callable[[], tuple[Target, list[Finding]]]

_REGISTRY: dict[str, tuple[_ChecksLoader, _DemoLoader]] = {
    Platform.NITRO.value: (_nitro_checks, _nitro_demo),
    Platform.SEV_SNP.value: (_sevsnp_checks, _sevsnp_demo),
    Platform.GPU_CC.value: (_gpucc_checks, _gpucc_demo),
    # Platform.TDX.value: (_tdx_checks, _tdx_demo),  # future
}


def supported_platforms() -> list[str]:
    return list(_REGISTRY.keys())


def checks_for(platform: str) -> list[type[Check]]:
    if platform not in _REGISTRY:
        raise ValueError(
            f"Unknown platform '{platform}'. Supported: {', '.join(supported_platforms())}"
        )
    return _REGISTRY[platform][0]()


def demo_for(platform: str) -> tuple[Target, list[Finding]]:
    if platform not in _REGISTRY:
        raise ValueError(
            f"Unknown platform '{platform}'. Supported: {', '.join(supported_platforms())}"
        )
    return _REGISTRY[platform][1]()
