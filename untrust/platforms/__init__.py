"""Platform abstraction for untrust.

Historically untrust audited only AWS Nitro Enclaves. The trust-boundary thesis
— *attestation proves the code, but not what you hand the code at boot* —
applies to every cloud TEE, so checks are now grouped by platform behind a small
registry. Nitro remains the default and its checks are unchanged.
"""
from .base import Platform
from .registry import checks_for, demo_for, supported_platforms

__all__ = ["Platform", "checks_for", "demo_for", "supported_platforms"]
