"""Demo mode for the host platform: a simulated SEV-SNP host whose evidence is
signed correctly but fails every other control.

The evidence is real (throwaway keys, a genuinely signed report) and the
findings come from running the actual HOST-* checks over it, so the demo
tracks the verifier logic rather than hand-written strings.
"""

from __future__ import annotations

import tempfile

from ...checks.base import Finding, Target
from ...runner import run_checks
from . import HOST_CHECKS, synth


def run_host_demo() -> tuple[Target, list[Finding]]:
    # A debug-policy guest on rolled-back firmware (with a VCEK fetched for that
    # old TCB), running an unpinned image, answering with a stale nonce, and a
    # baseline that never pinned AMD's root.
    fx = synth.snp_fixture(
        debug=True,
        reported_tcb={**synth.GOOD_TCB, "snp": 8, "microcode": 115},
        measurement=bytes.fromhex("d0" * 48),
        report_data=bytes(32),
        pin_root=False,
    )
    with tempfile.TemporaryDirectory(prefix="untrust-host-demo-") as d:
        evidence, baseline = synth.write_fixture(fx, d)
        target = Target(platform="host", host_evidence=str(evidence),
                        host_baseline=str(baseline), host_nonce=fx.nonce.hex())
        findings = run_checks(target, HOST_CHECKS)
    target.host_evidence = "demo://snp-host/evidence.json"
    target.host_baseline = "demo://snp-host/baseline.json"
    return target, findings
