"""The probe engine — fires the applicable catalog at a surface, scores oracles.

Surface-agnostic: give it any InputSurface and it selects the payloads for that
surface type, captures a baseline, fires each payload, runs its oracle, and
aggregates a report by attack class.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .catalog import CATALOG, Payload, payloads_for
from .oracles import Oracle, Verdict, default_oracles
from .surfaces import InputSurface


@dataclass
class PayloadResult:
    payload: Payload
    verdict: Verdict


@dataclass
class ProbeReport:
    surface_type: str
    results: list[PayloadResult] = field(default_factory=list)

    @property
    def vulnerable(self) -> list[PayloadResult]:
        return [r for r in self.results if r.verdict.vulnerable]

    @property
    def vulnerable_classes(self) -> list[str]:
        return sorted({r.payload.attack_class for r in self.vulnerable})

    @property
    def any_vulnerable(self) -> bool:
        return bool(self.vulnerable)

    def as_evidence(self) -> dict:
        return {
            "surface_type": self.surface_type,
            "vulnerable_classes": self.vulnerable_classes,
            "vulnerable": [
                {
                    "class": r.payload.attack_class,
                    "vector": r.payload.vector,
                    "oracle": r.verdict.oracle,
                    "detail": r.verdict.detail,
                }
                for r in self.vulnerable
            ],
            "tested": len(self.results),
        }


def probe_surface(
    surface: InputSurface,
    catalog: list[Payload] | None = None,
    oracles: dict[str, Oracle] | None = None,
) -> ProbeReport:
    """Probe one input surface with every applicable payload in the catalog."""
    catalog = catalog if catalog is not None else CATALOG
    oracles = oracles if oracles is not None else default_oracles()

    payloads = [p for p in catalog if surface.surface_type in p.applies_to]
    report = ProbeReport(surface_type=surface.surface_type)

    baseline = surface.baseline()
    for p in payloads:
        obs = surface.send(p)
        oracle = oracles.get(p.oracle)
        if oracle is None:
            continue
        verdict = oracle.evaluate(p, obs, baseline)
        report.results.append(PayloadResult(payload=p, verdict=verdict))

    surface.cleanup()
    return report


# Convenience so callers don't have to import the type registry.
def applicable_payloads(surface_type: str) -> list[Payload]:
    return payloads_for(surface_type)
