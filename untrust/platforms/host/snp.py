"""AMD SEV-SNP attestation report parsing and verification.

Layout follows the SEV-SNP firmware ABI ``ATTESTATION_REPORT`` (0x4A0 bytes;
versions 2 and 3). The signature covers bytes ``0x000-0x29F`` and is ECDSA
P-384 / SHA-384 with ``r`` and ``s`` stored as 72-byte little-endian integers.
``TCB_VERSION`` is decoded with the Milan/Genoa layout (bootloader, TEE, SNP,
microcode); Turin's FMC-bearing layout is not handled yet.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

REPORT_SIZE = 0x4A0
SUPPORTED_VERSIONS = (2, 3)
MIN_NONCE_BYTES = 16
SIGNED_LEN = 0x2A0
SIG_ALGO_ECDSA_P384_SHA384 = 1

# Guest policy bits.
POLICY_SMT = 1 << 16
POLICY_SINGLE_SOCKET = 1 << 20
POLICY_MIGRATE_MA = 1 << 18
POLICY_DEBUG = 1 << 19

# 0x48 key-info bits: MASK_CHIP_KEY is bit 1, SIGNING_KEY is bits 2-4.
SIGNING_KEY_VCEK, SIGNING_KEY_VLEK, SIGNING_KEY_NONE = 0, 1, 7

TCB_FIELDS = ("bootloader", "tee", "snp", "microcode")

# VCEK/VLEK certificate extensions carrying the TCB the key was derived for.
_OID_BASE = "1.3.6.1.4.1.3704.1"
TCB_OIDS = {
    "bootloader": f"{_OID_BASE}.3.1",
    "tee": f"{_OID_BASE}.3.2",
    "snp": f"{_OID_BASE}.3.3",
    "microcode": f"{_OID_BASE}.3.8",
}
HWID_OID = f"{_OID_BASE}.4"


def decode_tcb(raw: int) -> dict[str, int]:
    """Milan/Genoa ``TCB_VERSION``: byte 0 bootloader, 1 TEE, 6 SNP, 7 microcode."""
    b = raw.to_bytes(8, "little")
    return {"bootloader": b[0], "tee": b[1], "snp": b[6], "microcode": b[7]}


@dataclass
class SnpReport:
    raw: bytes
    version: int
    guest_svn: int
    policy: int
    vmpl: int
    signature_algo: int
    mask_chip_key: bool
    signing_key: int
    report_data: bytes
    measurement: bytes
    host_data: bytes
    chip_id: bytes
    current_tcb: dict[str, int]
    reported_tcb: dict[str, int]
    committed_tcb: dict[str, int]
    launch_tcb: dict[str, int]
    sig_r: int
    sig_s: int

    @property
    def debug(self) -> bool:
        return bool(self.policy & POLICY_DEBUG)

    @property
    def migrate_ma(self) -> bool:
        return bool(self.policy & POLICY_MIGRATE_MA)


def parse_report(raw: bytes) -> SnpReport:
    if len(raw) < REPORT_SIZE:
        raise ValueError(f"SEV-SNP report is {len(raw)} bytes; expected {REPORT_SIZE}")
    raw = raw[:REPORT_SIZE]
    version, guest_svn, policy = struct.unpack_from("<IIQ", raw, 0x00)
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"unsupported SEV-SNP report version {version}; this layout "
                         f"is only defined for versions {SUPPORTED_VERSIONS}")
    vmpl, signature_algo = struct.unpack_from("<II", raw, 0x30)
    (key_info,) = struct.unpack_from("<I", raw, 0x48)

    def tcb(offset: int) -> dict[str, int]:
        return decode_tcb(struct.unpack_from("<Q", raw, offset)[0])

    return SnpReport(
        raw=raw,
        version=version,
        guest_svn=guest_svn,
        policy=policy,
        vmpl=vmpl,
        signature_algo=signature_algo,
        mask_chip_key=bool(key_info & 0b10),
        signing_key=(key_info >> 2) & 0b111,
        report_data=raw[0x50:0x90],
        measurement=raw[0x90:0xC0],
        host_data=raw[0xC0:0xE0],
        chip_id=raw[0x1A0:0x1E0],
        current_tcb=tcb(0x38),
        reported_tcb=tcb(0x180),
        committed_tcb=tcb(0x1E0),
        launch_tcb=tcb(0x1F0),
        sig_r=int.from_bytes(raw[0x2A0:0x2E8], "little"),
        sig_s=int.from_bytes(raw[0x2E8:0x330], "little"),
    )


def verify_signature(report: SnpReport, signer: x509.Certificate) -> dict[str, Any]:
    """Verify the report signature with the VCEK/VLEK public key."""
    issues: list[str] = []
    if report.mask_chip_key or report.signing_key == SIGNING_KEY_NONE:
        issues.append("report is unsigned (MASK_CHIP_KEY set or SIGNING_KEY=none)")
    elif report.signing_key not in (SIGNING_KEY_VCEK, SIGNING_KEY_VLEK):
        issues.append(f"report names reserved SIGNING_KEY {report.signing_key}")
    else:
        issues.extend(_signer_kind_issues(report, signer))
    if report.signature_algo != SIG_ALGO_ECDSA_P384_SHA384:
        issues.append(f"unsupported signature algorithm {report.signature_algo}")
    key = signer.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp384r1":
        issues.append("signing certificate does not carry a P-384 key")
    if not issues and isinstance(key, ec.EllipticCurvePublicKey):
        sig = encode_dss_signature(report.sig_r, report.sig_s)
        try:
            key.verify(sig, report.raw[:SIGNED_LEN], ec.ECDSA(hashes.SHA384()))
        except InvalidSignature:
            issues.append("report signature does not verify against the VCEK/VLEK")
    return {
        "signer": signer.subject.rfc4514_string(),
        "signing_key": {SIGNING_KEY_VCEK: "vcek", SIGNING_KEY_VLEK: "vlek"}.get(
            report.signing_key, "none"),
        "issues": issues,
        "passed": not issues,
    }


def _signer_kind_issues(report: SnpReport, signer: x509.Certificate) -> list[str]:
    """The cert must be the kind of key the report says signed it.

    A VCEK carries a hardware-ID extension and a VLEK does not, so the report's
    SIGNING_KEY field cannot steer which bindings are checked.
    """
    _, hwid = cert_tcb(signer)
    if report.signing_key == SIGNING_KEY_VCEK and hwid is None:
        return ["report says VCEK but the signing certificate has no hardware ID (not a VCEK)"]
    if report.signing_key == SIGNING_KEY_VLEK and hwid is not None:
        return ["report says VLEK but the signing certificate carries a hardware ID (a VCEK)"]
    return []


def _der_int(value: bytes) -> int | None:
    if len(value) >= 2 and value[0] == 0x02 and value[1] == len(value) - 2:
        return int.from_bytes(value[2:], "big", signed=True)
    return None


def cert_tcb(cert: x509.Certificate) -> tuple[dict[str, int | None], bytes | None]:
    """The TCB and hardware ID baked into a VCEK (VLEKs carry no hwID)."""
    exts = {e.oid.dotted_string: e.value for e in cert.extensions}

    def raw(oid: str) -> bytes | None:
        v = exts.get(oid)
        return v.value if isinstance(v, x509.UnrecognizedExtension) else None

    tcb = {name: _der_int(raw(oid) or b"") for name, oid in TCB_OIDS.items()}
    hwid = raw(HWID_OID)
    if hwid is not None and len(hwid) == 66 and hwid[:2] == b"\x04\x40":
        hwid = hwid[2:]  # tolerate an OCTET STRING-wrapped hwID
    return tcb, hwid


def check_tcb(
    report: SnpReport, signer: x509.Certificate, baseline: dict[str, Any]
) -> dict[str, Any]:
    """Anti-rollback: reported TCB meets the floor and matches the signing cert."""
    issues: list[str] = []
    floor = baseline.get("min_tcb") or {}
    if not floor:
        issues.append("no TCB floor (min_tcb) in the baseline; a rolled-back "
                      "firmware/microcode TCB would be accepted")
    for name in TCB_FIELDS:
        want = floor.get(name)
        got = report.reported_tcb[name]
        if want is not None and got < int(want):
            issues.append(f"reported {name} SVN {got} is below the floor {want}")
    min_svn = baseline.get("min_guest_svn")
    if min_svn is not None and report.guest_svn < int(min_svn):
        issues.append(f"guest SVN {report.guest_svn} is below the floor {min_svn}")

    cert_values, hwid = cert_tcb(signer)
    if report.signing_key not in (SIGNING_KEY_VCEK, SIGNING_KEY_VLEK):
        issues.append("report names no VCEK or VLEK signing key, so its TCB cannot be "
                      "bound to a certificate")
    else:
        # Both VCEKs and VLEKs are issued for one specific TCB.
        mismatched = [n for n in TCB_FIELDS if cert_values[n] != report.reported_tcb[n]]
        if mismatched:
            issues.append("signing key was issued for a different TCB than the report "
                          "claims (" + ", ".join(mismatched) + ")")
    if report.signing_key == SIGNING_KEY_VCEK:
        if hwid is None:
            issues.append("VCEK carries no hardware ID extension")
        elif hwid != report.chip_id:
            issues.append("VCEK hardware ID does not match the report's CHIP_ID")
    return {
        "reported_tcb": report.reported_tcb,
        "committed_tcb": report.committed_tcb,
        "cert_tcb": cert_values,
        "min_tcb": floor,
        "guest_svn": report.guest_svn,
        "issues": issues,
        "passed": not issues,
    }


def check_debug(report: SnpReport, baseline: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    if report.debug and not baseline.get("allow_debug", False):
        issues.append("guest policy allows DEBUG; the hypervisor can read and "
                      "write guest memory")
    if report.migrate_ma and not baseline.get("allow_migration_agent", False):
        issues.append("guest policy allows a migration agent, which can export "
                      "guest state")
    max_vmpl = baseline.get("max_vmpl")
    if max_vmpl is not None and report.vmpl > int(max_vmpl):
        issues.append(f"report requested at VMPL{report.vmpl}, above VMPL{max_vmpl}")
    # Optional pins on the rest of the guest policy.
    abi = ((report.policy >> 8) & 0xFF, report.policy & 0xFF)
    min_abi = baseline.get("min_policy_abi")
    if min_abi is not None and abi < (int(min_abi["major"]), int(min_abi["minor"])):
        issues.append(f"guest policy minimum ABI {abi[0]}.{abi[1]} is below "
                      f"{min_abi['major']}.{min_abi['minor']}")
    smt = bool(report.policy & POLICY_SMT)
    if smt and not baseline.get("allow_smt", True):
        issues.append("guest policy allows SMT, which the baseline forbids")
    single_socket = bool(report.policy & POLICY_SINGLE_SOCKET)
    if baseline.get("require_single_socket", False) and not single_socket:
        issues.append("guest policy does not require a single socket")
    return {
        "policy": hex(report.policy),
        "debug": report.debug,
        "migrate_ma": report.migrate_ma,
        "vmpl": report.vmpl,
        "policy_abi": f"{abi[0]}.{abi[1]}",
        "smt": smt,
        "single_socket": single_socket,
        "issues": issues,
        "passed": not issues,
    }


def check_measurement(report: SnpReport, baseline: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    allowed = [m.lower() for m in baseline.get("measurements") or []]
    measured = report.measurement.hex()
    if not allowed:
        issues.append("no golden launch measurement pinned; any guest image is accepted")
    elif measured not in allowed:
        issues.append("launch measurement is not in the pinned baseline")
    host_data = baseline.get("host_data")
    if host_data is not None and report.host_data.hex() != host_data.lower():
        issues.append("HOST_DATA does not match the pinned value")
    return {
        "measurement": measured,
        "pinned": len(allowed),
        "issues": issues,
        "passed": not issues,
    }


def check_nonce(report: SnpReport, nonce: bytes | None) -> dict[str, Any]:
    """REPORT_DATA must equal the verifier's nonce (exact, or zero-padded to 64)."""
    if nonce is None:
        return {"report_data": report.report_data.hex(), "issues": [],
                "passed": None}
    issues = []
    if len(nonce) < MIN_NONCE_BYTES:
        issues.append(f"nonce is {len(nonce)} bytes; at least {MIN_NONCE_BYTES} are "
                      "needed so it cannot be guessed")
    expected = nonce.ljust(64, b"\0") if len(nonce) <= 64 else None
    if expected != report.report_data:
        issues.append("REPORT_DATA does not carry the expected nonce; the report may be "
                      "replayed")
    return {"report_data": report.report_data.hex(), "issues": issues,
            "passed": not issues}
