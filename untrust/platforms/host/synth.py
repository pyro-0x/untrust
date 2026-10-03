"""Synthetic, cryptographically real host evidence for the demo and tests.

Everything is signed with throwaway keys made here, so the verifier runs its
real chain, signature, and replay code. Nothing here is AMD- or TPM-vendor
signed; the "roots" are only trusted because the matching baseline pins them.
"""

from __future__ import annotations

import hashlib
import json
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import cache
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from . import snp, tpm
from .chain import fingerprint
from .verify import Evidence

GOOD_TCB = {"bootloader": 4, "tee": 0, "snp": 22, "microcode": 213}
GOOD_MEASUREMENT = bytes.fromhex("5e" * 48)
NONCE = hashlib.sha256(b"untrust-host-demo-nonce").digest()
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)


@dataclass
class Fixture:
    evidence: Evidence
    baseline: dict[str, Any]
    nonce: bytes


@cache
def _rsa(name: str) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@cache
def _ec(name: str, curve: str) -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1() if curve == "p384" else ec.SECP256R1())


def _cert(subject: str, key: Any, issuer: str, signer: Any, *, ca: bool | None,
          extensions: Sequence[x509.ExtensionType] = (), pss: bool = False) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
    )
    if ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                                        critical=True)
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)
    if pss:
        return builder.sign(signer, hashes.SHA384(), rsa_padding=_PSS)
    return builder.sign(signer, hashes.SHA256())


def _der_int(v: int) -> bytes:
    body = v.to_bytes(v.bit_length() // 8 + 1, "big")
    return bytes([0x02, len(body)]) + body


def _tcb_u64(tcb: dict[str, int]) -> int:
    b = bytes([tcb["bootloader"], tcb["tee"], 0, 0, 0, 0, tcb["snp"], tcb["microcode"]])
    return int.from_bytes(b, "little")


def snp_fixture(
    *,
    debug: bool = False,
    migrate_ma: bool = False,
    reported_tcb: dict[str, int] | None = None,
    cert_tcb: dict[str, int] | None = None,
    measurement: bytes = GOOD_MEASUREMENT,
    report_data: bytes | None = None,
    chip_id: bytes = b"\xc1" * 64,
    cert_chip_id: bytes | None = None,
    tamper: bool = False,
    pin_root: bool = True,
) -> Fixture:
    """A VCEK-signed SEV-SNP report plus a baseline it passes by default."""
    reported_tcb = reported_tcb or GOOD_TCB
    cert_tcb = cert_tcb or reported_tcb
    ark_key, ask_key, vcek_key = _rsa("ark"), _rsa("ask"), _ec("vcek", "p384")
    ark = _cert("ARK-Milan", ark_key, "ARK-Milan", ark_key, ca=None, pss=True)
    ask = _cert("SEV-Milan", ask_key, "ARK-Milan", ark_key, ca=None, pss=True)
    exts: list[x509.ExtensionType] = [
        x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), _der_int(cert_tcb[name]))
        for name, oid in snp.TCB_OIDS.items()
    ]
    exts.append(x509.UnrecognizedExtension(x509.ObjectIdentifier(snp.HWID_OID),
                                           cert_chip_id or chip_id))
    vcek = _cert("SEV-VCEK", vcek_key, "SEV-Milan", ask_key, ca=None, extensions=exts,
                 pss=True)

    policy = 0x30000 | (snp.POLICY_DEBUG if debug else 0) | (
        snp.POLICY_MIGRATE_MA if migrate_ma else 0)
    raw = bytearray(snp.REPORT_SIZE)
    struct.pack_into("<IIQ", raw, 0x00, 3, 1, policy)
    struct.pack_into("<II", raw, 0x30, 0, snp.SIG_ALGO_ECDSA_P384_SHA384)
    tcb = _tcb_u64(reported_tcb)
    for offset in (0x38, 0x180, 0x1E0, 0x1F0):
        struct.pack_into("<Q", raw, offset, tcb)
    raw[0x50:0x90] = (NONCE if report_data is None else report_data).ljust(64, b"\0")
    raw[0x90:0xC0] = measurement
    raw[0x1A0:0x1E0] = chip_id
    r, s = decode_dss_signature(
        vcek_key.sign(bytes(raw[:snp.SIGNED_LEN]), ec.ECDSA(hashes.SHA384())))
    raw[0x2A0:0x2E8] = r.to_bytes(72, "little")
    raw[0x2E8:0x330] = s.to_bytes(72, "little")
    if tamper:
        raw[0x90] ^= 0xFF  # flip a measurement byte after signing

    baseline = {"sev-snp": {
        "trusted_roots_sha256": [fingerprint(ark)] if pin_root else [],
        "measurements": [GOOD_MEASUREMENT.hex()],
        "min_tcb": dict(GOOD_TCB),
    }}
    return Fixture(Evidence("sev-snp", [vcek, ask, ark], report=bytes(raw)), baseline, NONCE)


def _event(pcr: int, event_type: int, data: bytes, digest: bytes | None = None) -> bytes:
    d = digest if digest is not None else hashlib.sha256(data).digest()
    return (struct.pack("<II", pcr, event_type) + struct.pack("<I", 1)
            + struct.pack("<H", 0x000B) + d + struct.pack("<I", len(data)) + data)


def _spec_id_event() -> bytes:
    spec = (b"Spec ID Event03\0" + struct.pack("<IBBBB", 0, 0, 2, 0, 2)
            + struct.pack("<I", 1) + struct.pack("<HH", 0x000B, 32) + b"\0")
    return struct.pack("<II", 0, tpm.EV_NO_ACTION) + bytes(20) + struct.pack("<I", len(spec)) + spec


def _secure_boot_var(enabled: bool) -> bytes:
    name = "SecureBoot".encode("utf-16-le")
    value = b"\x01" if enabled else b"\x00"
    return (bytes.fromhex("61dfe48bca93d211aa0d00e098032b8c")
            + struct.pack("<QQ", len(name) // 2, len(value)) + name + value)


def event_log(*, secure_boot: bool = True, forge_secure_boot: bool = False) -> bytes:
    """A crypto-agile log measuring firmware into PCR 0 and Secure Boot into PCR 7.

    ``forge_secure_boot`` keeps the digest of SecureBoot=0 but rewrites the event
    data to claim SecureBoot=1, the trick a lazy log parser falls for.
    """
    sb = _secure_boot_var(secure_boot)
    sb_digest = None
    if forge_secure_boot:
        sb_digest = hashlib.sha256(_secure_boot_var(False)).digest()
        sb = _secure_boot_var(True)
    return (_spec_id_event()
            + _event(0, 0x00000008, b"untrust-demo-firmware 1.0")  # EV_S_CRTM_VERSION
            + _event(7, tpm.EV_EFI_VARIABLE_DRIVER_CONFIG, sb, sb_digest)
            + _event(0, 0x00000004, b"\0\0\0\0")  # EV_SEPARATOR
            + _event(7, 0x00000004, b"\0\0\0\0"))


def tpm_fixture(
    *,
    log: bytes | None = None,
    quoted_pcrs: tuple[int, ...] = (0, 7),
    pcr_overrides: dict[int, bytes] | None = None,
    extra_data: bytes | None = None,
    firmware_version: int = 0x0001_0002_0003_0004,
    tamper: bool = False,
    pin_root: bool = True,
    hash_name: str = "sha256",
) -> Fixture:
    """A quote signed by a CA-certified AK, PCRs, and an event log; passes by default."""
    log = event_log() if log is None else log
    replayed = tpm.replay_event_log(log).pcrs["sha256"]
    pcrs = {i: replayed.get(i, bytes(32)) for i in range(24)}
    pcrs.update(pcr_overrides or {})

    ca_key, ak_key = _ec("ak-ca", "p256"), _ec("ak", "p256")
    ca = _cert("untrust AK CA", ca_key, "untrust AK CA", ca_key, ca=True)
    ak = _cert("host-01 AK", ak_key, "untrust AK CA", ca_key, ca=False)

    bitmap = bytearray(3)
    for i in quoted_pcrs:
        bitmap[i // 8] |= 1 << (i % 8)
    digest = hashlib.new(hash_name, b"".join(pcrs[i] for i in sorted(quoted_pcrs))).digest()
    nonce = NONCE if extra_data is None else extra_data
    hash_id = {v: k for k, v in tpm.HASH_ALGS.items()}[hash_name]
    attest = bytearray(
        struct.pack(">IH", tpm.TPM_GENERATED_VALUE, tpm.TPM_ST_ATTEST_QUOTE)
        + struct.pack(">H", 34) + b"\x00\x0b" + bytes(32)
        + struct.pack(">H", len(nonce)) + nonce
        + struct.pack(">QIIB", 123456, 7, 0, 1)
        + struct.pack(">Q", firmware_version)
        + struct.pack(">I", 1) + struct.pack(">HB", 0x000B, 3) + bytes(bitmap)
        + struct.pack(">H", len(digest)) + digest
    )
    hash_cls = {"sha1": hashes.SHA1, "sha256": hashes.SHA256}[hash_name]
    r, s = decode_dss_signature(ak_key.sign(bytes(attest), ec.ECDSA(hash_cls())))
    sig = (struct.pack(">HH", tpm.TPM_ALG_ECDSA, hash_id)
           + struct.pack(">H", 32) + r.to_bytes(32, "big")
           + struct.pack(">H", 32) + s.to_bytes(32, "big"))
    if tamper:
        attest[-1] ^= 0xFF

    baseline = {"tpm2": {
        "trusted_roots_sha256": [fingerprint(ca)] if pin_root else [],
        "pcrs": {"sha256": {str(i): replayed[i].hex() for i in (0, 7)}},
        "min_firmware_version": 0x0001_0002_0000_0000,
    }}
    evidence = Evidence("tpm2", [ak, ca], quote=bytes(attest), signature=sig,
                        pcrs={"sha256": pcrs}, event_log=log)
    return Fixture(evidence, baseline, NONCE)


def write_fixture(fx: Fixture, directory: str | Path) -> tuple[Path, Path]:
    """Write ``fx`` as an evidence manifest + baseline; return their paths."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    ev = fx.evidence
    certs = []
    for i, cert in enumerate(ev.certs):
        (d / f"cert{i}.pem").write_bytes(cert.public_bytes(Encoding.PEM))
        certs.append(f"cert{i}.pem")
    manifest: dict[str, Any] = {"type": ev.type, "certs": certs}
    if ev.type == "sev-snp":
        (d / "report.bin").write_bytes(ev.report)
        manifest["report"] = "report.bin"
    else:
        (d / "quote.msg").write_bytes(ev.quote)
        (d / "quote.sig").write_bytes(ev.signature)
        (d / "pcrs.json").write_text(json.dumps(
            {bank: {str(i): v.hex() for i, v in values.items()}
             for bank, values in ev.pcrs.items()}))
        manifest.update(quote="quote.msg", signature="quote.sig", pcrs="pcrs.json")
        if ev.event_log is not None:
            (d / "event_log.bin").write_bytes(ev.event_log)
            manifest["event_log"] = "event_log.bin"
    (d / "evidence.json").write_text(json.dumps(manifest, indent=2))
    (d / "baseline.json").write_text(json.dumps(fx.baseline, indent=2))
    return d / "evidence.json", d / "baseline.json"
