"""TPM 2.0 quote and TCG event log parsing and verification.

Inputs are what ``tpm2-tools`` produces: ``tpm2_quote -m quote.msg -s quote.sig``
(a marshalled ``TPMS_ATTEST`` and a TSS-format ``TPMT_SIGNATURE``), PCR values
as JSON, and the firmware's crypto-agile TCG event log
(``/sys/kernel/security/tpm0/binary_bios_measurements``). TPM structures are
big-endian; the event log is little-endian.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018

TPM_ALG_RSASSA, TPM_ALG_RSAPSS, TPM_ALG_ECDSA = 0x0014, 0x0016, 0x0018
HASH_ALGS: dict[int, str] = {0x0004: "sha1", 0x000B: "sha256", 0x000C: "sha384",
                             0x000D: "sha512"}
_CRYPTO_HASH: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

MIN_NONCE_BYTES = 16

EV_NO_ACTION = 0x00000003
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001


class _Reader:
    def __init__(self, data: bytes, endian: str) -> None:
        self.data, self.pos, self.endian = data, 0, endian

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated structure")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big" if self.endian == ">" else "little")

    def tpm2b(self) -> bytes:
        return self.take(self.uint(2))

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos


@dataclass
class Quote:
    raw: bytes
    extra_data: bytes
    firmware_version: int
    reset_count: int
    restart_count: int
    safe: bool
    # [(bank, [pcr indices in ascending order])] in selection order
    selection: list[tuple[str, list[int]]]
    pcr_digest: bytes


def parse_quote(raw: bytes) -> Quote:
    r = _Reader(raw, ">")
    if r.uint(4) != TPM_GENERATED_VALUE:
        raise ValueError("not a TPM-generated attestation (bad magic)")
    if r.uint(2) != TPM_ST_ATTEST_QUOTE:
        raise ValueError("attestation is not a quote")
    r.tpm2b()  # qualifiedSigner
    extra_data = r.tpm2b()
    r.uint(8)  # clock
    reset_count, restart_count, safe = r.uint(4), r.uint(4), r.uint(1)
    firmware_version = r.uint(8)
    selection = []
    for _ in range(r.uint(4)):
        alg = r.uint(2)
        bitmap = r.take(r.uint(1))
        pcrs = [i * 8 + b for i, byte in enumerate(bitmap) for b in range(8) if byte >> b & 1]
        selection.append((HASH_ALGS.get(alg, f"0x{alg:04x}"), pcrs))
    pcr_digest = r.tpm2b()
    return Quote(raw, extra_data, firmware_version, reset_count, restart_count,
                 bool(safe), selection, pcr_digest)


@dataclass
class Signature:
    alg: int
    hash: str
    rsa_sig: bytes = b""
    ecdsa_r: int = 0
    ecdsa_s: int = 0


def parse_signature(raw: bytes) -> Signature:
    """Parse a TSS-marshalled ``TPMT_SIGNATURE`` (``tpm2_quote -s``'s default)."""
    r = _Reader(raw, ">")
    alg, hash_id = r.uint(2), r.uint(2)
    name = HASH_ALGS.get(hash_id, f"0x{hash_id:04x}")
    if alg in (TPM_ALG_RSASSA, TPM_ALG_RSAPSS):
        return Signature(alg, name, rsa_sig=r.tpm2b())
    if alg == TPM_ALG_ECDSA:
        return Signature(alg, name, ecdsa_r=int.from_bytes(r.tpm2b(), "big"),
                         ecdsa_s=int.from_bytes(r.tpm2b(), "big"))
    raise ValueError(f"unsupported TPM signature algorithm 0x{alg:04x}")


def verify_quote_signature(quote: Quote, sig: Signature,
                           ak_cert: x509.Certificate) -> dict[str, Any]:
    issues: list[str] = []
    if sig.hash not in _CRYPTO_HASH:
        issues.append(f"unsupported quote hash {sig.hash}")
    elif sig.hash == "sha1":
        issues.append("quote is signed with SHA-1")
    key = ak_cert.public_key()
    if not issues:
        algo = _CRYPTO_HASH[sig.hash]()
        digest = hashlib.new(sig.hash, quote.raw).digest()
        try:
            if sig.alg == TPM_ALG_ECDSA and isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(encode_dss_signature(sig.ecdsa_r, sig.ecdsa_s), digest,
                           ec.ECDSA(Prehashed(algo)))
            elif sig.alg == TPM_ALG_RSASSA and isinstance(key, rsa.RSAPublicKey):
                key.verify(sig.rsa_sig, digest, padding.PKCS1v15(), Prehashed(algo))
            elif sig.alg == TPM_ALG_RSAPSS and isinstance(key, rsa.RSAPublicKey):
                key.verify(sig.rsa_sig, digest,
                           padding.PSS(padding.MGF1(algo), padding.PSS.AUTO), Prehashed(algo))
            else:
                issues.append("signature algorithm does not match the AK certificate key")
        except InvalidSignature:
            issues.append("quote signature does not verify against the AK certificate")
    return {"signer": ak_cert.subject.rfc4514_string(), "hash": sig.hash,
            "issues": issues, "passed": not issues}


def quoted_pcr_digest(quote: Quote, pcrs: dict[str, dict[int, bytes]], hash_name: str) -> bytes:
    """Recompute the quote's ``pcrDigest`` from supplied PCR values."""
    h = hashlib.new(hash_name)
    for bank, indices in quote.selection:
        for i in indices:
            value = pcrs.get(bank, {}).get(i)
            if value is None:
                raise ValueError(f"PCR {bank}:{i} is quoted but no value was supplied")
            h.update(value)
    return h.digest()


@dataclass
class EventLog:
    algorithms: dict[int, int]  # alg id -> digest size
    pcrs: dict[str, dict[int, bytes]] = field(default_factory=dict)
    secure_boot: bool | None = None  # None = no SecureBoot variable measured
    secure_boot_unbound: bool = False  # SecureBoot event data didn't match its digest
    secure_boot_conflict: bool = False  # SecureBoot measured twice with different values
    events: int = 0


def replay_event_log(raw: bytes) -> EventLog:
    """Replay a TCG crypto-agile event log into PCR values per bank."""
    r = _Reader(raw, "<")
    # Header event: legacy TCG_PCR_EVENT format carrying TCG_EfiSpecIDEvent.
    r.uint(4)
    if r.uint(4) != EV_NO_ACTION:
        raise ValueError("event log does not start with a Spec ID event")
    r.take(20)
    spec = _Reader(r.take(r.uint(4)), "<")
    if not spec.take(16).startswith(b"Spec ID Event03"):
        raise ValueError("event log is not in crypto-agile (Spec ID Event03) format")
    spec.take(8)  # platformClass, version, errata, uintnSize
    algorithms = {}
    for _ in range(spec.uint(4)):
        alg, size = spec.uint(2), spec.uint(2)
        algorithms[alg] = size
    log = EventLog(algorithms)
    banks = {HASH_ALGS[a] for a in algorithms if a in HASH_ALGS}
    log.pcrs = {b: {} for b in banks}
    locality = 0

    while r.remaining:
        pcr, event_type = r.uint(4), r.uint(4)
        digests = {}
        seen: set[int] = set()
        for _ in range(r.uint(4)):
            alg = r.uint(2)
            if alg not in algorithms:
                raise ValueError(f"event digest uses undeclared algorithm 0x{alg:04x}")
            if alg in seen:
                raise ValueError(f"event carries two digests for algorithm 0x{alg:04x}")
            seen.add(alg)
            digests[HASH_ALGS.get(alg, "")] = r.take(algorithms[alg])
        data = r.take(r.uint(4))
        log.events += 1
        if event_type == EV_NO_ACTION:
            if data.startswith(b"StartupLocality\0") and pcr == 0:
                if len(data) < 17:
                    raise ValueError("StartupLocality event is missing its locality byte")
                locality = data[16]
            continue
        # A measured event must carry a digest for every declared bank. One with
        # missing digests extends nothing, so it could add unbound event data
        # (e.g. a forged SecureBoot=1) while the log still replays to the quote.
        if seen != set(algorithms):
            raise ValueError(f"event {log.events} does not carry a digest for every "
                             "declared algorithm")
        for bank, digest in digests.items():
            if bank not in banks:
                continue
            size = hashlib.new(bank).digest_size
            current = log.pcrs[bank].get(pcr)
            if current is None:
                current = (bytes(size - 1) + bytes([locality])) if pcr == 0 else bytes(size)
            log.pcrs[bank][pcr] = hashlib.new(bank, current + digest).digest()
        if event_type == EV_EFI_VARIABLE_DRIVER_CONFIG and pcr == 7:
            name, value = _efi_variable(data)
            if name == "SecureBoot":
                # Replay only binds the digests; the event data is what we read, so
                # it must hash to those digests or a forged value could be slipped in.
                # Unbound and conflicting states are sticky: no later event clears them.
                bound = bool(banks) and all(
                    b in digests and hashlib.new(b, data).digest() == digests[b]
                    for b in banks)
                enabled = value[:1] == b"\x01"
                if not bound:
                    log.secure_boot_unbound = True
                elif log.secure_boot is not None and log.secure_boot != enabled:
                    log.secure_boot_conflict = True
                else:
                    log.secure_boot = enabled
    return log


def _efi_variable(data: bytes) -> tuple[str, bytes]:
    """Decode ``UEFI_VARIABLE_DATA``: GUID, name length, data length, name, data."""
    r = _Reader(data, "<")
    r.take(16)
    name_len, data_len = r.uint(8), r.uint(8)
    name = r.take(name_len * 2).decode("utf-16-le", errors="replace")
    return name, r.take(data_len)


def parse_pcrs(doc: dict[str, Any]) -> dict[str, dict[int, bytes]]:
    """``{"sha256": {"0": "<hex>", ...}}`` -> ``{"sha256": {0: b"..."}}``."""
    return {bank: {int(i): bytes.fromhex(v) for i, v in values.items()}
            for bank, values in doc.items()}


def check_measurement(quote: Quote, sig: Signature, pcrs: dict[str, dict[int, bytes]],
                      log: EventLog | None, baseline: dict[str, Any]) -> dict[str, Any]:
    """Quoted PCRs bind the supplied values, match the pins, and replay from the log."""
    issues: list[str] = []
    try:
        bound = quoted_pcr_digest(quote, pcrs, sig.hash if sig.hash in _CRYPTO_HASH
                                  else "sha256") == quote.pcr_digest
    except ValueError as e:
        bound = False
        issues.append(str(e))
    if not bound and not issues:
        issues.append("supplied PCR values do not hash to the quoted pcrDigest")
    quoted = {(bank, i) for bank, idx in quote.selection for i in idx}

    pins = parse_pcrs(baseline.get("pcrs") or {})
    if not any(pins.values()):
        issues.append("no golden PCR values pinned; any boot chain is accepted")
    for bank, values in pins.items():
        for i, want in values.items():
            if (bank, i) not in quoted:
                issues.append(f"pinned PCR {bank}:{i} is not covered by the quote")
            elif pcrs.get(bank, {}).get(i) != want:
                issues.append(f"PCR {bank}:{i} does not match the pinned value")

    replayed: bool | None = None
    if log is not None:
        mismatched = [f"{bank}:{i}" for bank, i in sorted(quoted)
                      if bank in log.pcrs and log.pcrs[bank].get(i) is not None
                      and log.pcrs[bank][i] != pcrs.get(bank, {}).get(i)]
        replayed = not mismatched
        if mismatched:
            issues.append("event log does not replay to the quoted PCRs ("
                          + ", ".join(mismatched) + ")")
    return {
        "quoted_pcrs": sorted(f"{b}:{i}" for b, i in quoted),
        "pcr_digest_bound": bound,
        "pinned": sum(len(v) for v in pins.values()),
        "event_log_replays": replayed,
        "issues": issues,
        "passed": not issues,
    }


def check_tcb(quote: Quote, baseline: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    floor = baseline.get("min_firmware_version")
    if floor is None:
        issues.append("no TPM firmware floor (min_firmware_version) in the baseline")
    elif quote.firmware_version < int(floor):
        issues.append(f"TPM firmware 0x{quote.firmware_version:016x} is below the "
                      f"floor 0x{int(floor):016x}")
    return {"firmware_version": f"0x{quote.firmware_version:016x}",
            "min_firmware_version": floor, "issues": issues, "passed": not issues}


def check_secure_boot(quote: Quote, pcrs: dict[str, dict[int, bytes]], log: EventLog | None,
                      baseline: dict[str, Any]) -> dict[str, Any]:
    """The TPM analog of the SNP debug bit: was the host booted with Secure Boot off?

    The log's SecureBoot value only counts if the log replays to a quoted PCR 7;
    otherwise the host could hand over any log it likes.
    """
    if log is None:
        return {"secure_boot": None, "issues": [], "passed": None}
    quoted = {(bank, i) for bank, idx in quote.selection for i in idx}
    pcr7_bound = any(
        (bank, 7) in quoted and values.get(7) is not None
        and values[7] == pcrs.get(bank, {}).get(7)
        for bank, values in log.pcrs.items()
    )
    issues: list[str] = []
    if not pcr7_bound:
        issues.append("PCR 7 is not quoted or the event log does not replay to it, so "
                      "the log's Secure Boot state is unverified")
    elif log.secure_boot_unbound:
        issues.append("the SecureBoot event's data does not match its measured digest")
    elif log.secure_boot_conflict:
        issues.append("the event log measures SecureBoot more than once with "
                      "conflicting values")
    elif baseline.get("require_secure_boot", True) and log.secure_boot is not True:
        issues.append("event log shows Secure Boot disabled" if log.secure_boot is False
                      else "event log does not measure the SecureBoot variable")
    return {"secure_boot": log.secure_boot, "pcr7_bound": pcr7_bound,
            "issues": issues, "passed": not issues}


def check_nonce(quote: Quote, nonce: bytes | None) -> dict[str, Any]:
    if nonce is None:
        return {"extra_data": quote.extra_data.hex(), "issues": [], "passed": None}
    issues = []
    if len(nonce) < MIN_NONCE_BYTES:
        issues.append(f"nonce is {len(nonce)} bytes; at least {MIN_NONCE_BYTES} are "
                      "needed so it cannot be guessed")
    if quote.extra_data != nonce:
        issues.append("quote extraData does not carry the expected nonce; the quote "
                      "may be replayed")
    return {"extra_data": quote.extra_data.hex(), "issues": issues, "passed": not issues}
