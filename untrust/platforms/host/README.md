# Host attestation platform (`--platform host`)

Offline verification of host attestation evidence against a pinned baseline.
It supports AMD SEV-SNP attestation reports and TPM 2.0 quotes. Intel TDX is
not supported yet.

The verdict logic is a library call with no scanner dependencies:

```python
from untrust.platforms.host.verify import load_baseline, load_evidence, verify

verdict = verify(load_evidence("evidence.json"), load_baseline("baseline.json"), nonce)
verdict.allowed      # fail closed: every control must have passed
verdict.to_dict()    # per-control pass/fail, issues, and evidence
```

The six `HOST-*` checks wrap the six controls one to one, so a service can
reuse the same decisions the scanner reports.

## Controls

| Check | Control | SEV-SNP | TPM2 |
|---|---|---|---|
| HOST-CHAIN-01 | chain | VCEK/VLEK → ASK → ARK (RSA-PSS), root fingerprint pinned | AK → CA, issuers must be CA certs, root fingerprint pinned |
| HOST-SIG-01 | signature | ECDSA P-384 over bytes `0x000–0x29F`; report versions 2–3 only; rejects `MASK_CHIP_KEY`, a missing or reserved `SIGNING_KEY`, and a cert that is not the kind of key the report names | `TPMT_SIGNATURE` (ECDSA, RSASSA, RSAPSS) over `TPMS_ATTEST`; rejects SHA-1; the AK cert must carry the TCG AK EKU `2.23.133.8.3` unless `require_ak_eku` is false |
| HOST-NONCE-01 | nonce | `REPORT_DATA` equals the nonce (at least 16 bytes), exact or zero-padded to 64 bytes | `extraData` equals the nonce (at least 16 bytes) |
| HOST-DEBUG-01 | debug | Policy DEBUG and MIGRATE_MA bits clear; optional `max_vmpl`, `min_policy_abi`, `allow_smt`, `require_single_socket` | Event log measures the global (EFI_GLOBAL_VARIABLE GUID) `SecureBoot=1` in PCR 7, exactly once or consistently, the event data hashes to its digest, and PCR 7 is quoted and replays |
| HOST-TCB-01 | tcb | `REPORTED_TCB` ≥ `min_tcb` per component, equal to the VCEK's TCB extensions, VCEK hwID equals `CHIP_ID`; optional `min_guest_svn` | `firmwareVersion` ≥ `min_firmware_version`; optional `require_clock_safe`; clock `safe`, reset and restart counts reported |
| HOST-MEAS-01 | measurement | `MEASUREMENT` in the pinned list; optional `host_data` pin | Supplied PCRs hash to the quoted `pcrDigest`, pinned PCRs are quoted and match, event log replays to the quoted PCRs |

A missing nonce, or a TPM quote without an event log, leaves that control
**unassessed**. The scanner reports it as SKIP and `verdict.allowed` is false.
A missing baseline pins nothing, so the chain, TCB, and measurement controls
FAIL. No check passes by default.

Every control reads from the evidence, so each one depends on HOST-SIG-01.
HOST-SIG-01 in turn depends on HOST-CHAIN-01. If a dependency fails, the runner
marks a PASS as resting on unverified evidence.

## Evidence manifest (`--host-evidence`)

Paths are relative to the manifest. `certs` lists the chain leaf first, and one
file may hold several PEM certificates.

```json
{"type": "sev-snp", "report": "report.bin", "certs": ["vcek.pem", "cert_chain.pem"]}
```

```json
{"type": "tpm2", "quote": "quote.msg", "signature": "quote.sig", "pcrs": "pcrs.json",
 "certs": ["ak.pem", "ak-ca.pem"], "event_log": "binary_bios_measurements"}
```

Capturing evidence:

- **SEV-SNP:** `snpguest report report.bin request.bin` with the nonce in the
  request file. Then `snpguest fetch ca pem milan .` and
  `snpguest fetch vcek pem milan . report.bin`, or the same files from AMD KDS.
- **TPM2:** `tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,5,6,7 -q NONCE -m quote.msg -s quote.sig`.
  Sign the AK cert with the TCG AK EKU, for example
  `openssl x509 -new -force_pubkey ak.pem -addext extendedKeyUsage=2.23.133.8.3 ...`.
  Write the PCRs as `{"sha256": {"0": "<hex>", ...}}`. The event log is
  `/sys/kernel/security/tpm0/binary_bios_measurements`.

## Baseline (`--host-baseline`)

```json
{
  "sev-snp": {
    "trusted_roots_sha256": ["<sha256 of the AMD ARK DER for your product>"],
    "measurements": ["<96 hex chars>"],
    "min_tcb": {"bootloader": 4, "tee": 0, "snp": 22, "microcode": 213},
    "min_guest_svn": 1, "max_vmpl": 0, "host_data": "<64 hex chars>",
    "min_policy_abi": {"major": 1, "minor": 51}, "allow_smt": true,
    "require_single_socket": false
  },
  "tpm2": {
    "trusted_roots_sha256": ["<sha256 of your AK CA DER>"],
    "pcrs": {"sha256": {"0": "<hex>", "7": "<hex>"}},
    "min_firmware_version": 0,
    "require_secure_boot": true,
    "require_ak_eku": true, "require_clock_safe": false
  }
}
```

Set `min_tcb` from AMD's current security bulletin for the platform. The
values above are placeholders.

## Known gaps

- **Synthetic tests only.** The parsers are written from the SEV-SNP ABI and the
  TCG specs, and the tests use evidence signed with throwaway keys. Nothing has
  been checked yet against a report from real SNP hardware or a quote from a
  real TPM.
- **No revocation checks.** AMD's ASK/VCEK CRL is not checked, and neither are
  AK CA CRLs.
- **Older SNP layout only.** `TCB_VERSION` is decoded with the Milan/Genoa
  layout. Turin adds an FMC field and a different byte order.
- **No VLEK hardware ID.** VLEK-signed reports carry no hardware ID, so the
  `CHIP_ID` binding applies to VCEK reports only.
- **TPM gaps.** There is no EK-based AK provenance (credential activation is
  trusted to the CA that issued the AK cert). The AK EKU shows the CA
  vouched for a restricted attestation key, but until EK-based provenance
  exists, a CA that certifies an unrestricted key enables forged quotes,
  because such a key can sign any blob that starts with `TPM_GENERATED_VALUE`. `qualifiedSigner` is not compared
  to the AK name, and only the `SecureBoot` variable is interpreted from the
  event log.
