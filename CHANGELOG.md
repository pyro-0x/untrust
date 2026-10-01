# Changelog

All notable changes to `untrust` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-09-30

Third platform: NVIDIA GPU Confidential Computing.

### Added

- **NVIDIA GPU Confidential Computing platform** (`--platform gpu-cc`, 18 checks)
  across both TEEs of a confidential-GPU deployment: report trust (ATT, MODE),
  verification (SIGVERIFY, CERT, RIM, REATTEST, FAILOPEN), attestation ordering
  (READY, CUDA), model inputs (MODEL probe, INPUT, DECRYPT), memory protection
  (VRAM, DMA), the CPU-side CVM and its binding to the GPU (CVM, BIND, VMM-META),
  and key/identity bypasses (KEY).
- **GPUCC-SIGVERIFY-01** checks a retained `nvattest` result: the receipt must
  match the raw output's digest and fields, and its nonce must equal the one
  nvattest ran with, so an old passing result cannot be replayed. The result's
  signed claims must name this report's GPU (`ueid`) and nonce, show a non-debug
  GPU, and a successful RIM appraisal.
- **GPUCC-CUDA-01** proves a CUDA kernel ran on the attested GPU after a
  successful attestation, through a hash-linked receipt chain.
- **Assurance tiers** on every GPU CC check (`report-derived`, `probed`,
  `operator-declared`). Report-derived passes are flagged when signature
  verification has not passed, and the console summary counts passes by tier.
- GPU CC target flags (`--gpu-attestation-report`, `--gpu-verifier-policy`,
  `--gpu-cc-mode`, `--gpu-kbs-policy`, `--gpu-model-bucket`,
  `--gpu-launch-config`) and boundary/assurance columns in `list-checks`.

### Fixed

- `--read-only` now applies on every platform: it also skips the canary-write
  bucket probes `GCS-BOOT-02` (sev-snp) and `GPUCC-MODEL-01` (gpu-cc), which
  previously ran regardless.
- `--platform` no longer offers `tdx`, which has no checks yet and crashed.
- `untrust --version` reports the package version (it was stuck at 1.0.0).
- Long check IDs no longer run into their summary in console output.
- GPUCC-RIM-01 fails a report that omits a required measurement instead of
  skipping it, and GPUCC-KEY-01 passes only an attestation-gated KBS as the DEK
  source (file, metadata, host, or an undeclared source now fail).

## [1.1.0] - 2026-08-30

Second cloud platform: AMD SEV-SNP on GCP Confidential Space.

### Added

- **SEV-SNP / GCP Confidential Space platform** (11 checks): attestation-bound
  key release (WIF attribute condition), Cloud KMS federation, bootstrap-bucket
  hardening plus an active injection probe, Confidential VM config, attestation
  token claims, and five Tier-1 attestation-bypass checks (metadata mutability,
  service-account impersonation, service-account keys, sibling WIF providers, and
  workload image signing).
- **Platform layer** (`untrust/platforms/`): a registry mapping each platform to
  its check set and demo; `nitro` resolves to the existing check set unchanged.
- **Injection-probe engine** (`untrust/probes/`) used by the GCS bootstrap probe.
- CLI `--platform {nitro,sev-snp}`, GCP target flags, and platform-aware
  `list-checks`.

### Changed

- The GCP client libraries (`google-api-python-client`, `google-cloud-storage`,
  `google-auth`) are now core dependencies, so a single `pip install untrust`
  provides both the AWS and GCP scanners.

## [1.0.0] - 2026-07-30

First public release.

### Added

- 33 AWS Nitro Enclave audit checks across eight categories: bootstrap &
  supply chain, object storage, KMS attestation, IAM & access control,
  network & host, host memory/persistence hygiene, enclave runtime, and
  detection & forensics.
- Alternative state-backend checks: DynamoDB (`DDB-01`), Secrets Manager
  (`SECRETS-01`), SSM Parameter Store (`SSM-01`), EFS/EBS (`EFS-01`), and
  RDS/Aurora (`RDS-01`).
- `--read-only` flag: run passive cloud-API checks only, skipping the
  `BOOTSTRAP-01` write probe and all host/enclave SSM command execution to
  avoid tripping SOC/EDR detections.
- CLI with `scan` and `list-checks` commands; `--demo` for a simulated
  vulnerable deployment (no AWS credentials needed); JSON output via
  `--output`/`--json`; `python -m untrust` support.
- MIT license.

### Fixed

- **KMS-01** resolves aliases to a canonical key id via `kms:DescribeKey`
  before calling `get_key_policy` (which rejects aliases), so the check works
  regardless of how the key is referenced.
- **BOOTSTRAP-01** treats any client-side (`4xx`) rejection of the
  path-traversal write probe — including a `400` from a bucket
  policy/encryption condition, not just `403 AccessDenied` — as
  **blocked (PASS)**. Only transient/server-side (`5xx`, throttling) failures
  are reported as `ERROR`.
- CMK detection for backend checks resolved authoritatively via
  `kms:DescribeKey` (`KeyMetadata.KeyManager`) instead of an alias-string
  heuristic that misread AWS-managed keys as customer CMKs.

### Research

Built from findings during an authorized adversarial simulation against a production TEE deployment. Presented at DEF CON 34 (August 2026): *"The Enclave Is Lying to You: Breaking TEE Trust Boundaries Through Boot-Time State."*
