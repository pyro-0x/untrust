# Changelog

All notable changes to `untrust` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
