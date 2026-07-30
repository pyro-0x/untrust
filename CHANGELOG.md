# Changelog

All notable changes to `untrust` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Expanded to 33 checks across eight categories, including full host and
  enclave-runtime coverage (PORT-01, EXEC-01, VSOCK-01, CORE-01, SWAP-01,
  LOG-01, RESTART-01, ENCLAVE-01/02/03/04, S3-01/02, ROLLBACK-01,
  CLOUDTRAIL-01, VPC-01).
- Alternative state-backend checks: DynamoDB (`DDB-01`), Secrets Manager
  (`SECRETS-01`), SSM Parameter Store (`SSM-01`), EFS/EBS (`EFS-01`), and
  RDS/Aurora (`RDS-01`).
- `--read-only` flag: run passive cloud-API checks only, skipping the
  `BOOTSTRAP-01` write probe and all host/enclave SSM command execution to
  avoid tripping SOC/EDR detections.

### Fixed

- **KMS-01** now resolves aliases to a canonical key id via `kms:DescribeKey`
  before calling `get_key_policy` (which rejects aliases), so the check works
  regardless of how the key is referenced.
- **BOOTSTRAP-01** now treats any client-side (`4xx`) rejection of the
  path-traversal write probe — including a `400` from a bucket
  policy/encryption condition, not just `403 AccessDenied` — as
  **blocked (PASS)**. Only transient/server-side (`5xx`, throttling) failures
  are reported as `ERROR`.
- CMK detection for backend checks resolved authoritatively via
  `kms:DescribeKey` (`KeyMetadata.KeyManager`) instead of an alias-string
  heuristic that misread AWS-managed keys as customer CMKs.

## [1.0.0] - 2026-08-07

### Added

- Twelve AWS Nitro Enclave audit checks across six categories:
  - **BOOTSTRAP-01** — S3 path traversal in bootstrap state download (critical)
  - **BOOTSTRAP-02** — S3 bucket policy does not restrict PutObject (high)
  - **KMS-01** — KMS key policy missing `RecipientAttestation` conditions (high)
  - **IMDS-01** — EC2 instance does not enforce IMDSv2 (high)
  - **IAM-01** — Instance role has wildcard resources on S3/KMS actions (high)
  - **SSH-01** — SSH daemon running or EC2 Instance Connect installed (high)
  - **NAT-01** — IMDS reachable from enclave via NAT bridge (medium)
  - **HOST-01** — Sensitive files (EIF, keys, env) are world-readable (medium)
  - **HOST-02** — Enclave systemd services run as root (medium)
  - **ENV-01** — Dangerous host-supplied environment variables, semantic validation of infrastructure config, and world-readable config (medium)
  - **DNS-01** — Host DNS DNAT rules redirect enclave DNS queries (low)
  - **AUDIT-01** — S3 bucket versioning and logging disabled (low)
- CLI with `scan` and `list-checks` commands
- `--demo` flag for running against a simulated vulnerable deployment (no AWS credentials needed)
- JSON output via `--output` and `--json` flags
- `python -m untrust` support
- MIT license

### Research

Built from findings during an authorized adversarial simulation against a production TEE deployment. Presented at DEF CON 34 (August 2026): *"The Enclave Is Lying to You: Breaking TEE Trust Boundaries Through Boot-Time State."*
