# untrust — AMD SEV-SNP (GCP Confidential Space)

The v2.0 platform. Same thesis as the Nitro auditor: **attestation proves the
code, but not what you hand the code at boot, nor who you let ask for the keys.**
On GCP Confidential Space a workload proves itself with an attestation token and
exchanges it — through Workload Identity Federation (WIF) — for Cloud KMS access.
The token and hardware are sound; the *deployment* around them is where the
trust boundary leaks.

## Checks

| Check | Severity | What it verifies | Nitro analog |
|-------|----------|------------------|--------------|
| **CSPACE-KEYBIND-01** | high | The WIF provider's attribute condition binds key release to a code measurement — requires `dbgstat == 'disabled-since-boot'` **and** a pinned `image_digest`, not just identity | KMS-01 |
| **CSPACE-KMS-01** | high→critical | Cloud KMS decrypt is granted only to a `principalSet://…/workloadIdentityPools/…` member (federated through attestation), never `allUsers`/`allAuthenticatedUsers` or a plain service account | KMS-01 / IAM-01 |
| **GCS-BOOT-01** | high→critical | Bootstrap bucket enforces public-access prevention + uniform bucket-level access, scopes object-write to the workload, and has versioning + a retention policy | BOOTSTRAP-02 / S3-01 / ROLLBACK-01 / AUDIT-01 |
| **GCS-BOOT-02** | high | Active probe: the bootstrap bucket rejects injection-shaped object writes (path-traversal / absolute-path names a careless boot consumer could join onto a local path) | BOOTSTRAP-01 |
| **CSPACE-VM-01** | high | Instance is a real Confidential VM with Secure Boot, vTPM, and integrity monitoring, on a TEE Confidential Space can attest: AMD SEV or Intel TDX (Google's attestation service rejects SEV-SNP with `UNSUPPORTED_CC_TECHNOLOGY`; SEV-SNP passes only for a plain Confidential VM) | ENCLAVE-02 |
| **CSPACE-ATT-01** | critical | A captured attestation token asserts `disabled-since-boot`, a signed image, a non-USABLE (production) Confidential Space image, and AMD SEV hardware | ENCLAVE-01 / ENCLAVE-04 |
| **CSPACE-META-01** | high→critical | No broad/impersonatable principal can rewrite the Confidential VM's `tee-image-reference` / `tee-cmd` / `tee-env-*` metadata — otherwise an attacker runs their own code *as* the attested workload | — |
| **CSPACE-SA-01** | high→critical | The workload service account cannot be impersonated (`serviceAccountTokenCreator` / `actAs` / `workloadIdentityUser`) to mint tokens and reach KMS/GCS with no attestation | IAM-01 |
| **CSPACE-SAKEY-01** | high | The workload service account has no long-lived user-managed keys (a stolen key bypasses attestation permanently) | — |
| **CSPACE-WIF-02** | high | Every provider in the workload identity pool binds Confidential Space attestation — no weaker sibling provider offers a lateral key-release path | — |
| **CSPACE-IMG-01** | high | Workload image signing is enforced (`tee-signed-image-repos` set), the image is digest-pinned, and the Artifact Registry repo is not broadly writable | ENCLAVE-03 |

Each check splits into a pure `analyze_*()` function (unit-tested, no I/O) and a
thin live-fetch wrapper, mirroring how the Nitro checks separate logic from the
AWS SDK call.

## Usage

Demo (no GCP credentials needed):

```bash
untrust scan --platform gcp-cspace --demo
untrust list-checks --platform gcp-cspace
```

Live scan (requires Application Default Credentials with read access to the
resources):

```bash
untrust scan --platform gcp-cspace \
  --gcp-project my-proj \
  --wip-provider projects/123/locations/global/workloadIdentityPools/POOL/providers/PROV \
  --gcp-kms-key projects/my-proj/locations/global/keyRings/RING/cryptoKeys/KEY \
  --gcs-bucket my-workload-state \
  --gcp-instance workload-vm --gcp-zone us-central1-a \
  --attestation-token ./captured-token.jwt \
  --output report.json
```

Any single `--…` target is enough; checks whose inputs are absent report SKIP.

## Required GCP permissions (read-only)

- `iam.workloadIdentityPoolProviders.get` — CSPACE-KEYBIND-01
- `cloudkms.cryptoKeys.getIamPolicy` — CSPACE-KMS-01
- `storage.buckets.get`, `storage.buckets.getIamPolicy` — GCS-BOOT-01
- `compute.instances.get` — CSPACE-VM-01
- CSPACE-ATT-01 consumes a token file you capture from the workload; no API call.

## Scope / limitations (in the honest-scanner tradition)

- **Token signature/freshness** — CSPACE-ATT-01 inspects *claims*. Verifying the
  token's RS256 signature against Google's Confidential Space JWKS and checking
  `aud`/`exp`/`nonce` belongs in the workload's key-release code, not a deploy
  auditor.
- **Live GCS canary write** (the active BOOTSTRAP-01 path-traversal probe) is not
  yet ported; GCS-BOOT-01 currently audits bucket config + IAM only.
- **Bare-metal SEV-SNP** (direct VCEK→ASK→ARK report verification via AMD KDS,
  KBS-based key release) is a separate surface, not covered here.
