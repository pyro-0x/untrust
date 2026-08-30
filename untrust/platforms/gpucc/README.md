# untrust — NVIDIA GPU Confidential Computing (`gpu-cc`)

The v1.2 platform. Same thesis as the Nitro and Confidential Space auditors,
sharpened for confidential AI: the GPU hardware root-of-trust and its signed
attestation report are sound, but the *deployment* leaks along the three
boundaries attestation does not cover — the untrusted **inputs** the workload
loads (model weights, data), the **runtime memory** those secrets pass through,
and the untrusted **VMM/host** that controls the launch.

**Threat model (per NVIDIA):** the host OS, hypervisor/VMM, cloud provider, boot
firmware, SMM, and peripheral devices are all untrusted, and the adversary may
read host system memory. The H100/H200 in CC-On protects VRAM (hardware
encryption) and PCIe traffic (encrypted bounce buffers), and signs an attestation
report — but only if the deployment actually verifies it and keeps secrets inside
the boundary.

## Checks (v1 — 11)

| Check | Severity | What it verifies |
|-------|----------|------------------|
| **GPUCC-ATT-01** | critical | The captured attestation report asserts a trusted state: CC-On, non-debug, measurements present, a recognized GPU model, and a signed report |
| **GPUCC-RIM-01** | high | The verifier **pins the RIM golden measurements** (VBIOS, GSP firmware, driver), not identity-only |
| **GPUCC-CERT-01** | high | The device certificate chain is validated to the **NVIDIA on-die root of trust** |
| **GPUCC-MODE-01** | high→critical | The GPU is **CC-On**, not **CC-DevTools** (debug) or CC-Off |
| **GPUCC-READY-01** | critical | The workload **attests before toggling the GPU ready-state ON**, and key release is bound to a valid attestation |
| **GPUCC-MODEL-01** | high | The **model/weights bootstrap store** rejects injection-shaped (path-traversal/absolute) object writes — actively probed |
| **GPUCC-DECRYPT-01** | high | Model/data **decryption occurs inside the TEE**, not in untrusted host RAM (NVIDIA's documented plaintext-DEK gap) |
| **GPUCC-VRAM-01** | high | Hardware **VRAM encryption** is in effect |
| **GPUCC-DMA-01** | high | **CPU↔GPU DMA is encrypted** over an established SPDM secure session |
| **GPUCC-VMM-META-01** | high→critical | The untrusted host **cannot mutate the CVM/GPU launch** config/measurement (the metadata-mutability class) |
| **GPUCC-CVM-01** | high | The GPU is attached to a **verified Confidential VM** (Intel TDX / AMD SEV-SNP), non-debug, Secure Boot on |

Fast-follow (☆): GPUCC-REVOKE-01 (revocation), GPUCC-NONCE-01 (report freshness),
GPUCC-VERIFIER-01 (authenticate the NRAS verdict), GPUCC-INPUT-01 (untrusted
launch env/args), GPUCC-MEMHYG-01 (CVM core-dump/swap), GPUCC-VMM-DEVICE-01
(attestation binds the specific GPU), GPUCC-AUDIT-01 (log GPU trust decisions).

Each check splits into a pure `analyze_*()` function (unit-tested, no I/O) and a
thin live-fetch wrapper, mirroring how the Nitro and sev-snp checks separate
logic from the SDK/host call.

## Usage

Demo (no GPU, driver, or evidence needed):

```bash
untrust scan --platform gpu-cc --demo
untrust list-checks --platform gpu-cc
```

Analyze captured evidence (file-based — the primary path):

```bash
untrust scan --platform gpu-cc \
  --gpu-attestation-report report.json \
  --gpu-verifier-policy policy.json \
  --gpu-cc-mode on \
  --gpu-kbs-policy kbs.json \
  --gpu-launch-config launch.json \
  --gpu-model-bucket my-model-weights \
  --output report-out.json
```

Any single target flag is enough; checks whose inputs are absent report `SKIP`.

## Environment & dependencies

Deployment targets: **Azure NCC H100 v5** (CVM on an Intel TDX host + H100 NVL,
joint Intel-signed attestation), **GCP A3 confidential** (H100 SXM, Intel TDX +
Hopper CC), and on-prem SEV-SNP/TDX hosts with a CC-capable NVIDIA driver.

Live checks draw on: GPU-node command access (`nvidia-smi conf-compute -f`) for
CC mode/session; a captured **NVIDIA attestation report (JSON)** from the NVIDIA
Attestation SDK / local Verifier / NRAS for the A-group; the relying party's
verifier and key-release **policy** files; and cloud control-plane read access
(reusing the underlying CVM platform's credentials) for the model store, launch
config, and KMS/KBS policy. The `analyze_*` core needs **no** extra Python
dependency; live seams lazy-import `nv-attestation-sdk` / `nvidia-ml-py` and are
not bundled into core.

## Scope / limitations (deliberately not checked)

These threats are real but need guest-OS hardening, silicon, or runtime
introspection a deployment auditor cannot test:

- **Runtime hypervisor microarchitectural attacks** — interrupt injection
  (HECKLER), malicious `#VC` (WeSee), single-stepping (SEV-Step), performance-
  counter side channels (CounterSEVeillance), ciphertext side channels. These
  live in the guest `#VC`/interrupt-handling code and the silicon layer.
- **Plaintext RPC headers / physical-address-table** metadata, **application
  defects inside the CVM**, and **physical attacks** — all out of NVIDIA's CC
  scope.
- **Signature / nonce freshness verification** of the attestation report belongs
  in the workload's key-release code; GPUCC-ATT-01 inspects the report's claims.
