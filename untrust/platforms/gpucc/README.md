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

## Checks (18)

| Check | Severity | What it verifies |
|-------|----------|------------------|
| **GPUCC-ATT-01** | critical | The captured attestation report asserts a trusted state: CC-On, non-debug, measurements present, a recognized GPU model, and a signed report |
| **GPUCC-RIM-01** | high | The verifier **pins the RIM golden measurements** (driver + VBIOS RIMs; GSP is inside the driver RIM), and **cross-checks the golden values** against the report when they are pinned |
| **GPUCC-CERT-01** | high | The device certificate chain is validated to the **NVIDIA on-die root of trust** |
| **GPUCC-SIGVERIFY-01** | critical | The attestation report signature is **cryptographically verified** against the GPU device key, not parsed-and-trusted |
| **GPUCC-REATTEST-01** | high | Attestation is **continuous** and re-runs on GPU state change (not attest-once-run-forever) |
| **GPUCC-FAILOPEN-01** | high | The verifier **fails closed** when attestation can't be checked (NRAS/RIM outage, verifier error) |
| **GPUCC-MODE-01** | high→critical | The GPU is **CC-On**, not **CC-DevTools** (debug) or CC-Off (deduped against ATT-01 when a report is present) |
| **GPUCC-READY-01** | critical | The workload **attests before toggling the GPU ready-state ON**, and key release is bound to a valid attestation |
| **GPUCC-CUDA-01** | high | A CUDA challenge kernel ran on the **same GPU UUID after successful `nvattest` verification**, with the raw-result → attestation-receipt → CUDA-receipt SHA-256 chain intact |
| **GPUCC-MODEL-01** | high | The **model/weights bootstrap store** rejects injection-shaped (path-traversal/absolute) object writes — actively probed |
| **GPUCC-INPUT-01** | high→critical | Model weights are **loaded safely** (safetensors / `weights_only=True` + signed, digest-verified manifest), never **deserialized as code** (pickle/`torch.load` = RCE on load) |
| **GPUCC-DECRYPT-01** | high | Model/data **decryption occurs inside the TEE**, not in untrusted host RAM (NVIDIA's documented plaintext-DEK gap) |
| **GPUCC-VRAM-01** | high | Hardware **VRAM encryption** is in effect |
| **GPUCC-DMA-01** | high | **CPU↔GPU DMA is encrypted** over an established SPDM secure session |
| **GPUCC-VMM-META-01** | high→critical | The untrusted host **cannot mutate the CVM/GPU launch** config/measurement (the metadata-mutability class) |
| **GPUCC-CVM-01** | high | The GPU is attached to a CVM with a **real, vendor-verified TDX/SEV-SNP quote** (not a self-asserted flag), non-debug, Secure Boot on |
| **GPUCC-BIND-01** | high→critical | The GPU attestation is **cryptographically bound to the CVM** measurement (the two TEEs can't be relayed/mixed-and-matched) |
| **GPUCC-KEY-01** | high→critical | The DEK / workload identity is **not an attestation bypass** (no host-env DEK, rotation on, no SA user-managed keys or impersonators) |

CVM-01 and BIND-01 came out of live red-team testing: a
confidential-GPU deployment is **two** TEEs (the H100 and the CPU TDX/SEV-SNP CVM),
and verifying only the GPU report — while never checking or binding the CPU-side
quote — lets a genuine GPU report be relayed onto an untrusted CPU context.

## Assurance tiers (how much a PASS means)

Each check carries an **assurance tier** (console output + JSON `assurance` field)
so a green result is read for what it is:

- **`report-derived`** (6: ATT/CUDA/VRAM/DMA/CVM/BIND) — read from retained runtime
  evidence and the GPU attestation
  report, trustworthy **only as far as the report's signature is verified**; each
  depends on `GPUCC-SIGVERIFY-01`, and a PASS is flagged **⚠ unverified-report**
  when that hasn't passed. `RIM-01` **promotes** itself into this tier when it
  cross-checks golden values.
- **`probed`** (1: MODEL-01) — actively tested against the live surface.
- **`operator-declared`** (11) — confirms only that an operator-authored policy
  *declares* the right thing; a lying policy passes.

The console reframes passes honestly (e.g. `Of the passes: 6 verified, 2
self-reported`), and `untrust list-checks --platform gpu-cc` shows each check's
**boundary** (`attestation`/`inputs`/`memory`/`vmm`/`cvm`).

## Chip families

The scanner reads the abstracted attestation-report + policy JSON, not raw silicon,
so it is **largely chip-agnostic** — ATT-01 recognizes the whole CC lineup
(`H100/H200/B100/B200/GH200/GB200`) and every deployment-boundary check is
independent of the GPU model. Three points are chip-family-sensitive and handled
explicitly:

- **RIM measurements** default to `driver + vbios` (verified live on **Hopper**;
  GSP is inside the driver RIM). Blackwell and multi-GPU NVLink domains (GB200 NVL)
  can carry more — a verifier policy overrides the set via `required_measurements`.
- **CVM CPU TEE** — CVM-01/BIND-01 accept x86 **Intel TDX / AMD SEV-SNP** *and*
  **ARM CCA** for NVIDIA Grace superchips (GH200/GB200), so a legitimate Grace
  confidential VM is not falsely failed.
- **Multi-GPU NVLink CC** (GB200 NVL72) adds NVSwitch/NVLink attestation and a
  multi-GPU binding dimension that is **not yet modeled** — single-GPU scope for now.

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
`--read-only` skips GPUCC-MODEL-01, the one check that writes (and then deletes)
canary objects in the model bucket. The model-store probe uses Cloud Storage.

### Evidence files

SIGVERIFY-01 and CUDA-01 read retained verifier output from the same directory
as `--gpu-attestation-report`:

| File | Holds | Read by |
|------|-------|---------|
| `verification.json` | Raw boot-time `nvattest` result: `command` (including `--nonce`) and `stdout_payload` | SIGVERIFY-01 |
| `runtime-attestation.json` | The runtime attestation receipt the CUDA receipt hash-links | CUDA-01 |
| `runtime-verification.json` | Raw runtime `nvattest` result, hash-linked from that receipt | CUDA-01 |

Each receipt must match its raw result's SHA-256, result code, claim count, and
detached EAT, and its nonce must equal the `--nonce` nvattest was run with, so
an old passing result cannot be replayed under a new receipt.

The raw result's single GPU claim set must also describe this report: its signed
`eat_nonce` equals the receipt nonce, its `ueid` equals the report's `gpu.ueid`,
`dbgstat` is `disabled`, and `measres` is `success`. A passing result from a
different GPU or attestation run therefore cannot vouch for the report, so the
normalized report must carry the attested device's `gpu.ueid`.

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
- **Nonce expiration windows and remote-verifier channel authentication** remain
  workload/key-release responsibilities. SIGVERIFY-01 validates the retained
  `nvattest` result and CUDA-01 validates the ordered runtime receipt chain, but
  neither turns mutable guest files into tamper-proof remote audit evidence.
