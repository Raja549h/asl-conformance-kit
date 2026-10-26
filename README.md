# ASL Conformance Kit

A public, **source-free** verification kit for the Agent Safety Layer (ASL): the
language-neutral conformance vectors, the public exploit benchmark bundles and
their signed receipts, the signed evidence reports, and the invariants — all
checkable by a third party without access to the engine.

**This repository contains no files from `src/asl/`.** It ships only artifacts
that can be re-checked, not the implementation that produced them.

## Quickstart

```bash
python conformance/verify_vectors.py
```

That runs the **second, independently written verifier** (standard library only,
zero `asl` imports) against every conformance vector, prints
`checked 31 vector cases, 0 failures`, and exits `0`.

## Executive summary

| Metric | Value |
|---|---|
| Trusted core (TCB) | **2,998 lines** across 11 stdlib-only modules (budget 3,000) |
| AST mutation kill rate | **97.7%** — 585 / 599 mutants; all 14 survivors proven *equivalent* |
| Public exploit containment | **250 / 250** contained — **250/250** breach the `--vulnerable` control, **0/250** breach ASL |
| Gate trials | **0 / 16,000** breaches — dev `0/11,000` (16 classes × 1,000) + blind `heldout_v2` `0/5,000` (5 classes × 1,000) |
| Positive control | **160** breaches — the range is proven *able* to detect |
| 700-agent swarm | **0** breaches, **0** false alarms; `S01`–`S06` collusion all contained |
| Fault injection | all paths fail closed |
| Kernel-level egress confinement | **PROVEN** on Ubuntu 26.04 / WSL2 — 3/3 tests; a `unshare --net` child has **no route at all** while the mediated channel still returns a real `200` |
| Conformance vectors | 5 files, **31 cases**, verified by a second stdlib-only implementation |
| Invariants | **48** numbered invariants (+3 P-rows, +8 mutation rows = 59 claims), each mapped to the tests that check it |
| **Earned level** | **L4.5 (Full Kernel + Mediated)** where Linux namespaces exist; **L4.5 (Architecture Verified)** on native Windows |

## What is in here

| Path | What it is |
|---|---|
| `conformance/verify_vectors.py` | Standalone stdlib-only verifier (no `asl` imports) |
| `conformance/vectors/*.json` | Language-neutral fixtures: canonical JSON, argument hashing, token mint/verify, audit chain, `X-ASL-Attestation` |
| `conformance/benchmarks/*.json` | Five public exploit bundles, 50 payloads each (250 total) |
| `conformance/benchmarks/receipts/*.json` | Five signed, path-free tester receipts (submission SHA-256 + per-payload verdicts) |
| `docs/invariants.md` | The 48 numbered invariants and the containment-levels table |
| `docs/signed-evidence-report.json` / `.md` | The HMAC-SHA256-signed level report — the **Linux/WSL2** run, `L4.5 (Full Kernel + Mediated)` |
| `docs/signed-evidence-report-windows.json` / `.md` | The **native Windows** run, kept verbatim: `L4.5 (Architecture Verified)` |
| `docs/kernel-confinement.md` | The kernel-confinement proof: the three tests, the host, and the exact reproduction steps |
| `docs/public-benchmark-report.md` | The 250-payload benchmark result table |
| `docs/threat-model.md`, `docs/limits.md` | Threat model, and the honest limits (what is *not* claimed) |
| `STATUS.md` | Feature-by-feature build status through P7 |

## What this proves — and what it does not

This kit proves the **measurement**: the vectors are language-neutral and pass a
second, independently written verifier; the benchmark receipts are signed,
path-free and reproducible offline; and the level report is *derived* from the
evidence files rather than asserted — it **fails closed** on missing, tampered
or breaching evidence.

It also now proves the **kernel half** of the containment claim, on a host that
can provide Linux namespaces: under Ubuntu 26.04 / WSL2 all three
`tests/test_egress_kernel.py` cases pass, so a confined child has no IP route at
all and only the mediated channel remains. That is what moves the level from
*Architecture Verified* to **L4.5 (Full Kernel + Mediated)** — see
`docs/kernel-confinement.md`.

It does **not** claim kernel confinement on **native Windows**, where no Linux
namespace is available; the Windows report in this kit says
`can_deny_egress: False` and stays at *L4.5 (Architecture Verified)*. The other
deliberate gaps — real-model agents and swarms, the hardware actuator and
heartbeat sink, eBPF telemetry, the `asl witness --auto` shorthand — are listed
in `docs/limits.md`.

## Reproducing the numbers

1. **Vectors** — `python conformance/verify_vectors.py`.
2. **Receipts** — recompute each receipt's `submission_sha256` from the matching
   bundle's payloads to confirm the signed receipt corresponds to the published
   bundle, and verify the receipt's HMAC-SHA256 signature.
3. **Containment** — `docs/invariants.md` maps every claim to the exact test that
   checks it; that map is the reproduction path for the containment numbers.
4. **Kernel confinement** — the four commands in `docs/kernel-confinement.md`
   install a WSL2 Ubuntu, install bubblewrap, and run the three tests.
