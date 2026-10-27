# ASL Conformance Kit

A public, **source-free** verification kit for the Agent Safety Layer (ASL): the
language-neutral conformance vectors, the public exploit benchmark bundles and
their signed receipts, the signed evidence and ceiling reports, and the
invariants — all checkable by a third party without access to the engine.

**This repository contains no files from `src/asl/`.** It ships only artifacts
that can be re-checked, not the implementation that produced them.

## Quickstart

```bash
python conformance/verify_vectors.py
```

That runs the **second, independently written verifier** (standard library only,
zero `asl` imports) against every conformance vector, prints
`checked 45 vector cases, 0 failures`, and exits `0`.

## Executive summary

| Metric | Value |
|---|---|
| Trusted core (TCB) | **2,998 lines** across 11 stdlib-only modules (budget 3,000) |
| AST mutation kill rate | **97.7%** — 585 / 599 mutants; all 14 survivors proven *equivalent* |
| Public exploit containment | **250 / 250** contained — **250/250** breach the `--vulnerable` control, **0/250** breach ASL |
| Gate trials | **0 / 16,000** breaches — dev `0/11,000` (11 dev classes × 1,000) + blind `heldout_v2` `0/5,000` (5 classes × 1,000) |
| Positive control | **160** breaches — the range is proven *able* to detect |
| 700-agent swarm | **0** breaches, **0** false alarms; `S01`–`S06` collusion all contained |
| Fault injection | all paths fail closed |
| Covert channels | **0 bits/s** across 5 probed channels on the output boundary |
| Continuous fuzzing (P8) | 4 grammar families, seeded and bounded; the auto-regression corpus is minimised, promoted atomically and replayed against the live gateway |
| Solo-host ceiling (P9) | **9 / 9** solo gates measured and passing; 4 physical dependencies named as outside one host |
| Kernel-level egress confinement | **PROVEN** on Ubuntu 26.04 / WSL2 — 3/3 tests; a `unshare --net` child has **no route at all** while the mediated channel still returns a real `200` |
| Conformance vectors | 6 files, **45 cases**, verified by a second stdlib-only implementation |
| Invariants | **52** numbered invariants (I1–I52, no gaps) plus the mutation and level rows, each mapped to the tests that check it |
| **Earned level** | **L4.5 (Full Kernel + Mediated)** where Linux namespaces exist; **L4.5 (Architecture Verified)** on native Windows |

## What is in here

| Path | What it is |
|---|---|
| `conformance/verify_vectors.py` | Standalone stdlib-only verifier (no `asl` imports) |
| `conformance/vectors/*.json` | Language-neutral fixtures: canonical JSON, argument hashing, token mint/verify, audit chain, `X-ASL-Attestation`, and the **P9 external boundary** (witness checkpoint + hardware kill command, positive *and* negative cases) |
| `conformance/benchmarks/*.json` | Five public exploit bundles, 50 payloads each (250 total) |
| `conformance/benchmarks/receipts/*.json` | Five signed, path-free tester receipts (submission SHA-256 + per-payload verdicts) |
| `docs/invariants.md` | The numbered invariants through P9, and the containment-levels table |
| `docs/signed-evidence-report.json` / `.md` | The HMAC-SHA256-signed level report — the **Linux/WSL2** run, `L4.5 (Full Kernel + Mediated)` |
| `docs/signed-evidence-report-windows.json` / `.md` | The **native Windows** run, kept verbatim: `L4.5 (Architecture Verified)` |
| `docs/boundary-ceiling-report.json` / `.md` | The **P9 ceiling**: nine measured solo gates, the four physical dependencies, and the sealed verdict |
| `docs/kernel-confinement.md` | The kernel-confinement proof: the three tests, the host, and the exact reproduction steps |
| `docs/public-benchmark-report.md` | The 250-payload benchmark result table |
| `docs/threat-model.md`, `docs/limits.md` | Threat model, and the honest limits (what is *not* claimed) |
| `STATUS.md` | Feature-by-feature build status through P9 |

## What this proves — and what it does not

This kit proves the **measurement**: the vectors are language-neutral and pass a
second, independently written verifier; the benchmark receipts are signed,
path-free and reproducible offline; and the level report is *derived* from the
evidence files rather than asserted — it **fails closed** on missing, tampered
or breaching evidence.

It also proves the **kernel half** of the containment claim, on a host that can
provide Linux namespaces: under Ubuntu 26.04 / WSL2 all three
`tests/test_egress_kernel.py` cases pass, so a confined child has no IP route at
all and only the mediated channel remains. That is what moves the level from
*Architecture Verified* to **L4.5 (Full Kernel + Mediated)** — see
`docs/kernel-confinement.md`.

The **P9 ceiling report** draws the line this project cares most about. Nine
gates are properties of the code and are measured on one machine: TCB size and
stdlib purity read from source, the mutation score, five signed benchmark
receipts, the dev and blind trial counts, the swarm, a live covert-channel
measurement, the P8 fuzzer, and a round-trip self-test of the boundary wire
contracts. Four dependencies are **not** software and no amount of local testing
closes them:

| Dependency | What it requires |
|---|---|
| `L5-HW-KILL` | A physical second machine with an IPMI/BMC or GPIO relay wired to cut ATX/PDU power |
| `L5-OFFBOX-WITNESS` | A network-isolated witness host in an external trust domain holding its own key |
| `L4.5-FULL-KERNEL` | Native Linux kernel `unshare`/`bubblewrap` namespaces (absent on native Windows) |
| `L5-FRONTIER-SWARM` | Paid frontier model APIs or GPU racks running live multi-agent weights |

The P9 wire contracts are the *software half* of the first two: a witness
checkpoint signed with the host key and acknowledged with a **different** witness
key, and a kill command whose monotonic nonce makes a captured frame worthless.
Their vectors — including the negative ones — are in this kit, so the formats can
be implemented against independently. No hardware has been exercised: the
contracts are tested, the relay and the witness host do not exist here.

It does **not** claim kernel confinement on **native Windows**, where no Linux
namespace is available; the Windows report in this kit says
`can_deny_egress: False` and stays at *L4.5 (Architecture Verified)*. The other
deliberate gaps — real-model agents and swarms, the hardware actuator and
heartbeat sink, eBPF telemetry, the `asl witness --auto` shorthand — are listed
in `docs/limits.md`.

## Reproducing the numbers

1. **Vectors** — `python conformance/verify_vectors.py`.
2. **Boundary wire formats** — the same command: `conformance/vectors/boundary_v1.json`
   carries 13 cases, seven of which *must* be rejected (tampered HMAC, unknown
   schema, duplicate key, replayed nonce), so a port that accepts them fails.
3. **Receipts** — recompute each receipt's `submission_sha256` from the matching
   bundle's payloads to confirm the signed receipt corresponds to the published
   bundle.
4. **Containment** — `docs/invariants.md` maps every claim to the exact test that
   checks it; that map is the reproduction path for the containment numbers.
5. **Ceiling** — `docs/boundary-ceiling-report.md` lists each solo gate with its
   measurement and the artifact it was read from, and the four dependencies it
   refuses to claim.
6. **Kernel confinement** — the four commands in `docs/kernel-confinement.md`
   install a WSL2 Ubuntu, install bubblewrap, and run the three tests.
