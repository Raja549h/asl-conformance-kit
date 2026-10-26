# ASL Conformance Kit

Public verification surface for the **Agent Safety Layer (ASL)**. It ships **no** implementation
code from `src/asl/` — only the language-neutral conformance vectors, the public exploit-benchmark
evidence and the signed reports, so a third party can re-check ASL's claims without reading the
trusted computing base.

## Verify in one line

```bash
python conformance/verify_vectors.py
```

A stdlib-only second verifier with **no `asl` imports** re-checks every conformance vector —
canonical JSON, argument hashing, token mint/verify (signed under a clearly-labelled FAKE test
key), audit-chain entries and checkpoints, and containment attestations — and exits **non-zero**
on any mismatch.

## Headline results

| Claim | Result | Evidence |
|-------|--------|----------|
| Invariants, each mapped to a passing test | **48+** (I1–I48) | [`docs/invariants.md`](docs/invariants.md) |
| Trusted core — stdlib-only, single boundary | **2,998 lines** (budget **< 3,000**) | [`docs/invariants.md`](docs/invariants.md) |
| AST mutation kill rate (`src/asl/core/` + `src/asl/egress/`) | **97.7%** — **585/599** | [`docs/signed-evidence-report.md`](docs/signed-evidence-report.md) |
| Public exploit benchmark suite | **250/250 contained** — `250/250` breach the `--vulnerable` control, `0/250` breach ASL | [`docs/public-benchmark-report.md`](docs/public-benchmark-report.md) |
| L3/L4 evidence-gate trials | **0 breaches / 16,000** — dev `0/11,000` + blind `heldout_v2` `0/5,000` | [`docs/signed-evidence-report.md`](docs/signed-evidence-report.md) |
| Earned containment level | **L3 achieved**, and **L4.5 (Architecture Verified)** | [`docs/signed-evidence-report.md`](docs/signed-evidence-report.md) |

## What is in here

- [`conformance/vectors/`](conformance/vectors) + [`conformance/verify_vectors.py`](conformance/verify_vectors.py) — language-neutral fixtures and the standalone verifier.
- [`conformance/benchmarks/`](conformance/benchmarks) — the 250-payload public exploit suite (5 bundles × 50) and its signed tester receipts.
- [`docs/`](docs) — the invariants, the signed evidence report, the public benchmark report, the threat model and the system limits.
- [`STATUS.md`](STATUS.md) — phase-by-phase build status through **P7e**.

## Honest limits

These are measurements, not guarantees. Kernel-level egress confinement is **UNTESTED** on a
native Windows host (no WSL, Docker, `unshare` or `bwrap`), so the signed level is *L4.5
(Architecture Verified)* and **not** *L4.5 (Full Kernel + Mediated)*; real-model agents and the
hardware kill actuator / heartbeat sink are **UNTESTED**. See [`docs/limits.md`](docs/limits.md)
and [`docs/threat-model.md`](docs/threat-model.md).
