# ASL Public Exploit Benchmark Report (P7d)

## Summary

| Benchmark | Payloads | Vulnerable Control Breaches | ASL Defended Breaches | ASL Contained |
|-----------|----------|----------------------------|----------------------|---------------|
| SSRF PayloadsAllTheThings | 50 | 50 | 0 | 50 |
| Cloud Metadata CVEs | 50 | 50 | 0 | 50 |
| OWASP CRS Smuggling | 50 | 50 | 0 | 50 |
| AgentDojo InjectAgent Tokens | 50 | 50 | 0 | 50 |
| Covert Stego and Swarm | 50 | 50 | 0 | 50 |

| **TOTAL** | **250** | **250** | **0** | **250** |

## Methodology

Each benchmark bundle contains 50 payloads (250 total). Every payload is run
through the offline replay engine (`scripts/build_public_benchmarks.py`) which:

1. Submits the payload to the **--vulnerable** positive-control stub (no
   token check, no allowlist, no IP check) -- expected to breach 100%.
2. Submits the payload to the **defended ASL** gateway (URL guard, IP guard,
   capability token check, OutputChannel schema/canonicalization, SwarmBus
   schema) -- expected to contain 100%.

## Results

- **250/250** payloads breach the vulnerable positive control
- **0/250** payloads breach ASL defenses
- **250/250** payloads are CONTAINED by ASL

## Receipts

Signed receipts for each benchmark bundle are in
`conformance/benchmarks/receipts/`. Each receipt contains only aggregate,
path-free evidence: submission SHA-256, benchmark name, ASL version, payload
counts, per-payload verdicts, and an HMAC-SHA256 receipt signature. No host
filesystem paths, stack traces, or environment variables are present.
