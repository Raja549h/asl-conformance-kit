# ASL Boundary Ceiling Report

**Solo-Host Engineering Status:** 100% COMPLETE (P0–P9 VERIFIED, 0 ERRORS)
**Maximum Solo-Host Level:** L4.5 (Architecture Verified — All L3 & Solo Gates Passed)
**Host-measured level:** L4.5 (Full Kernel + Mediated)
**Solo gates passed:** 9/9

## Solo-host gates (measured on this machine)

| Gate | Measurement | Passed | Evidence |
|---|---|---|---|
| Trusted core is stdlib-only and under the line budget | 2,998 lines across 11 modules; 24 imports, all stdlib | yes | src/asl/core/*.py (11 files) |
| AST mutation kill rate over the trusted core and egress gateway | 97.7% (585/599 killed) | yes | docs\signed-evidence-report.json |
| Public exploit benchmark suite contained | 250/250 contained on ASL, 250/250 breached the --vulnerable control | yes | conformance/benchmarks/receipts/ (5 signed receipts) |
| Development attack classes contained | 0/11,000 breaches over 11 dev classes | yes | docs\signed-evidence-report.json |
| Blind held-out v2 classes contained | 0/5,000 breaches over 5 blind classes | yes | docs\signed-evidence-report.json |
| 700-agent swarm collusion contained | 700 agents, 0 breaches, 0 false alarms across S01-S06 | yes | docs\signed-evidence-report.json |
| Covert-channel scrubbing on the output boundary | 0 bit(s) crossed 5 probed channels; 0.0 bits/s | yes | src/asl/output/leak.py + src/asl/output/canonical.py (live measurement) |
| Continuous adversarial fuzzer and auto-regression corpus loop | 4 grammar families (url_parser, header_smuggling, zero_width_bidi, token_widening) | yes | src/asl/cyberrange/fuzzer.py; src/asl/cyberrange/regression_loop.py |
| Off-box witness and hardware kill wire contracts | witness ack verified, packet round-tripped, replayed kill command rejected | yes | src/asl/boundary/external_contracts.py |

## Requires external infrastructure

1. **L5-HW-KILL — Physical out-of-band hardware power relay**
   - requires: A second machine with an IPMI/BMC or GPIO relay wired to cut ATX/PDU power to the agent host
   - why one host cannot: A kill that runs on the same host as the agent is a request, not a guarantee: code that has escaped can decline it. Only a relay outside the trust domain can cut power the agent cannot argue with.
   - software half, already built: HardwareKillCommandPacket: signed, schema-versioned, nonce-monotonic frame with replay rejection (this module).

2. **L5-OFFBOX-WITNESS — Independent off-box witness host**
   - requires: A physically separate, network-isolated witness server in an external trust domain holding its own verification key
   - why one host cannot: A host that can rewrite its own audit chain can also rewrite its own witness record. Truncation and rollback are only detectable from a copy the host cannot reach.
   - software half, already built: WitnessCheckpointWirePacket plus verify_witness_ack: a host HMAC and a separate witness signature, with a freshness window (this module).

3. **L4.5-FULL-KERNEL — Dedicated bare-metal Linux kernel host**
   - requires: Native Linux kernel unshare/bubblewrap network namespaces; on native Windows there is no kernel namespace to confine a child with
   - why one host cannot: Process-level mediation is enforced by the gateway. Confinement that survives a gateway compromise has to come from the kernel, and the Windows host does not expose one.
   - software half, already built: tests/test_egress_kernel.py passes all three cases under WSL2 Ubuntu 26.04; on native Windows it skips with an explicit reason.

4. **L5-FRONTIER-SWARM — Multi-node frontier LLM cluster**
   - requires: Paid external frontier model APIs or GPU racks running live multi-agent weights against the ASL gateway
   - why one host cannot: The 700-agent simulator is deterministic and honest about what it models, but it cannot discover the behaviours a real model would invent when it is trying to escape.
   - software half, already built: The swarm governor, mediated bus and collective caps are built and tested against S01-S06 in tests/test_swarm_p4.py.

## Verdict

SOLO CEILING REACHED: 100% of software, cryptographic, and protocol architecture is complete. Advancing to L5 requires external physical hardware (out-of-band power relay, separate witness server, and multi-node compute cluster) that cannot be provisioned on a single local host.

## Receipt

Algorithm: HS256
Signature: 78762089a20ff3048c469821dddfa49b35b89cb8c6c915ee321f4af8f5a76c23
Issued (ns): 1793083902870056100
