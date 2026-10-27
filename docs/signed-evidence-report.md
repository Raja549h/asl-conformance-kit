# ASL Signed Evidence Report

**Containment Level:** L4.5 (Full Kernel + Mediated)
**Issued At:** 1793086592.5287817

## Evidence Summary

- [x] L3: 0 dev-class breaches across 11 classes x 1000 trials
- [x] L3: 0 heldout_v2 breaches across 5 classes x 1000 trials
- [x] L3: positive control breaches = 160 (range detects)
- [x] L4.5: evolutionary soak — 0 breaches against real gateway
- [x] L4.5: 700-agent swarm — 0 breaches, 0 false alarms
- [x] L4.5: fault injection — all paths fail closed
- [x] L4.5: mutation kill rate = 97.7% (>= 95%)
- [x] kernel namespace confinement detected

## Host Capabilities

- platform: linux
- resource_limits: True
- network_namespace: True
- bubblewrap: True
- job_objects: False
- can_deny_egress: True

## Breach Counts by Gate

- dev: 0
- heldout_v2: 0
- positive_control: 160
- evolution_defended: 0
- swarm_700: 0
- fault_all_closed: 0
- mutation_kill_rate: 0.9766277128547578

## Signature

Algorithm: HMAC-SHA256
Signature: 143649b6cb45019c8575cf837f3369e72e2e0a69b92d3bb9eb69654fc5d8ea50