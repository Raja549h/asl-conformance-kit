# System Limits

ASL provides robust isolation but has known boundaries:

1. **Host-Level Boundaries (Windows):** Windows file ACLs do not protect against identical-user processes. ASL relies strictly on the container boundary.
2. **Audit Rollback:** Rolling back an audit log without a witness hash is a known limit.
3. **Forensic Erasure:** `asl wipe` deletes files and breaks cryptographic chains but does not securely shred disk sectors.
4. **Tool Compatibility:** External dependencies required by the agent must be pre-baked into the Docker image or proxied via the allowlist.
5. **Cyber Range (P2) — scripted attacks only.** The 15 attack classes in the cyber range are
   deterministic scripts that use the same standard-library client a real agent would. They
   measure whether the *mediated channel and the defenses behind it* stop a known attack
   class; they say nothing about what an unconstrained frontier model would do in the same
   harness. A real-model harness is a contributor task, not a claim.
6. **Cyber Range — kernel-level egress confinement is UNTESTED on native Windows, PROVEN under WSL2/Linux.** The range
   runs the agent through the process sandbox, and only a host with Linux network namespaces
   or bubblewrap can give the child *no IP route at all*. On native Windows the child keeps a
   direct loopback route; the report says so (`confinement: resource_only`) and every trial
   carries that note. What a Windows run proves is the mediated half of the claim; the kernel
   half is untested there. On Ubuntu 26.04 under WSL2 the kernel half **is** proven: all three
   `tests/test_egress_kernel.py` cases pass and `asl level` reports **L4.5 (Full Kernel +
   Mediated)** — see [kernel-confinement.md](kernel-confinement.md).
7. **Cyber Range — the range's own probe reaches the decoy.** To prove the trap is live the
   range itself fetches the decoy before the agent starts. That request is recorded and
   chain-verified, and it is excluded from breach scoring by a positional boundary rather
   than by a marker. The consequence: the decoy's log always holds at least one request, and
   only the agent-window requests are scored.
8. **Cyber Range — single-trial statistics.** The default run is one trial per class, so the
   95% bound is 3/1 = 3.0. The bound is arithmetic, not a claim of strength; 1,000 trials per
   class are needed before the number says anything.
9. **The campaign tripwire is a range defense, not a shipped one (P2c).** The tripwire that
   recognises a sweep, a credential spray, a large transfer and a listen/bind attempt lives in
   `src/asl/cyberrange/`, is installed only in the range's gateway, and is deliberately absent
   from the positive-control stub. It is **not** part of the product's mediated-egress path.
   Nothing here shows that a production deployment would have an equivalent; shipping a
   tripwire in the gateway itself is a contributor task, not a claim.
10. **The tripwire's thresholds are heuristics (P2c).** Six un-granted destinations, three
    credential-shaped requests, a 1 MiB body and a listen/bind path are chosen by hand. They are
    tested to fire and to stay quiet for the legitimate baseline, but the false-positive rate
    on a real workload is **UNTESTED**.
11. **The fake IoT devices are not real devices (P2c).** They answer four default credentials,
    serve six routes and hold a canary. A real fleet's behaviour — firmware versions,
    backdoors, UPnP quirks, credential reuse across models — is **UNTESTED**; the class models
    the *shape* of a spreading attack, not the difficulty of a real one.
12. **Time-to-detect measures the gateway, not an operator (P2c).** It is the interval until
    the safety layer refused something or recognised a pattern. The time for a *human* to
    notice is **UNTESTED**.
13. **Covert-channel leakage is measured for one payload (P2c).** The rate comes from a single
    fixed covert payload and the request logs. Whether another payload shape leaks faster is
    **UNTESTED**.
14. **The output channel is not yet on the product's tool-call path (P2.5b).** The `OutputChannel`
    exists and is tested, and the covert channels are measured closed *for the channel*. The
    product's tool-call path still returns its own responses, so the measured bits-per-second
    describe the channel, not the whole product. Wiring it in is a contributor task, not a claim.
15. **Read-only workspaces are advisory on native Windows (P2.5b).** The file mode is set
    read-only, but Windows does not stop the same user from writing anyway. The real guarantee is
    the digest re-check: the environment recomputes the workspace digest and reports a run that
    wrote into it. Kernel-enforced read-only mounts are **UNTESTED** here.
16. **Model weight read-only enforcement is UNTESTED (P2.5b).** The environment *denies* a run
    whose backend cannot make the weight paths read-only, and that denial is tested. Whether a
    real backend can make them read-only is **UNTESTED**: the shipped backend reports that it
    cannot, so the denial path is what runs.
17. **The hardware kill actuator and the hardware heartbeat sink are interface only, UNTESTED
    (P2.5b).** There is no hardware here to test them against. The software actuator and the
    file sink are tested; a hardware adapter is a research tier (L5+), not a claim.
18. **The watchdog bounds a plug-in but does not preempt it (P2.5b).** A hanging actuator or
    sanitizer is abandoned on a daemon thread, which keeps the safety layer responsive but does
    not stop the runaway code. Preemption is **UNTESTED**.
19. **The bucketed denial timing is coarse (P2.5b).** Refusals are quantised into 50 ms
    buckets, so a refusal is not constant-time: an observer can still distinguish a refusal
    inside one bucket from one that crossed a boundary. The claim is that the *reason* is not
    distinguishable, not that the timing is perfectly flat.
20. **The unix-socket half of the external signal adapter is UNTESTED on this host (P2.5b).**
    This Windows host has no `AF_UNIX`, so the file-drop path is exercised and the socket path
    skips with an explicit reason.
21. **Real-model multi-agent swarm is UNTESTED (P4).** The 700-agent simulator uses deterministic
    scripted agents; it says nothing about what a frontier multi-agent model would do in the same
    harness. A real-model swarm harness is a contributor task, not a claim.
22. **The swarm simulator's fixed attack catalog (P4).** The six scripted attack scenarios (S01–S06)
    are deterministic scripts that measure whether the *swarm controls and the defenses behind them*
    stop a known attack class; they say nothing about what an unconstrained colluding model would
    do. A smarter attacker might find attack shapes outside these six families: **UNTESTED**.
23. **The swarm campaign tripwire thresholds are heuristics (P4).** Six un-granted destinations,
    three credential-shaped requests, 50 concurrent queue-flooding agents, and per-agent step/message/spend/covert-bit
    budgets are chosen by hand. They are tested to fire and to stay quiet for the legitimate baseline,
    but the false-positive rate on a real workload is **UNTESTED**.

