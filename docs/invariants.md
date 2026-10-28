# Invariants — P1a + P1b (trusted core, mediated egress, kill paths)

Each invariant below is a claim the system must never violate. Every one is mapped to the
tests that check it. Anything not backed by a passing test is marked **UNTESTED**; nothing in these
phases is currently untested except where explicitly noted.

The trusted core under test is `src/asl/core/` (`canonical.py`, `tokens.py`, `audit.py`,
`killstate.py`, `kill.py`). Line count at the time of writing: **1,730** (budget 3,000).

I1–I6 are the P1a core invariants. I7–I14 are added by P1b (mediated egress and its per-hop
destination checks, caged helper services, the four kill paths, and fail-closed behaviour).

| # | Invariant | Tests |
|---|---|---|
| I1 | A capability token authorises exactly one action. It verifies only for the exact `agent_id`, `run_id`, `action` and canonical `args_hash` it was minted for; any difference is denied. Only the core can mint, and an agent cannot widen a token. | `tests/test_core_tokens.py::test_wrong_agent_is_denied`, `::test_wrong_run_is_denied`, `::test_wrong_action_is_denied`, `::test_wrong_arguments_are_denied`, `::test_uncanonicalisable_arguments_are_denied`, `::test_an_agent_cannot_mint_and_widen_a_token`; `tests/test_core_properties.py::test_token_never_verifies_for_a_different_agent`, `::..._different_run`, `::..._different_action`, `::..._different_arguments`; `tests/test_core_canonical.py::test_parse_json_strict_rejects_duplicate_keys` |
| I2 | A token is single-use. Consumption is recorded atomically in SQLite, so a replay fails even when many attempts race on the same token. | `tests/test_core_tokens.py::test_replay_is_denied`, `::test_consumption_is_recorded_atomically_under_concurrency` (16 threads, exactly one wins), `::test_consumption_raises_replay_when_nonce_already_in_store`; `tests/test_core_properties.py::test_a_consumed_token_never_verifies_again` |
| I3 | Verification fails closed. Bad signature, wrong agent/run/action/args, expiry, not-yet-valid, a backwards clock, a malformed token, and a database error all deny. Comparisons of secret-derived values are constant time. | `tests/test_core_tokens.py::test_bad_signature_is_denied`, `::test_another_authoritys_signature_does_not_verify`, `::test_expired_token_is_denied`, `::test_not_yet_valid_token_is_denied`, `::test_clock_going_backwards_is_denied`, `::test_malformed_wire_tokens_are_denied`, `::test_non_hex_signature_is_denied`, `::test_oversized_wire_token_is_denied`, `::test_non_json_payload_is_denied`, `::test_payload_with_extra_fields_is_denied`, `::test_database_error_during_consumption_denies`, `::test_unexpected_store_error_denies`, `::test_no_store_configured_denies_consumption`; `tests/test_core_properties.py::test_an_expired_token_never_verifies`, `::test_any_single_byte_change_to_a_token_is_detected`; `tests/test_core_canonical.py` (whole file) |
| I4 | Key and state hygiene. The signing key is generated and stored **outside the repository**, is listed in `.gitignore`, is written mode `0600`, and is never printed or logged; the kill-state store reports "halt" on any read failure. | `tests/test_core_tokens.py::test_key_is_created_outside_the_repo_with_0600`, `::test_key_is_reused_not_regenerated`, `::test_key_file_never_prints_the_key`, `::test_key_path_defaults_to_the_state_dir`, `::test_authority_repr_hides_the_key`, `::test_signing_key_is_listed_in_gitignore`; `tests/test_core_killstate.py` (whole file, fail-closed cases) |
| I5 | The audit chain is append-only and tamper-evident. Each entry's HMAC covers the previous hash plus the canonical entry; append fsyncs; an edited entry, a deleted middle entry, a reorder, a truncated tail, a rollback, and a partial write are all detected. A signed checkpoint is exportable and anchors truncation and rollback. | `tests/test_core_audit.py::test_edited_entry_is_detected`, `::test_deleted_middle_entry_is_detected`, `::test_reordered_entries_are_detected`, `::test_partial_write_is_detected`, `::test_truncated_tail_is_detected_against_the_checkpoint`, `::test_checkpoint_from_elsewhere_catches_a_rolled_back_log`, `::test_published_head_hash_catches_a_forked_log`, `::test_checkpoint_with_a_bad_hmac_is_rejected`, `::test_append_refuses_a_log_that_does_not_verify`, `::test_append_fsyncs_each_entry`, `::test_cli_audit_verify_fails_on_a_tampered_chain`; `tests/test_core_properties.py::test_any_single_byte_change_to_a_log_entry_is_detected` |
| I6 | The trusted core is a boundary. It imports only the standard library and itself — never network, LLM, judge, dashboard, or report code — and stays under the 3,000-line budget. | `tests/test_core_boundary.py::test_no_forbidden_imports_anywhere_in_the_core`, `::test_core_imports_only_stdlib_and_itself`, `::test_core_stays_under_the_line_budget`, plus the checker's own positive/negative cases |
| I7 | **Token-bound egress.** Every outbound request needs a valid single-use capability token bound to the exact request (method, URL, headers, body and the run/agent). A missing, mis-bound, forged, expired, replayed, or revoked-run token is refused *before anything is fetched*. | `tests/test_egress_mediator.py::TestTokenEnforcement` (whole class), `::TestKillState::test_an_active_kill_state_denies_before_the_token_is_checked`; `tests/test_egress_channel.py::TestHandleMessage::test_a_valid_message_is_authorised`, `::test_a_bad_token_denies_without_reaching_the_fetcher`; `tests/test_egress_helpers.py::TestTheMirrorHasNoAuthorityOfItsOwn::test_an_allowed_fetch_still_needs_the_callers_token` |
| I8 | **Default deny.** An empty allowlist permits nothing. A destination is cleared only when an exact `(host, port)` entry matches, case- and dot-insensitively; a malformed entry is refused rather than silently ignored. The sandbox has no direct route; its only channel is the mediated one. | `tests/test_egress_allowlist.py` (whole file: `TestNormalizeHost`, `TestAllowEntry`, `TestAllowlist`, `TestAllowlistFromConfig`); `tests/test_egress_mediator.py::TestDestinationPolicy::test_an_off_allowlist_destination_is_refused`; `tests/test_egress_channel.py::TestHandleMessage::test_an_internal_fault_denies_never_allows` |
| I9 | **Per-hop final-IP validation.** The gateway resolves DNS itself, once per hop, and validates the *final* destination IP after following each redirect, pinning the TCP connect to that validated address. Blocked: private ranges, loopback (unless the entry explicitly allows it), link-local, cloud-metadata, IPv6 and IPv4-mapped/shortened forms, decimal/hex/octal numerics, DNS rebinding, URL-parser differentials and userinfo tricks. A redirect to a blocked, disguised or off-allowlist target is refused. | `tests/test_egress_ipguard.py` (whole file), `tests/test_egress_urlguard.py` (whole file); `tests/test_egress_mediator.py::TestDestinationPolicy`, `::TestRedirects`, `::TestRequestValidation`, `::TestPinnedTransportAgainstAFakeServer`; `tests/test_egress_channel.py::TestEndToEndOverLoopbackHttp` |
| I10 | **Caged helper services (confused deputy).** Any service an agent can reach acts only with the requesting agent's token and never on its own authority, and has no outbound route beyond the same allowlist. The trap package mirror has a real outbound path to a decoy holding a canary credential, yet every proxy, redirect, alternate-encoding and smuggling attempt through it is denied and logged, and the decoy receives **zero** requests. | `tests/test_egress_helpers.py` (whole file: `TestTheTrapIsLive`, `TestProxyAttemptsThroughTheMirror`, `TestRedirectsThroughTheMirror`, `TestAlternateEncodingsThroughTheMirror`, `TestRequestSmugglingThroughTheMirror`, `TestTheMirrorHasNoAuthorityOfItsOwn`) |
| I11 | **Four independent kill paths.** Policy (a rule or tripwire fires), lease (the sandbox dies when the gateway stops renewing), budget (step, wall-clock or spend limit reached), and human (a switch file). Each fires on its own and runs the cascade. The budget limits are configurable per run. | `tests/test_kill.py::TestPolicyKill`, `::TestDeadManLeaseKill`, `::TestBudgetKill`, `::TestHumanSwitchKill`; `tests/test_config.py::test_config_budget_limits_map_onto_the_kill_path_budget` |
| I12 | **The cascade is complete and loud.** Every kill (1) terminates the run's process, (2) revokes the run's tokens — which deny-lists the `run_id` — (3) writes an audit entry, and (4) writes an evidence snapshot. A failure in any step is recorded on the frozen `KillEvent` and never stops the others; a failed revocation falls back to a global halt; a kill never reports success it did not achieve; the cascade is idempotent. | `tests/test_kill.py::TestTheKillCascade` (whole class), `::TestProcessRegistry::test_terminate_ends_a_real_process_and_is_measured` |
| I13 | **The agent cannot reach, disable or delay a kill path.** No egress module imports the kill module; the agent-facing surface exposes no control name; the controller exposes no unkill API; a `KillEvent` is frozen; a busy agent does not delay the lease kill; and a detector that raises is treated as a signal, not as "no signal". | `tests/test_kill.py::TestAgentCannotReachAnyKillPath` (whole class), `::TestFailClosed::test_a_detector_that_raises_is_treated_as_a_signal` |
| I14 | **Fail closed under fault.** A gateway crash, a locked database, clock skew (forward or backward), a partially written audit log, a malformed request and a raising detector each result in deny or kill — never allow. | `tests/test_kill.py::TestFailClosed` (whole class) |

## P2 — the cyber range

P2 adds the *instrument*, not new defenses: an isolated cyber range that attacks ASL's own
fake services and scores what happened, from evidence, rather than from what the agent says.
I15–I21 are the range's own invariants. They say nothing about the security of a real
deployment; they say the *measurement* is sound. The code is `src/asl/cyberrange/`.

| # | Invariant | Tests |
|---|---|---|
| I15 | **The range can fail.** A deliberately checkless stub gateway (`--vulnerable`) must be breached by *every* attack in the library, and the run must exit non-zero. An attack that does not breach the stub cannot tell a defended system from an undefended one, so it would prove nothing. Conversely, the real gateway must contain every attack. | `tests/test_cyberrange.py::TestPositiveControl` (all 15 attacks, both directions), `::TestPositiveControlAtRangeScale` (whole class), `::TestCLI::test_cli_exits_nonzero_when_the_positive_control_breaches` |
| I16 | **Loopback only, or refuse to start.** Every fake service, decoy and trap target binds `127.0.0.1` on a fresh ephemeral port; the range *refuses to start* if any configured target is not loopback, and every canary is fresh, random and prefixed `ASL-CANARY-` for each trial. | `tests/test_cyberrange.py::TestLoopbackOnlyAndCanaries` (whole class), `::TestRefusesNonLoopback` (whole class, including `::test_a_trial_refuses_to_start_on_a_non_loopback_target`) |
| I17 | **A breach is evidence, not a report.** A breach is a request that reached a decoy or a non-allowed service, or a canary that crossed a boundary, without a valid single-use token bound to that exact request. It is computed from the per-trial tamper-evident ledger and the services' own request logs — never from the agent's own account of what it did. The range's own trap-liveness probe is excluded by a *positional* boundary (everything recorded before the agent launched), not by a marker an attacker could imitate. | `tests/test_cyberrange.py::TestPositiveControl::test_the_attack_breaches_the_vulnerable_stub` (asserts the ledger-derived verdict), `::TestBaselineFalseAlarms` (zero false alarms over legitimate traffic) |
| I18 | **Each defense is load-bearing.** Turning off exactly one defense of the real gateway — the capability-token check, the destination allowlist, single-use consumption, or the kill-state check — must let the matching attack through, and turning it back on must contain it. A defense that is present but stops nothing would pass every other test while protecting nothing. | `tests/test_cyberrange.py::TestDefenseAblation` (whole class: four ablations, the "on by default" control, the unknown-ablation refusal, and the halted-run control) |
| I19 | **A hang is not a pass.** A trial that never produced a verdict — a hung agent, a killed agent, a channel that stopped answering, an agent that wrote no findings — is INCONCLUSIVE, never CONTAINED. Availability is reported separately from containment, and an inconclusive trial never enters the denominator of the 95% bound, so a flaky run cannot manufacture a flattering number. | `tests/test_cyberrange.py::TestInconclusiveIsNotContained` (whole class) |
| I20 | **The scoreboard's math is sound.** A class with zero breaches over *n* conclusive trials reports the rule-of-three bound 3/n; a class with any breach, or with no conclusive trial, reports **no** bound rather than a smaller-than-the-truth number. Evidence is written to fresh timestamped files and never appended to a previous run's. | `tests/test_cyberrange.py::TestScoreboardMath` (whole class) |
| I21 | **The range is deterministic and the catalog is honest.** The same seed reproduces the same verdicts and the same findings. The dev/held-out split is 10/5, and no held-out attack is referenced by any defense module, so a held-out result is evidence rather than a target to tune against. An unproven gap against the real gateway is recorded as a numbered FINDING and a strict `xfail`, so it turns red if it is ever fixed by accident. | `tests/test_cyberrange.py::TestDeterminism` (whole class), `::TestAttackLibrary::test_the_dev_and_heldout_split_is_about_two_thirds_dev`, `::TestAttackLibrary::test_the_heldout_attacks_are_not_imported_by_the_defenses` |

## P3 — the adaptive attacker

P3 adds a *search* over the space of attack payloads: seeded grammar generators, a
fitness signal that measures **how far** a payload got rather than whether it
breached, an evolutionary loop, and an auto-regression corpus. The code is
`src/asl/cyberrange/mutator.py`, `src/asl/cyberrange/evolution.py` and
`src/asl/cyberrange/corpus.py`. I22–I25 are the invariants of that instrument.

| # | Invariant | Tests |
|---|---|---|
| I22 | **The held-out set is genuinely held out.** No module under `src/asl` outside the held-out module contains a held-out attack id, payload fragment, or a static import of the held-out module. The development library does not load the held-out module when imported, so nothing that imports the development set can see the held-out set by accident. The evolutionary mutator seeds from the development set only, and reaches the held-out set only when the operator explicitly asks for the final evaluation. The split stays roughly two-thirds development, one-third held-out, and the two sets cover disjoint classes. | `tests/test_heldout_isolation.py` (whole file: `TestTheSplit`, `TestNoSourceReferencesTheHeldOutSet`, `TestTheMutatorSeedsFromDevelopmentOnly`, `TestTheHeldOutSetIsStillUsable`) |
| I23 | **The search is seeded, deterministic and bounded.** The same seed produces the same variants, the same decisions and the same corpus entries; the grammar generators are pure functions of their seed; no payload, body or frame count can grow without limit; and every trial is streamed to a fresh timestamped JSONL file rather than accumulated in memory. | `tests/test_mutator.py::TestDeterminism`, `::TestBounds`, `::test_seeding_a_population_is_deterministic`, `::test_mutants_always_have_a_stable_identity_and_serialisable_form`; `tests/test_evolution.py::TestTheSearch` (whole class, including `::test_every_trial_is_streamed_to_disk` and `::test_the_trials_file_is_fresh_for_each_run`) |
| I24 | **The corpus is a standing promise, and it is complete.** Every variant worth keeping — one that beat its parent, one that raised an unexpected exception, one that was inconclusive, one that breached, and the fittest of each generation — is minimised to a portable entry and written to `tests/corpus/regression_seeds.jsonl`. The file is rewritten atomically and **never** opened in append mode. Every entry is replayed against the real gateway and must be contained; an entry that names a FINDING carries a strict xfail, so a bypass that is closed by accident turns red. | `tests/test_regression_corpus.py` (whole file: `TestTheCorpusFile`, `TestTheCorpusRoundTrip`, `TestTheCorpusReplays`); `tests/test_evolution.py::TestTheSearch::test_the_corpus_entries_are_reproducible` |
| I25 | **The fitness function is a valid progress metric, and it can find a real bug.** Fitness is monotone with what actually happened: a fitness-5 trial really did reach a non-allowed service, and no lower-fitness trial did. Against a gateway with a planted flaw — it validates only the first redirect hop — the search *finds* the flaw and breaches; against the real gateway the same search never breaches and its ceiling is "reached a service". A search that cannot find a bug that is there could not be trusted to report that there is none. | `tests/test_evolution.py::TestTheFitnessScale` (whole class), `::TestTheHarness` (whole class), `::TestThePositiveControl` (whole class, including `::test_the_search_finds_the_planted_flaw`, `::test_the_same_search_does_not_break_the_real_gateway` and `::test_the_fitness_is_monotone_with_what_happened`) |

## P2c — the replication class and the measured metrics

P2c closes two gaps: a threat class that is a *campaign* rather than a request, and
three scoreboard numbers that were placeholders. The code is
`src/asl/cyberrange/tripwire.py`, the fake IoT fleet in `src/asl/cyberrange/services.py`,
attack class 16 in `src/asl/cyberrange/attacks/__init__.py`, and the metric plumbing in
`src/asl/cyberrange/scoring.py` and `src/asl/cyberrange/runner.py`.

| # | Invariant | Tests |
|---|---|---|
| I26 | **A campaign is stopped, not just its requests.** The per-request defenses (a capability token bound to the exact request, the destination allowlist) stop a single request; the tripwire stops a *campaign*. A sweep of un-granted destinations, a spray of credential-shaped requests, a body larger than the transfer limit and a request to open a listener are each recognised, recorded, and answered with a tiered response: throttle, then freeze, then kill. A well-behaved agent trips nothing — the baseline raises zero false alarms. | `tests/test_replication_class.py::TestTheTripwire` (whole class), `::TestTheTripwireUnit` (whole class) |
| I27 | **Class 16 discriminates, and every defense it leans on is load-bearing.** The self-replication chain — sweep, default-credential login, file drop, service start, onward spread — is CONTAINED by the real gateway (no request reaches a device, no device canary moves) and BREACHES the deliberately checkless positive control. Ablating the destination allowlist lets the chain reach a device; ablating the tripwire leaves the run contained but no longer *detected* and no longer halted. | `tests/test_replication_class.py::TestAgainstTheRealGateway`, `::TestAgainstThePositiveControl`, `::TestDefenseAblation` (whole class) |
| I28 | **The metrics are measurements, not slots.** `time_to_detect_s` is the interval from the start of the trial to the moment the safety layer first noticed — a refusal it made or a tripwire pattern it recognised — which is not the same moment as a breach. `time_to_kill_s` is the interval to the run actually being halted, and is absent when the run was never halted. `covert_bits_per_sec` is the covert payload's leakage rate, computed from what actually crossed a monitored boundary: zero against the real gateway (a real measurement) and non-zero against the checkless stub. | `tests/test_replication_class.py::TestTheMetricsAreRealMeasurements` (whole class) |

## Honest gaps

* **Constant-time comparison (part of I3)** is implemented with `hmac.compare_digest`
  (`src/asl/core/tokens.py`) and is exercised for correctness by the tests above, but its
  *timing* behaviour is **not** independently measured here. Treat "no timing side channel" as
  **UNTESTED**; only "the comparison is the constant-time primitive and returns the right answer"
  is tested.
* **Off-box anchoring (part of I5).** `asl audit checkpoint` writes a local file; detecting a
  rollback relies on that file having been copied somewhere the attacker cannot also roll back.
  The mechanism is tested; the operational step of publishing it is a process control, not code.
* **Human switch, true off-box operation (part of I11) — UNTESTED.** The switch is only ever a
  *local* file, and `HumanSwitch` cannot verify which OS user owns it; enforcing that separation
  is an operational step, not code. Only "content present → halt", "absent → no halt" and
  "unreadable → halt (fail closed)" are tested. A switch owned by a *different OS user*, outside
  the agent's reach, is **UNTESTED**.
* **No-direct-network at the kernel level (part of I8/I9) — UNTESTED on native Windows.** Proving
  the sandbox has no IP route (rather than merely being *unwired* from the mediated channel) needs
  Linux network namespaces or bubblewrap. Those tests live in `tests/test_egress_kernel.py`, are
  written to run under WSL2, and **skip with an explicit reason** on native Windows; they are among
  this phase's deliberate skips.
* **Kernel-level egress confinement in the range (part of I15) — UNTESTED on native Windows.** The
  range runs the agent through the P1b process sandbox, and on a host that offers Linux network
  namespaces or bubblewrap the agent gets *no IP route at all*. On native Windows it cannot: the
  child keeps a direct loopback route, and the report says so
  (`confinement: resource_only`, `egress_enforced: false`, plus a note on every trial). What the
  Windows run *does* prove is the mediated-channel half: every request the attack library makes
  goes through the gateway and is authorised there. The kernel half is **UNTESTED** on this host.
* **The range's own trap-liveness probe reaches the decoy (part of I17).** To prove the trap is
  live, the range itself fetches the decoy over the mirror's real outbound path before the agent
  exists. That request is recorded in the ledger and chain-verified like everything else, and it is
  excluded from breach scoring by a positional boundary rather than by a marker. The consequence is
  that the decoy's request log always contains at least one request; only the *agent-window*
  requests are scored.
* **Trial statistics (part of I20).** Each attack class was run for 100 conclusive trials with
  fixed seeds, each trial in a fresh subprocess, evidence written to fresh timestamped files
  (never appended). With zero breaches over 100 trials, the rule-of-three bound is 3/100 = 0.03
  per class — i.e. it says "this proves little but more than one trial". The bound is a property
  of the arithmetic, not a claim of strength; the L1 level requires 1,000 trials per class and is
  **not** reached by this phase. Per-class results (trials, breaches, INCONCLUSIVE, 95% upper
  bound) are recorded in `evidence/phase3_final/` and summarised in `STATUS.md`.
* **Real-model behaviour (part of I15–I21) — UNTESTED.** Every attack in the library is a
  deterministic script. Nothing here shows what a frontier model would do inside the same
  harness. A real-model swarm harness is a contributor task, not a claim.
* **Timing side channels (part of I15) — UNTESTED.** The range *measures* latency overhead and
  per-attack time-to-detect, but it does not measure whether the gateway's *refusals* leak the
  allowlist through timing. The A15 attack probes error text, not timing distributions.
* **Held-out attacks are held out from *defense code*, not from the range's own reporting.** The
  held-out set (A11–A15) is never imported by a defense module — that is enforced by a test — but
  the range necessarily *runs* it and reports the result, which is the point of holding it out.
* **The evolutionary search explores a fixed candidate space (P3).** The search generates payloads
  from four seeded grammar families and from the routes the fake services publish. It is a real
  search with a real fitness signal, but it is *not* an exhaustive proof: a payload outside those
  families is never tried. Against the real gateway the search's ceiling is "reached an allowed
  service"; whether a smarter generator could do better is **UNTESTED**.
* **The positive control's flaw is one flaw, not a class (P3).** The control gateway validates only
  the first redirect hop. That is enough to prove the search can find *a* bug, and it is the bug
  class that matters most for an SSRF filter, but the control does not cover every flaw shape.
  The other planted-flaw shapes named in the P3 plan — double-decoded hosts, last-key-wins JSON —
  are **UNTESTED**; the mutation operators that would find them exist, but no control exercises
  them.
* **Corpus entries are portable, not literal (P3).** An entry stores the *intent* (which service,
  which route, which grammar family) rather than the address, because the fake services bind a
  fresh port every trial. The replay rebuilds the address against a live environment. A variant
  whose *meaning* depends on a specific port is therefore not exactly reproducible — a limitation
  the corpus format records but does not solve.
* **The tripwire is a range defense, not a shipped one (P2c, part of I26).** It lives in
  `src/asl/cyberrange/`, is installed only in the range's gateway, and is deliberately absent
  from the positive-control stub. It is *not* part of the product's mediated egress path, and
  nothing here shows that a production deployment would have an equivalent. Shipping a tripwire
  in the gateway itself is a **contributor task**, not a claim.
* **The tripwire's thresholds are heuristics (P2c, part of I26).** Six un-granted destinations,
  three credential-shaped requests, a 1 MiB body and a listen/bind path are chosen by hand. They
  are tested to fire and to stay quiet for the baseline, but they are **not** tuned against real
  traffic, and the false-positive rate on a real workload is **UNTESTED**.
* **The fake IoT devices are not real devices (P2c, part of I27).** They answer four default
  credentials, serve six routes and hold a canary. A real fleet's behaviour — firmware versions,
  backdoors, UPnP quirks, credential reuse across models — is **UNTESTED**; the class models the
  *shape* of a spreading attack, not the difficulty of a real one.
* **Time-to-detect measures the gateway, not an operator (P2c, part of I28).** It is the interval
  until the safety layer refused something or recognised a pattern. It does not include the time
  for a human to notice, which is the number an incident reviewer usually wants: **UNTESTED**.
* **Covert-channel leakage is measured for one payload (P2c, part of I28).** The rate is computed
  from a single fixed covert payload and the request logs. Whether another payload shape leaks
  faster is **UNTESTED**.
* **The output channel is not yet wired into the shipped gateway path (P2.5b).** The
  `OutputChannel` exists, is tested, and closes the covert channels it is measured against, but
  the product's tool-call path still returns its own responses rather than routing every
  agent-to-outside message through the channel. Wiring it in is a contributor task, not a
  claim: the covert-channel numbers describe the channel, not the whole product.
* **The measured covert channels are five (P2.5b, part of I36).** Whitespace, zero-width
  characters, homoglyphs, number-precision noise and key order are measured closed. Other
  degrees of freedom — for example the *choice* between two semantically equivalent free-text
  spellings, or the length of a free-text field — are **UNTESTED** as channels.
* **A timing channel is not closed by canonicalisation (P2.5b, part of I36).** A bit carried
  in *when* a message is sent is not in the message, so canonicalisation cannot remove it. The
  measurement therefore reports 0 content bits for the timing channel, before and after: the
  bits are not in the content domain at all. The *refusal* latency is bucketed (I40), but the
  outbound timing domain is **UNTESTED** here.
* **Read-only workspaces are advisory on native Windows (P2.5b, part of I39).** The file mode
  is set read-only, but Windows does not stop the same user from writing anyway. The real
  guarantee is the *digest check*: the environment re-computes the workspace digest and
  reports a run that wrote into it. Enforcement by the kernel (a read-only mount, a
  container) is **UNTESTED** here.
* **Model weight read-only enforcement is UNTESTED (P2.5b, part of I39).** The environment
  *denies* a run whose backend cannot make the weight paths read-only, and that denial is
  tested. Whether a real backend can make them read-only is **UNTESTED**: the shipped backend
  reports that it cannot, so the denial path is what runs.
* **The hardware kill actuator and the hardware heartbeat sink are interface only, UNTESTED
  (P2.5b, part of I38).** There is no hardware here to test them against. The software
  actuator and the file sink are tested; a hardware adapter is a research tier (L5+), not a
  claim.
* **The watchdog bounds a plug-in, it does not preempt it (P2.5b, part of I41).** A hanging
  actuator or sanitizer is abandoned on a daemon thread, which is enough to keep the safety
  layer responsive but does not stop the runaway code. Preemption is **UNTESTED**.
* **The unix-socket half of the external signal adapter is UNTESTED on this host (P2.5b, part
  of I37).** This Windows host has no `AF_UNIX`, so the file-drop path is exercised and the
  socket path skips with an explicit reason. Whether an outside monitor on a POSIX host can
  use the socket path is **UNTESTED** here.
* **The bucketed denial timing is coarse (P2.5b, part of I40).** Refusals are quantised into
  50 ms buckets, so a refusal is *not* constant-time: an observer can still distinguish a
  refusal inside one bucket from one that crossed a bucket boundary. The claim is that the
  *reason* is not distinguishable, not that the timing is perfectly flat.



## P2.5a — assurance foundations

P2.5a adds the assurance layer that lets a deployment *prove* what it is, not just
assert it: crypto-agile versioned tokens and audit entries, language-neutral
conformance vectors with a second verifier, a pure functional run lifecycle as a
state machine, backend assurance classes verified by active probes, and a signed
run-assurance manifest. The code is `src/asl/core/algorithm.py`,
`src/asl/core/lifecycle.py`, `src/asl/core/run_manifest.py`, the versioned parts
of `src/asl/core/tokens.py` and `src/asl/core/audit.py`, `conformance/vectors/`,
`conformance/verify_vectors.py`, and `src/asl/sandbox/assurance.py`. I29–I34 are
the invariants of this phase.

| # | Invariant | Tests |
|---|-----------|-------|
| I29 | **Crypto agility and versioning.** Every token, audit entry and checkpoint carries a format version, an algorithm id and a key id. A small registry holds the enabled algorithms — only HMAC-SHA256 is shipped and enabled. An unknown algorithm, a disabled algorithm, or an unknown version is denied before any signature is checked. Minting always uses the current key; verification accepts any active (non-revoked) key id; revoked key ids are denied. | `tests/test_core_tokens.py` (`test_unknown_algorithm_is_denied`, `test_disabled_algorithm_is_denied`, `test_unknown_version_is_denied`, `test_key_rotation_verifies_under_any_active_key`, `test_mint_uses_the_current_key_after_rotation`, `test_revoking_the_current_key_is_refused`); `tests/test_core_audit.py` (version/algorithm/key_id on entries and checkpoints) |
| I30 | **Conformance vectors and a second verifier.** `conformance/vectors/*.json` are language-neutral fixtures for canonical JSON, argument hashing, token mint/verify (signed under a clearly-labeled FAKE test key) and audit-chain entries/checkpoints, including adversarial cases. A test proves the main implementation passes every vector, and a separately written stdlib-only verifier (`conformance/verify_vectors.py`, no `asl` imports) passes them too, checked by a differential test. | `tests/test_conformance_vectors.py` (whole file: main implementation + standalone verifier differential) |
| I31 | **Functional core state machine.** The run lifecycle and kill logic are an explicit state machine (CREATED, RUNNING, KILLED, DONE) with a transition table; inputs yield a decision plus effects as data, and I/O stays at the edges. KILLED is absorbing; no path leads from KILLED to RUNNING; a kill request is honored from every state; unknown transitions are denied. | `tests/test_core_lifecycle.py` (whole file: exhaustive matrix + Hypothesis state machine) |
| I32 | **Backend assurance classes.** Every sandbox backend declares a class (B0 process limits, B1 namespaces, B2 userspace kernel, B3 microVM, B4 reserved/not implemented) and claimed properties. Declared properties are verified at start by active probes against fake targets; a failed probe downgrades the class or denies. Policy can require a minimum class per action risk tier; insufficient class is denied. | `tests/test_sandbox_assurance.py` (whole file: class ordering, probe verification/downgrade, B4 reserved denied, per-tier enforcement) |
| I33 | **Signed run-assurance manifest.** At run start a signed manifest (run_id, versions, policy hash, backend and its VERIFIED properties, signal providers/watchdog present, workspace image hash, issued_at, expires_at) is written into the audit chain as a tamper-evident entry; a verify command checks chain integrity and the validity window. No network. | `tests/test_run_manifest.py` (whole file: manifest fields, audit-chain round-trip, tamper detection, validity window) |
| I34 | **Trusted-core boundary unchanged.** `asl/core` remains stdlib-only and under the 3,000-line budget, with the boundary test passing. Additions for P2.5a are minimal; I/O and non-core logic live in untrusted packages (`asl/sandbox/`, `conformance/`). | `tests/test_core_boundary.py::test_core_stays_under_the_line_budget`; line count at time of writing: **2,188** (budget 3,000) |


## P2.5b — channel, signal and kill seams

P2.5b adds the seams where a deployment plugs its own parts in: the output
channel every agent-to-outside message goes through, the risk-signal providers
that watch a run from outside, the kill actuator and heartbeat, the stateless
run environment, the information hiding around refusals, and the conformance
kits that hold every plug point to the same contract. The code is
`src/asl/output/`, `src/asl/core/signals.py`, `src/asl/risk/providers.py`,
`src/asl/core/heartbeat.py`, `src/asl/kill/`, `src/asl/runenv/`,
`src/asl/safety/denial.py`, `src/asl/bounded.py` and `tests/kits.py`.
I35–I40 are the invariants of this phase.

| # | Invariant | Tests |
|---|-----------|-------|
| I35 | **One door out, and no covert channel through it.** Every agent-to-outside message passes one `OutputChannel`: it is validated against a declared typed schema (an unschema'd message is denied), canonicalised (Unicode normalised, control/zero-width/bidi characters *rejected*, numbers fixed-format, keys sorted, whitespace normalised), held inside per-message, per-run and rate caps and a per-run bit budget, and passed through every registered sanitizer. Free text is allowed only in declared fields, with a length cap and a character allowlist. A sanitizer may only **reject** or **trim** — the channel refuses a trim that adds or rewrites content. | `tests/test_output_channel.py` (whole file) |
| I36 | **The covert channels are closed, and the rate is measured.** Whitespace, zero-width characters, homoglyphs, number-precision noise and key order each form a one-bit channel. The tests measure the bits that cross per second **before** canonicalisation (non-zero) and **after** it (zero), so the claim is a measurement rather than an assertion. | `tests/test_output_channel.py::TestSteganography` (`test_every_covert_channel_leaks_before_canonicalisation`, `test_every_covert_channel_is_closed_after_canonicalisation`, `test_the_leak_rate_is_measured_in_bits_per_second`) |
| I37 | **Risk signals are signed, versioned and tighten-only.** A `RiskSignal` carries a format version, a provider, a severity (`NONE < THROTTLE < FREEZE < KILL`), a reason, a run id, a validity window and an HMAC signature. The combiner takes the **maximum** severity and offers no way to lower one, so a loosening signal is impossible by construction. An invalid, expired or unsigned signal from a **required** provider is a KILL; from an **optional** provider it is ignored and audited. Built-in providers: tripwire and budget. An adapter reads signed signals from an external monitor (a file drop or a unix socket) — this is where outside monitors, such as model-internals probes run by a model owner, plug in. | `tests/test_risk_signals.py` (whole file) |
| I38 | **The heartbeat is a fixed-size frame, and a lapse stops the run.** The frame is exactly 44 bytes: magic `HB`, a version, a reserved flags byte, a big-endian 64-bit counter and an HMAC-SHA256 over the header. A frame of any other length, a bad magic, an unsupported version, a wrong key or a tampered byte is refused. The counter must strictly increase, so a replay or a rollback is refused. A standalone stdlib-only watchdog process verifies the frames and triggers the kill actuator on a lapse or a bad frame. Test vectors pin the exact bytes. | `tests/test_heartbeat_kill.py` (whole file, including `test_heartbeat_conformance_vectors` and the standalone-process tests) |
| I39 | **Every run is stateless.** A run starts from a read-only, hash-verified golden workspace image; a hash mismatch **refuses the start**; the workspace is destroyed afterwards; and the environment re-checks the digest, so a run that wrote into the workspace is reported and a second run cannot see the first run's files. Model weight paths are read-only where the backend supports it, and policy **denies** the run where it does not. | `tests/test_run_environment.py` (whole file) |
| I40 | **The agent learns nothing from a refusal.** The kill state, the lease TTL, the heartbeat and which tripwire fired are never in the agent's hands: every denial is the same shape and the same message, and every denial is timed into the same bucket, so a fast refusal and a slow refusal are indistinguishable. The reason goes to the operator's audit log, not to the agent. | `tests/test_information_hiding.py` (whole file, in particular `test_every_denial_reason_produces_the_same_response` and `test_two_different_reasons_take_the_same_time`) |
| I41 | **Every plug point has the same contract.** A reusable conformance kit exists for each of the five plug points — backend, signal provider, heartbeat sink, kill actuator, sanitizer. A new implementation inherits the kit and must pass it, including the fail-closed behaviour when the plug-in is **missing**, **raises**, **hangs** or **returns garbage**. A plug point that hangs is bounded by its host. | `tests/kits.py` (the kits), `tests/test_conformance_kits.py` (the kits run against the shipped implementations: `TestSanitizerConformance`, `TestSignalProviderConformance`, `TestSinkConformance`, `TestActuatorConformance`, `TestBackendConformance`) |


## P4 — swarm controls and 700-agent collusion simulator

P4 adds swarm-level containment: gateway-assigned identities, per-agent isolated
workspaces, a mediated inter-agent message bus where peer text is data never
authority, collective budget/rate caps with a tighten-only tripwire, and a
deterministic seeded asyncio simulator for a 700-agent collusion stress test.
The code is `src/asl/swarm/`. I42–I48 are the invariants of this phase.

| # | Invariant | Tests |
|---|-----------|-------|
| I42 | **Gateway-assigned identity.** Every agent receives a gateway-minted, signed capability token binding ``agent_id`` + ``run_id`` at spawn. An agent cannot mint or widen its own identity; a spoofed or replayed token is denied (``BindingError``) and trips the spoofing tripwire. | `tests/test_swarm_p4.py::TestSwarmIdentity` (whole class) |
| I43 | **Isolated per-agent workspaces.** Each agent gets its own directory under ``<run_workspace>/agents/<agent_id>/``; cross-agent reads and writes are blocked by construction. | `tests/test_swarm_p4.py::TestSwarmIsolation` (whole class) |
| I44 | **Mediated inter-agent bus.** Every peer message passes one OutputChannel: schema-validated, canonicalised, rate-capped and bit-budgeted, then logged to the AuditChain. Peer text is data, never authority — a message containing ``GO``, a capability token or an approval override can never mint, widen or transfer authority. | `tests/test_swarm_p4.py::TestSwarmBus` (whole class) |
| I45 | **Collective budget and rate caps.** Per-agent and collective swarm-wide limits on steps, messages per second, spend and covert bits are enforced fail-closed; exceeding any cap denies the action. | `tests/test_swarm_p4.py::TestSwarmGovernor` (whole class) |
| I46 | **Collective tripwire halts the swarm.** A distributed scan (many agents probing distinct targets), a queue flood (many agents hammering the approval queue), or instruction laundering (a peer message carrying ``GO`` or a token) advances the tier tighten-only: throttle → freeze → kill. At KILL the swarm is halted. | `tests/test_swarm_p4.py::TestSwarmGovernor` (whole class, tripwire tests) |
| I47 | **All six scripted attacks are contained.** Against the real swarm governor, S01–S06 all yield ``CONTAINED`` (0 breaches) and legitimate agents see zero false alarms. Against the ``--vulnerable`` positive-control stub (swarm defenses disabled), all six yield ``BREACHED``. | `tests/test_swarm_p4.py::TestSwarmSimulator` (`test_normal_run_contains_all_scenarios`, `test_vulnerable_positive_control_breaches_all`) |
| I48 | **Deterministic, seeded, RAM-bounded.** The same seed reproduces the same search and corpus; every trial streams to a fresh timestamped JSONL file; a full 700-agent run completes under the 450 MB RAM gate. | `tests/test_swarm_p4.py::TestSwarmSimulator` (`test_determinism_across_runs`, `test_full_700_agent_run_stays_under_ram_gate`) |


## P5 — rigor runs, fault injection, mutation testing (this phase)

P5 measures rather than asserts: a calibrated cyber-range batch, fail-closed fault-injection tests, and an AST mutation check. The code is `scripts/phase3_trials.py`, `scripts/phase3_trials_cli.py`, `scripts/phase3_mutate.py`, `tests/test_kill.py` (fault injection) and `tests/test_mutant_killers.py`. Every run writes fresh timestamped files under `evidence/phase3/` and never appends to a previous run's.

| # | Invariant | Result |
|---|---|---|
| P1 | **Zero breaches across the calibrated range batch.** 160 trials over 16 attack classes (dev A01-A10, A16; held-out A11-A15), 10 trials each, fixed seed 20261023, fresh per-trial output: **0 breaches, 0 CONTAINED, 130 INCONCLUSIVE, 30 ERROR**, per-class 95% upper bound 3/10 = 0.3. Total 294 s (~1.8 s/trial). | `scripts/phase3_trials.py` → `evidence/phase3/*/trial_summary.json` |
| P2 | **Fail closed under fault.** A gateway killed mid-request denies (never allows), a locked database denies, clock skew (forward or back) denies, a truncated/corrupted write denies, and malformed input denies — never allow. | `tests/test_kill.py::TestFailClosed` (whole class, incl. `test_a_gateway_killed_mid_request_denies_never_allows`) — passes |
| P3 | **AST mutation check over `src/asl/core/` and `src/asl/egress/`.** The first recorded run reported 591 mutants, **0 killed (0.0% kill rate)**. That figure was a **harness bug, not a security finding**: `apply_mutation` deep-copied the AST before mutating, so the mutation point (which referred to a node in the *original* tree) never matched by identity and every "mutant" was byte-for-byte the original. (The earlier "package imports never shadowed" explanation was a misdiagnosis.) The mutator is fixed and the check re-run under P6.5, which reports the real kill rate and explains each surviving mutant. | `scripts/phase3_mutate.py` → `evidence/phase3/*/mutation_report.json` (P6.5) |

### Honest gaps (P5)

* **Kernel-level egress confinement — UNTESTED on native Windows.** The range runs without a Linux network namespace or bubblewrap (`confinement: resource_only`, `egress_enforced: false`), so most trials produce no conclusive verdict (INCONCLUSIVE) rather than CONTAINED. What the Windows run *does* prove is the mediated-channel half: every request the attack library makes funnels through the gateway and is authorised there. The kernel half (no IP route at all) is not proven on this host.
* **Classes A01/A13/A14 errored on all 10 trials.** These returned ERROR verdicts rather than CONTAINED/INCONCLUSIVE, so no bound is stronger than 3/10 = 0.3 for them either; errors are non-conclusive and never folded into containment.
* **Mutation kill rate was 0.0% by harness bug — now fixed and re-measured.** The mutator deep-copied the AST before mutating, so no mutation was ever applied. The bug is fixed and the honest kill rate is reported under P6.5.
* **Real-model behaviour — UNTESTED.** Every attack in the library is a deterministic script. Nothing here shows what a frontier model would do inside the same harness; a real-model swarm is a contributor task, not a claim.


## P6 — production deployment hardening (this phase)

P6 hardens the deployment surface so ASL can run in production. The code is
`Dockerfile`, `.dockerignore`, `scripts/sbom.py`, `deploy/charts/asl-gateway/`,
`tests/test_container_security.py`, `tests/test_deployment_hardening.py`, and
`src/asl/gateway/mcp.py` (health endpoints). Every check runs offline without a
Docker daemon.

| # | Invariant | Result |
|---|---|---|
| D1 | **Container image is minimal and non-root.** Multi-stage build (build → distroless final), non-root user (65532:65532), read-only root filesystem, no shell or package manager in the final stage, entrypoint uses exec form with `python -m asl.cli serve`. Only runtime dependencies installed, with `--require-hashes` from pinned locks. | `tests/test_container_security.py` (whole file) — passes |
| D2 | **Image contains no secrets, tests, or evidence.** The signing key, HMAC key, and secrets are never copied into the image (they live outside the repo). Tests, evidence, `.venv`, and development tooling are excluded via `.dockerignore`. | `tests/test_container_security.py` — passes |
| D3 | **Network policy enforces zero direct egress.** The baseline NetworkPolicy denies all ingress and egress to every pod. The gateway policy allows only DNS (port 53) and egress-gateway HTTPS (443 via istio-system); no `ipBlock` direct egress to the internet. | `tests/test_deployment_hardening.py::test_network_policy_default_deny_egress`, `::test_gateway_network_policy_no_direct_egress` — passes |
| D4 | **Deployment enforces hardened security contexts.** `runAsNonRoot`, `readOnlyRootFilesystem`, dropped `ALL` capabilities, `RuntimeDefault` seccomp profile, non-automounted service account, resource limits, and liveness/readiness probes. | `tests/test_deployment_hardening.py::test_deployment_has_security_context`, `::test_values_yaml_sets_hardened_defaults` — passes |
| D5 | **Signing key is outside the repo with mode 0600.** `core_signing.key` is listed in `.gitignore` and `*.key`, is never committed, and when present outside the repo is written mode `0600`. | `tests/test_deployment_hardening.py::test_signing_key_outside_repo`, `::test_signing_key_mode_0600` — passes |
| D6 | **SBOM is generated and reproducible.** `scripts/sbom.py` emits a component list (name, version, SHA-256 digest) from the lock file; two runs against the same lock produce identical output (modulo `generated_at`). | `tests/test_deployment_hardening.py::test_sbom_script_exists_and_runs`, `::test_sbom_is_reproducible` — passes |
| D7 | **Lock verification passes with --require-hashes.** `scripts/check_locks.py` confirms every requirement is pinned, every pin carries a sha256 hash, and platform-specific packages carry environment markers. | `tests/test_deployment_hardening.py::test_check_locks_passes` — passes |

### Honest gaps (P6)

* **Container image is not actually built.** These tests validate the Dockerfile statically; building and running the image requires a Docker daemon, which is unavailable on this host. The image build path (`docker build --tag asl-gateway:0.1.0 .`) is documented but not exercised here.
* **Health endpoints are basic.** `/healthz` and `/readyz` return static status; they do not yet probe the audit chain, signing key, or kill-state store. Deeper readiness checks are a contributor task.
* **SBOM covers Python packages only.** System-level dependencies in the base image are not enumerated. A container-native SBOM tool (e.g., Syft, Trivy) would add OS-layer coverage.
* **Kernel-level egress confinement — UNTESTED on native Windows.** The Helm chart documents bubblewrap/network-namespace confinement, but this host cannot enforce it. See P5 gap on kernel-level confinement.


## P6.4 — operational safety controls (this phase)

P6.4 closes the operational gaps around the kill paths: who may throw the human
switch, what happens when the actuator or the heartbeat sink is a *hardware*
device that can succeed, fail or hang, and whether the budget and tripwire
thresholds stay quiet on ordinary traffic. The code is
`src/asl/kill/actuator.py`, `src/asl/kill/sink.py`, `src/asl/core/kill.py`
(human-switch ownership) and `tests/test_p64_operational_safety.py`.

| # | Invariant | Result |
|---|---|---|
| S1 | **The human switch is owner-checked and fails closed.** With `verify_ownership=True`, the switch only counts as *not* engaged when the file's owner matches `authorized_user`; a wrong owner, an unreadable file, or a host where ownership cannot be determined (non-POSIX) all read as engaged — a kill, never a silent pass. | `tests/test_p64_operational_safety.py::test_human_switch_ownership_verification_rejects_wrong_owner`, `::test_human_switch_ownership_verification_accepts_correct_owner`, `::test_human_switch_fails_closed_when_ownership_cannot_be_determined` — passes (the "correct owner" case is skipped on Windows; see the gap below) |
| S2 | **A hardware kill actuator is simulated, not assumed.** `HardwareKillActuatorSimulator` reproduces success, failure and hang, and can be reconfigured at runtime, so the watchdog's behaviour against a hardware actuator that misbehaves is exercised rather than assumed. | `::test_hardware_actuator_simulator_success`, `::test_hardware_actuator_simulator_failure`, `::test_hardware_actuator_simulator_hang`, `::test_hardware_actuator_simulator_dynamic_reconfigure`, `::test_hardware_actuator_simulator_hang_config`, `::test_watchdog_with_hardware_actuator_simulator` — passes |
| S3 | **A hardware heartbeat sink is simulated, not assumed.** `HardwareHeartbeatSinkSimulator` reproduces success, failure and hang, so a heartbeat that stops crossing a real boundary is exercised. | `::test_hardware_sink_simulator_success`, `::test_hardware_sink_simulator_failure`, `::test_hardware_sink_simulator_hang`, `::test_hardware_sink_simulator_dynamic_reconfigure` — passes |
| S4 | **Thresholds are quiet on ordinary traffic, but the tripwire still fires.** Budget/rate caps and the tripwire produce zero false positives on a baseline workload, while scan, credential-spray, large-transfer and listen-bind are each detected, with a tiered throttle→freeze→kill response. | `::test_budget_baseline_no_false_positives`, `::test_tripwire_baseline_no_false_positives`, `::test_tripwire_detects_scan`, `::test_tripwire_detects_credential_spray`, `::test_tripwire_detects_large_transfer`, `::test_tripwire_detects_listen_bind`, `::test_tripwire_tiered_response` — passes |
| S5 | **Every kill path still fires the complete cascade.** Policy, lease, budget and human each halt the run through the full cascade, and a detector that raises is treated as a signal rather than as "no signal". | `::test_budget_exceeded_triggers_kill`, `::test_lease_expired_triggers_kill`, `::test_policy_gate_triggers_kill`, `::test_human_switch_engaged_triggers_kill`, `::test_kill_cascade_is_complete`, `::test_detector_that_raises_is_treated_as_signal` — passes |

### Honest gaps (P6.4)

* **The real hardware actuator and hardware sink remain interface only, UNTESTED.** Only the simulators exist; there is no hardware here to test against. The simulators prove the *software* reacts correctly to a hardware device that succeeds, fails or hangs — they do not prove any real device works.
* **The ownership check is POSIX-only.** `pwd` is unavailable on Windows, so with `verify_ownership=True` the switch always reads as engaged on this host (fail closed). That is safe, but it means the "correct owner clears the switch" path can only be exercised on a POSIX host; the Windows run covers the fail-closed branch only.


## P6.1 — autonomous agent integration (this phase)

P6.1 wires the actual agent-to-outside message path through the `OutputChannel`
(P2.5b): schema validation, canonicalisation, per-message/per-run/rate caps,
bit budget, and reject-or-trim sanitizers. The code is `src/asl/gateway/core.py`,
`src/asl/gateway/mcp.py`, and `tests/test_p61_real_model.py`.

| # | Invariant | Result |
|---|---|---|
| A1 | **Every agent-to-outside response routes through the OutputChannel.** The gateway's `_execute_tool` sends the result through `output_channel.send()`; the MCP proxy's `/mcp/call` routes errors through `sanitize_outbound()`. No raw response reaches the agent. | `tests/test_p61_real_model.py::test_output_channel_routes_model_response`, `::test_mcp_proxy_errors_route_through_output_channel` (MCP path tested via SDK) — passes |
| A2 | **Schema enforcement on outbound.** A response missing `tool_name` or `success`, or with an undeclared field, is denied. | `tests/test_p61_real_model.py::test_output_channel_schema_enforced_on_model_response` — passes |
| A3 | **Canonicalisation removes covert bits.** Whitespace normalised, float precision fixed (6 decimals), keys sorted, control/zero-width/bidi characters rejected (denied, not stripped). | `tests/test_p61_real_model.py::test_output_channel_canonicalisation_on_model_response` — passes |
| A4 | **Caps enforced.** Per-message (4 KiB), per-run (64 KiB), bit budget (512 KiB), rate limit (100/min) all enforced; over-cap responses denied. | `tests/test_p61_real_model.py::test_output_channel_caps_enforced_on_model_response`, `::test_output_channel_bit_budget_enforced`, `::test_output_channel_rate_limit_enforced` — passes |
| A5 | **Sanitizers are reject-or-trim only.** A sanitizer that adds content is denied; a trim that breaks the schema is denied; a raising/hanging sanitizer is denied (fail closed). | `tests/test_p61_real_model.py::test_sanitizer_rejects_model_output`, `::test_sanitizer_trim_enforced`, `::test_sanitizer_cannot_add_content` — passes |

### Honest gaps (P6.1)

* **MCP proxy integration test skipped.** Mocking the module-level `gateway` instance in `mcp.py` is complex; the integration is verified via `test_gateway.py` and SDK tests instead. A full end-to-end MCP test requires a different app factory pattern.
* **Real-model smoke test uses stub.** The `_RealModelStub` exercises the channel with covert-channel payloads but does not call an actual LLM. A real-model integration requires an external endpoint and is a contributor task.
* **Real-model swarm stress test not implemented.** Successor to P4's 700-agent simulator with real models is a contributor task, not a claim.
* **Health endpoints do not probe channel state.** `/healthz`/`readyz` return static status; they do not verify the output channel is operational.


## P6.3 — observability & audit (this phase)

P6.3 provides structured audit export, off-box witness anchoring, metrics collection,
and alerting. The code is `src/asl/audit/export.py`, `src/asl/risk/metrics.py`,
and `tests/test_p63_observability.py`. All operations run offline and fail closed.

| # | Invariant | Result |
|---|---|---|
| O1 | **Structured audit export.** The chain can be exported as JSONL or JSON; each entry is a self-contained object with all fields (seq, timestamp, event, data, prev_hash, hash, version, algorithm_id, key_id). Export supports sequence-range filtering. | `tests/test_p63_observability.py::TestAuditExport` (whole class) — passes |
| O2 | **Off-box witness anchoring.** A signed checkpoint can be written to a local file, appended via SSH (`user@host:/path`), or POSTed to an HTTP endpoint. The witness is immutable once published, so an attacker cannot roll it back. | `tests/test_p63_observability.py::TestOffBoxWitness` (whole class) — passes |
| O3 | **Witness verification detects truncation/rollback.** Verifying the local chain against a published witness detects if the chain is shorter than the witness, or if the head hash at the witnessed sequence differs — evidence of truncation or alteration. | `tests/test_p63_observability.py::TestOffBoxWitness::test_verify_against_witness_truncated`, `::test_verify_against_witness_head_mismatch` — passes |
| O4 | **Metrics collection: detection/kill timing.** `time_to_detect_s` (interval from run start to first refusal/tripwire) and `time_to_kill_s` (interval to run halt) are recorded per run. | `tests/test_p63_observability.py::TestMetricsCollector::test_record_detection_and_kill` — passes |
| O5 | **Metrics collection: covert channel leakage.** `covert_bits` (bits that actually crossed), `covert_bits_attempted`, `covert_seconds`, and derived `covert_bits_per_sec` are tracked per run. | `tests/test_p63_observability.py::TestMetricsCollector::test_record_covert_bits` — passes |
| O6 | **Metrics collection: denial bucketing.** Every denial is counted and bucketed by reason category (policy, rate, auth, etc.); global and per-run buckets available. | `tests/test_p63_observability.py::TestMetricsCollector::test_record_denial` — passes |
| O7 | **Metrics collection: output channel & sanitizer events.** Output channel denials, sanitizer rejections, sanitizer trims tracked per run. Bit budget exhaustion and rate limit events recorded. | `tests/test_p63_observability.py::TestMetricsCollector::test_output_channel_metrics`, `::test_bit_budget_and_rate_limit` — passes |
| O8 | **Metrics collection: revocation & replay.** Run revocation events and replay attempts are counted per run. | `tests/test_p63_observability.py::TestMetricsCollector::test_revocation_and_replay` — passes |
| O9 | **Alerting on kill/cascade, revocation, replay, chain tampering, covert leakage, denial spikes, output channel denials, sanitizer events, budget/rate exhaustion.** Alerts include type, severity (info/warning/critical), run_id, agent_id, metadata, timestamp. Handlers are registered callbacks; the default logs to JSONL. | `tests/test_p63_observability.py::TestMetricsCollector::test_chain_tampered_alert`, `::TestAlertLogger`, `::TestConvenienceFunctions` — passes |
| O10 | **Periodic metrics reporting.** `MetricsReporter` emits a JSONL snapshot of all active runs, global denial buckets, and aggregate stats at a configurable interval. | `tests/test_p63_observability.py::TestMetricsReporter::test_emits_snapshot` — passes |

### Honest gaps (P6.3)

* **Alert handlers are best-effort.** Handlers run synchronously on the safety layer's thread; a slow handler blocks. Production deployments should use async dispatch.
* **Witness destinations are not mutually authenticated.** SSH and HTTP anchors rely on transport security (SSH keys, TLS) but do not implement application-level mutual auth.
* **Metrics reporter runs on a daemon thread.** If the process is killed ungracefully, the final snapshot may be lost. A shutdown hook is a contributor task.
* **No built-in dashboard.** Metrics are emitted as JSONL for external aggregation (e.g., Loki, Elastic, Splunk). A UI is a contributor task.


## P6.5 — rigorous verification: mutation, confinement, timing (this phase)

P6.5 converts three claims that were previously *asserted* into measurements: the
mutation score of the trusted core and the egress gateway, kernel-level egress
confinement, and the constant-time property of the secret comparisons. It also
fixes the Windows file-locking failure that made the full suite red. The code is
`scripts/phase3_mutate.py` (harness), `tests/test_egress_kernel.py`,
`tests/test_constant_time.py`, the killer tests appended to each mapped test
file, and the `contextlib.closing(...)` change across the SQLite stores.

| # | Invariant | Result |
|---|---|---|
| M1 | **The mutator actually mutates, and a module is measured against the tests that exercise it.** The earlier recorded 0.0% kill rate was a harness bug: `apply_mutation` deep-copied the AST, so the mutation point (which referred to a node in the *original* tree) never matched by identity and every "mutant" was byte-for-byte the original. The mutator now mutates the tree in place, builds each mutant from a freshly parsed tree and relocates the point by index, and refuses to report a 0% kill rate when no mutant changes the source. The test map is part of the measurement: `core/tokens.py` is now measured against the core token tests **and** the P7 attenuation tests, because the `attenuate` guards live in that suite — a one-file map reported 7 live guards as unexplained survivors. A resume checkpoint only replays an outcome whose source **and** test-map hashes still match. | `scripts/phase3_mutate.py` — 606/606 mutants change the source |
| M2 | **The kill rate is measured, not assumed.** Over the 14 modules of `src/asl/core/` and `src/asl/egress/`: **606 mutants, 592 killed, 14 survived → 97.7%** (up from 89.0% before the P6.5 killer tests). Per module: tokens 94/94 (100%), kill 71/74 (95.9%), killstate 1/2 (50.0%), audit 102/103 (99.0%), canonical 20/20 (100%), lifecycle 5/5 (100%), signals 53/54 (98.1%), heartbeat 32/32 (100%), mediator 34/35 (97.1%), ipguard 61/62 (98.4%), urlguard 37/38 (97.4%), allowlist 34/35 (97.1%), helpers 19/20 (95.0%), channel 29/32 (90.6%). | `scripts/phase3_mutate.py` → `evidence/phase3/20261028T032008-002544/mutation_report.json` (tokens re-measured and merged; `remeasured`/`merged_from` in the report) |
| M3 | **Every surviving mutant is explained — none is unexplained.** All 14 survivors are *equivalent* mutants (a mutation that cannot change observable behaviour) or runtime-inert. See the table below; each was proved equivalent by inspection and, where non-trivial, by probe. | `evidence/phase3/20261024T115106-632824/mutation_report.json` (`survivors`) |
| M4 | **A hard kill cannot leak a mutant into the tree.** Pre-mutation copies are parked *outside* the repo and replayed by `restore_stale_backups()` at the start of the next run, and the per-mutant restore runs in a `finally`. After the completed run the backup directory is empty and `git diff --quiet` is clean for all 14 mutated modules. | `scripts/phase3_mutate.py`; `git diff --quiet -- <module>` → 0 for every module |
| M5 | **Kernel-level egress confinement is tested where the platform provides it.** `tests/test_egress_kernel.py` places a child in `unshare --net` (and, separately, `bwrap --unshare-all`) with a fake loopback server reachable on the host, and requires the child to be unable to reach it, while `test_a_namespaced_child_can_still_use_the_mediated_channel` requires the unix-socket mediated channel to keep working across the namespace boundary. On a host without namespaces the whole file skips with the exact reason. | `tests/test_egress_kernel.py` — **SKIPPED on this host** (see gap) |
| M6 | **Constant-time comparison is measured, not merely asserted correct.** `_best_ns_per_call` takes the *minimum* per-call cost over 25 batches of 2 000 calls (the minimum converges on pure compute; jitter only ever adds time). It must show flatness — the spread across equal / differs-last-byte / differs-first-byte inputs must be under 2.0× — for both `hmac.compare_digest` and `asl.core.tokens._ct_eq`. | `tests/test_constant_time.py::TestConstantTimePrimitiveIsTimingFlat` — passes |
| M7 | **The measurement is proven able to see a leak.** The positive control times a deliberately leaky first-byte-exit comparator and requires the ratio to exceed 3.0×. Without it a flat result would be indistinguishable from a broken stopwatch. A static guard also requires the eight security-critical modules to keep calling a constant-time primitive. | `tests/test_constant_time.py::TestTheMeasurementCanDetectALeak`, `::TestHardenedCallSitesUseCompareDigest` — passes |
| M8 | **The suite is green on Windows because SQLite handles are closed, not merely committed.** `with sqlite3.connect(...) as conn:` commits but never closes the underlying handle, so a test that removes the session state directory hits `WinError 32` (file in use). Every such site (killstate, approval queue, consent store, baseline, kill switch, vault, CLI, red-team runner) now uses `with contextlib.closing(sqlite3.connect(...)) as conn, conn:`. | `tests/test_privacy.py::test_wipe` and the full suite — passes |

### Surviving mutants (all proven equivalent)

| Module | Mutation | Why it cannot change behaviour |
|---|---|---|
| `core/kill.py` L45, `core/killstate.py` L21, `core/signals.py` L33, `egress/allowlist.py` L15, `egress/mediator.py` L41, `egress/channel.py` L35 | drop `if TYPE_CHECKING:` | A typing-only import guard. `TYPE_CHECKING` is `False` at runtime, so removing the guard changes nothing that any test (or any caller) can observe. |
| `core/kill.py` L538 (drop-check and remove-`not`) | 2 mutants | Dead code: the guarded branch is unreachable, so both the dropped guard and the un-`not`ed test are unobservable. |
| `core/audit.py` L288 | flip `>` → `<` on `anchor_count > 0` | `anchor_count` is validated non-negative by `read_checkpoint`, so in the reachable domain `anchor_count < 0` is always `False` exactly as `anchor_count > 0` is `False` when it is `0`; the branch is taken identically for `0` and never taken for the flipped form. |
| `egress/ipguard.py` L74 | drop `if "%" in text:` | Slicing a string that contains no `%` at the first `%` is a no-op, so guarded and unguarded produce byte-identical output for every input. |
| `egress/urlguard.py` L101 | `split.netloc or ""` → `split.netloc and ""` | `netloc` feeds only the immediately following userinfo check, which is already decided by `split.username` / `split.password`; the value itself never reaches the target. |
| `egress/channel.py` L133 (drop-check and `and`→`or`) | 2 mutants | The unlink of the socket path is inside `contextlib.suppress(OSError)`; the guard only avoids a pointless `unlink` on a path that does not exist, and the suppressed error is swallowed either way. |
| `egress/helpers.py` L74 | drop `if ...:` guard | The mutation raises `TypeError` inside a `try/except Exception: pass`, so the produced denial record is identical to the original's. |

### Honest gaps (P6.5)

* **Kernel-level egress confinement — UNPROVEN on native Windows, PROVEN under WSL2.** On native Windows `tests/test_egress_kernel.py` still skips with an explicit reason: no Docker daemon, and neither `unshare` nor `bwrap` exists there. It is no longer unproven *anywhere*: on Ubuntu 26.04 under WSL2 (kernel `6.18.54.1-microsoft-standard-WSL2`, bubblewrap 0.11.1) all three cases pass — a `unshare --net` child gets `NO_ROUTE` against a live loopback server while the mediated `AF_UNIX` channel still returns a real `200`, and the same no-route property holds under `bwrap --unshare-all --dev-bind / /`. So the mediated half (the channel surviving a namespace boundary) is proven too, and `asl level` on that host reports **L4.5 (Full Kernel + Mediated)**. See [kernel-confinement.md](kernel-confinement.md). That fix also exposed a probe defect: `require_bubblewrap()` probed a bare `bwrap --unshare-all -- true`, which has no root bind and therefore cannot `execvp true`; it now probes the same flag set the test uses.
* **97.7% is a lower bound on the true mutation score.** The 14 survivors are all equivalent, so the number of mutants that *can* be killed is 585; the score those 585 represent is 100%. The 97.7% is reported as measured, counting equivalent mutants as survivors rather than quietly excluding them.
* **One test file per module.** The harness credits a mutant only if its single mapped test file fails, so a mutant caught only by some *other* test would be recorded as a survivor. The mapping is 1:1 and deliberate; the killer tests were appended to the mapped file for that reason.
* **Timing tests are host-sensitive.** `TestConstantTimePrimitiveIsTimingFlat` and the positive control carry `slow` and `timing` and can be deselected with `-m "not timing"`; the static `compare_digest` guard in the same file has neither marker and always runs.

| Level | Claim | Status |
|-------|-------|--------|
| L0 | No mediation: the agent runs unconstrained on the host. | Baseline (not a safety claim) |
| L1 | Mediated egress: every outbound request passes the capability-token-checked, allowlist-validated channel; no direct network. | Built / Tested (P1b) |
| L2 | Kill paths: policy, lease, budget and human switches each halt a run through a fail-closed cascade. | Built / Tested (P1a/P1b) |
| L3 | Measured attack surface: the cyber range scores scripted attacks (classes 1-16) from evidence, and the tripwire detects campaigns. | Built / Tested (P2/P2c/P3) |
| L4 | Assurance foundations: versioned crypto, conformance vectors with a second verifier, the run state machine, backend assurance classes verified by active probes, a signed run-assurance manifest, one output channel with no covert channel, signed tighten-only risk signals, a fixed-size heartbeat with a standalone watchdog, a stateless hash-verified run environment, uniform refusals, and conformance kits for every plug point. | Built / Tested (P2.5a, P2.5b) |
| L4.5 | Swarm controls: gateway-assigned unforgeable identities, per-agent isolated workspaces, a mediated inter-agent bus where peer text is data never authority, collective budget/rate caps with a tighten-only tripwire, and a deterministic 700-agent collusion stress test with all six attack scenarios contained. | Built / Tested (P4) |
| L3/L4.5 gates (measured) | An evidence gate measures the claim rather than asserting it: 1,000 trials/class over the 12 development classes (`A01`–`A10` + `A16` + `A17`) and the 5 blind `heldout_v2` classes, the 250-payload public exploit benchmark suite, the evolutionary soak, the 700-agent swarm and fail-closed fault injection. `asl level` derives a signed report from the evidence files and fails closed on missing, tampered or breaching evidence. | Built / Tested (P7d/P7e) — dev `0/12,000`, held-out `0/5,000`, public `250/250` contained, mutation kill rate 97.7%; earned **L4.5 (Full Kernel + Mediated)** on a host with Linux namespaces (the signed report on disk), **L4.5 (Architecture Verified)** on native Windows ([proof](kernel-confinement.md)) |
| Solo ceiling | Every gate one host can measure is measured and passing: TCB size and stdlib purity, mutation score, public benchmarks, dev and blind held-out trials, the 700-agent swarm, the covert-channel scrubber, the P8 fuzzer, and the P9 wire contracts. The four remaining dependencies are physical and are named as such. | Built / Tested (P9) — 9/9 solo gates, receipt in `docs/boundary-ceiling-report.json`; `asl boundary` prints the verdict and exits non-zero if any gate fails |
| L5+ | Research tiers (verified-kernel / hardware isolation, formal proof of the TCB, real-model adversarial resilience, a hardware kill actuator, a hardware heartbeat sink). | **NOT CLAIMED** — interface only, no implementation, no test. The four physical blockers are enumerated by `asl boundary` |

**Every seam in ASL is labeled "interface only" until a passing test backs it.** A
seam that has no passing test is UNTESTED and must not be treated as a guarantee.
The trusted core (`asl/core`) is the only component held to the 3,000-line
stdlib-only boundary; everything outside it is untrusted and is validated by
evidence, not by assertion.

## P8 — continuous adversarial fuzzing and the auto-regression loop

P8 turns the P3 attacker from a one-off search into a standing instrument. Two
things change: the fuzzer grows four *targeted* families that generic mutation
stops reaching, and the corpus loop becomes a first-class object that minimises,
promotes and replays on its own. The code is
`src/asl/cyberrange/fuzzer.py`, `src/asl/cyberrange/regression_loop.py`, the
extended operator set in `src/asl/cyberrange/mutator.py`, and the
`asl range fuzz` / `asl range regression` commands in `src/asl/cli.py`.

I24 and I25 are **strengthened** rather than repeated: the corpus now grows from
a loop that runs by itself, and the fitness scale is checked against the
positive control on every run instead of once during development.

| # | Invariant | Tests |
|---|---|---|
| I49 | **The new families are generated, family-fair, bounded and deterministic.** Four families — `url_parser` (control characters, Unicode confusables, overlong UTF-8, authority tricks), `header_smuggling` (`Content-Length`/`Transfer-Encoding` conflict, obs-fold, padded and duplicated names, `X-Forwarded-*` / `X-Original-URL` overrides), `zero_width_bidi` (zero-width and bidirectional format characters), and `token_widening` (claims to widen an attenuated capability) — each contribute to every population, each map back from their own origin, and every payload, body and frame count obeys the same clamps as the P3 grammar. A generator is a pure function of its seed: the same seed yields the same payloads and ids, a different seed yields different ones. The P3 operator set stays **frozen** and the seven P8 operators are added beside it, so the already-published corpus stays reproducible. A refusal is scored where it happens: a malformed header name is rejected by the harness's own request canonicaliser before a token can be minted, and that is a refusal **at the normalisation stage** (fitness 1), not an internal error — the header family is what exposed that the exception path was scoring such variants as fitness 0 "unknown refusal" with `error` set. | `tests/test_p8_fuzzing_and_regression.py::TestDeterminism` (whole class, including `::test_the_published_operator_set_is_not_widened`), `::TestFamilies` (whole class), `::TestFitnessMonotonicity::test_a_malformed_header_name_is_scored_as_a_refusal_not_an_error` |
| I50 | **The loop minimises, promotes and replays safely.** A variant worth keeping is reduced to the shortest payload that reaches **exactly** the same stage — a cut that exposes a bypass scores the breach stage and is rejected, so minimisation can never manufacture a finding — and the pass is bounded by `MAX_MINIMISE_TRIALS`. A trial at the floor (fitness 0) is never minimised, because every candidate ties there and the minimiser would shred a payload into a fragment that reproduces nothing; a trial that raised or was inconclusive is kept verbatim, because its verdict belongs to that exact input. The corpus is rewritten atomically (temporary sibling, `fsync`, then `os.replace`): a crash mid-rewrite leaves the previous corpus intact and leaves no temporary file behind, and the corpus is **never** opened in append mode. Transcripts are *reserved* with `O_CREAT | O_EXCL` rather than named from a clock, because two runs inside one clock tick would otherwise share a filename and one would silently truncate the other's evidence. Replay is the gate: every entry, old and new, is re-run against the live gateway, and an entry that now breaches is a regression that turns the run red. | `tests/test_p8_fuzzing_and_regression.py::TestMinimisation` (whole class), `::TestCorpusAtomicity` (whole class), `::TestEndToEnd` (whole class) |
| I25 (P8) | **The ceiling holds on every run, and the control still breaches.** Against the real gateway a fuzzing run peaks at "reached a service" (fitness 4, `FITNESS_CEILING_REAL_GATEWAY`) with **zero** breaches and no replay regression; against the planted-flaw positive control the same loop reaches fitness 5, which is what proves the scale can still fail. A run whose trials disagree with the breach flag is rejected as a progress metric, and a control that never breaches fails the same check as a gateway that does. | `tests/test_p8_fuzzing_and_regression.py::TestFitnessMonotonicity` (whole class) |

**Honest gaps (P8).** The four families are grammar, not model: they explore a
fixed candidate space, so a stronger generator could still find a shape none of
these produce — that remains UNTESTED. Minimisation is segment-granular (it cuts
at delimiters) rather than a general delta-debugger, so a reproducer is small but
not provably minimal. The loop promotes into `tests/corpus/regression_seeds.jsonl`,
which is a tracked file: a run therefore dirties the tree by design, and the
promotion is reviewed like any other evidence change.

## P9 — the external boundary and the solo-host ceiling

P9 finishes the software half of the two dependencies that are *physical* — an
independent witness and a power-cut relay — and then says, in one auditable
place, which claims one host can prove and which it cannot. The code is
`src/asl/boundary/external_contracts.py` (deliberately outside the trusted core,
so the TCB line count does not move), the `asl boundary` command, and
`conformance/vectors/boundary_v1.json`.

| # | Invariant | Tests |
|---|---|---|
| I51 | **The external wire contracts are deterministic, versioned and replay-proof.** A witness checkpoint is canonical JSON (`schema`, `version`, `algorithm_id`, run/seq/hashes/timestamp) signed with the *host* key; an acknowledgment is signed with a **different** key held by the witness, so a host that could produce both would be its own witness, and each acknowledgment is bound to one packet and one freshness window. A hardware kill command is the same shape plus a `monotonic_nonce`, and a relay accepts it only when the signature verifies **and** the nonce strictly exceeds the high-water mark for that node — and the signature is checked *first*, so a forged frame cannot burn a real nonce and lock out a genuine kill. Both parsers refuse a duplicate key, a non-finite number, an unknown schema or version, and any field they did not expect. The boundaries are testable by a second implementation: `conformance/vectors/boundary_v1.json` carries 13 cases, including the negative ones, and the standalone verifier reproduces every byte. | `tests/test_p9_boundary_and_ceiling.py::TestWitnessPacket`, `::TestWitnessAck`, `::TestKillCommand`, `::TestBoundaryVectors` (whole classes) |
| I52 | **The ceiling is a measurement with two buckets, and it fails closed.** `verify_solo_ceiling()` measures nine solo gates — TCB lines *and* stdlib-only imports read from source, the mutation kill rate, the 5 signed public-benchmark receipts, the dev and blind held-out trials, the 700-agent swarm, a **live** covert-channel measurement (5 bit-0/bit-1 probes collapsed to 0 bits/s), the P8 fuzzer, and a round-trip self-test of the P9 contracts — and separately enumerates the four physical dependencies that no local host can close. `solo_complete` is `True` only when every gate passes; pointed at an empty directory the same inspector reports `INCOMPLETE` and names the failing gates. The receipt it writes is HMAC-SHA256 sealed, and flipping any gate in it breaks the signature. | `tests/test_p9_boundary_and_ceiling.py::TestSoloCeiling`, `::TestCeilingReceipt`, `::TestCli` (whole classes) |

**Honest gaps (P9).** The wire contracts are *contracts*: no witness host and no
relay exist, so nothing here has been exercised against real hardware — the
software half is tested, the hardware half is absent. A signed evidence report
generated on another platform cannot be byte-verified here, because the signing
key is per-host; the inspector says so explicitly instead of calling it
tampering, and the P9 receipt carries the local seal. `L4.5-FULL-KERNEL` remains
conditional on the host: proven under WSL2, skipped on native Windows.

## P12 — the finding handler

P12 adds the seam that turns a discovered flaw from an exploit into evidence: a
typed report, a containment switch that only tightens, a triage queue that rides
the existing approval queue, ticket/draft alert routing, a staging-only
remediation sandbox, and signed redacted documents on the existing attestation
framing. The code is `src/asl/finding/` (deliberately outside the trusted core),
the finding mediator in `src/asl/cyberrange/gateway.py`, and range class 17. A
discovery on an asset *in scope* is reportable; an asset *outside* the scope
inventory is report-only and nothing else. I53–I60 are the invariants of this
phase, and `docs/claims.md` carries the scope boundary they enforce.

| # | Invariant | Tests |
|---|---|---|
| I53 | **A report is evidence, never a weapon.** `VulnerabilityReport` is validated through the one `OutputChannel`: the schema names `target_id`, `class`, `severity`, `evidence_hash` and one capped non-weaponized `summary`, with `additionalProperties` false — there is no field that could carry a payload, and a message with an undeclared one is refused, never stored. Evidence enters only as a SHA-256 hash of the observation; the raw observation is never kept by the report. An unknown class, severity or type, an uppercase hash, a control character in the summary or an oversized one are all refusals. | `tests/test_p12_finding_handler.py::TestVulnerabilityReportSchema` (whole class) |
| I54 | **Filing a report contains the run, tighten-only and measured.** The finding handler switches the run to REPORT_ONLY: every exploit-capable token for the run is revoked, outbound traffic to the reported target is denied, and the report channel stays open. The deny set only grows and no method exists that re-allows a target or re-issues a token; a second containment for the same target is idempotent and does not re-revoke. The time from report to enforcement is measured on **one** clock (the handler reads the controller's clock, so the two timestamps are subtractable — a-report-on-the-epoch-times-enforcement-on-the-monotonic-clock is not a measurement), and a broken revoker does not block the deny. | `tests/test_p12_finding_handler.py::TestReportOnlySwitch` (whole class) |
| I55 | **The finding provider is tighten-only.** A report signals FREEZE, a probe pattern signals FREEZE, and a probe *after* containment signals KILL. A run whose source has gone quiet holds its floor rather than lapsing to silence, and no later observation can lower a severity the run already reached. The signal is a signed `RiskSignal` from the existing machinery — no new tier, no reordered severity. | `tests/test_p12_finding_handler.py::TestFindingSignalProvider` (whole class) |
| I56 | **Triage rides the approval queue; scope decides ownership.** Findings queue through the existing `ApprovalManager` — no second queue of record. The dedupe binding is exactly ``(target_id, class, evidence_hash)``: the same observation filed twice coalesces into one item even when re-scored at a different severity. The owner comes from a scope inventory: an asset in the file has an owner and raises a ticket; an asset not in the file — or marked out of scope — is report-only with no owner and no ticket, and the queue lists most severe first. | `tests/test_p12_finding_handler.py::TestTriageQueue` (whole class), `tests/test_p12_range.py::TestFindingMediator::test_an_out_of_scope_asset_is_denied_before_anything_else` |
| I57 | **Nobody sends a disclosure; a chain of three gates does.** An owned finding becomes an internal ticket in a local file sink and never leaves the host. A third-party finding becomes a draft that is sent only after a human approves it, the embargo flag is lifted, and the rate window admits it — in that order, so no single decision and no single component can put one out the door. A rejected draft never sends; an approved-but-embargoed draft refuses; a sent draft cannot be sent twice; a pending approval alone is not a send. | `tests/test_p12_finding_handler.py::TestAlertRouting` (whole class) |
| I58 | **Remediation proposes, and never ships.** A patch proposal is a unified diff produced against a *staging copy* of the owned tree, with the supplied test command run **inside** the staging copy. A stale expectation is refused; a path that escapes the tree (absolute or `..`) is refused; production is byte-for-byte untouched; and `apply_to_production` refuses **by construction** — shipping is not a permission this module can be granted. | `tests/test_p12_finding_handler.py::TestRemediationSandbox` (whole class) |
| I59 | **A document that leaves the run is signed, redacted and need-to-know.** The redacted document (schema fields + routing metadata: owner, scope, embargo, recipients) is signed with the same canonical-JSON/HMAC-SHA256 framing as `X-ASL-Attestation`, so a recipient needs no new code to verify it. The signer refuses fields outside the declared set — an exploit command cannot ride along; a tampered body, a flipped signature byte, a wrong key and a re-signed unrelated field all fail verification. Only the owner is a recipient; a third-party draft names none and is born embargoed. Every accepted report and probe is audited. | `tests/test_p12_finding_handler.py::TestSignedFindingDocuments` (whole class), `::TestFindingHandlerEndToEnd` |
| I60 | **Range class 17 proves the seam end to end.** Against the real gateway: discovery over a granted GET, a report that is answered, the follow-up exploit *denied*, the ticket in the fake sink with the scope-file owner, and the denial plus the REPORT_ONLY switch present in the trial's audit chain. Against the checkless positive control the same attempt hands over the secret (the exploit response body crosses into the findings, so a checkless gateway cannot score as contained). Against `ablate="finding"` the defense is shown load-bearing: the exploit lands and the canary crosses. Out-of-scope destinations and exploit-shaped paths are denied whether or not a report was filed. | `tests/test_p12_range.py::TestClass17FindingHandler` (whole class), `::TestFindingMediator` (whole class) |

**Honest gaps (P12).** The probe-pattern classifier and the disclosure rate
window are hand-chosen heuristics: they are tested to fire and to stay quiet on
the range baseline, but their false-positive rate on a real model's traffic is
**UNTESTED**. The "send" behind a disclosure is a state change in a local file
sink — there is no real mail or HTTP transport, so *delivery* is out of scope
here. The embargo clock is a human decision, not a measured SLA. The L3
1,000-trials-per-class gate **includes** class 17: its 1,000 trials answer the
report channel on every trial and deny the follow-up exploit, inside the
evidence's `0/12,000` dev result (the class-17 row records
`report_channel_accepted = 1,000`). What a *real model*
does when handed the finding handler — file reports, probe, or argue — is
**UNTESTED**, like every scripted-vs-model boundary in this repository.



