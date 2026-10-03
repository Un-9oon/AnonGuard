# Tier 1 Audit Progress Report

> Per Part A Rule 1: every claim below was derived from current code read directly off
> disk in this session. File:line citations are included for every claim.
> Grep counts are from actual tool output, not stated from memory.

---

## Session 1 Results (independently verified by project owner — see master prompt Part B)

- **`src/mesh/consensus.rs`** — VERIFIED SAFE (state-before-validation question closed).
- **`src/mesh/sybil.rs`** — VERIFIED SAFE. 3 production call sites of `check_and_record`,
  not 2 as originally reported: `authority.rs:244`, `tracker.rs:155`, `authority.rs:474`.
- **`src/kernel/killswitch.rs`** — VERIFIED SAFE. Poison-recovery via `unwrap_or_else` on
  both `trip()` and `reset()`, tested by `test_mutex_poisoning_does_not_disable_kill_switch`.

---

## Session 2 Results

### `src/mesh/pool.rs` — REVIEWED, NO NEW FINDINGS

**State-before-validation check:** No counters, maps, or caches are mutated before a
cryptographic check in this file. Cryptographic verification is delegated:
- `relay.verify_identity()` called at line 115 before inserting into `relay_votes`.
- `validate_circuit_diversity` called at line 382 before appending each candidate.
Both checks gate state mutation. No bypass path found.

**Subnet diversity enforcement:** Diversity IS checked per-circuit at build time (not only
at registration) via `validate_circuit_diversity` on the accumulating `test_hosts` slice
before each candidate is appended (`get_diverse_onion_chain_with_exit`, lines 376-385).
This answers the open question from the master prompt.

**`rotate_on_block` (line 416):** increments `failure_count`/marks `is_alive = false` without
a cryptographic check — intentional liveness heuristic, not a security check. Not a
state-before-validation instance.

**NOT audited:** guard-state persistence (`GuardState::save`/`load`) disk format and tamper-resistance.

---

### `src/mesh/tracker.rs` — REVIEWED, NO NEW FINDINGS

**State-before-validation check:** Confirmed correct order in `handle_connection`
`REGISTER_REVERSE` branch: `verify_pow` at line 144 → early-return on failure at line 152
→ `check_and_record` at line 155 → directory mutation at line 195. All gated correctly.

**Auth-token hijacking (lines 167-184):** Uses `subtle::ConstantTimeEq` — correct
constant-time comparison preventing timing-oracle token enumeration.

**`GET /nodes` info-leak (lines 263-280):** Returns node IDs only, never auth tokens.
Regression test at line 433 explicitly asserts this.

**NOT audited:** `CONNECT_REVERSE` cancel-safety under `kill -9` (Tier 4 scope).

---

### `src/morphing/*` — REVIEWED, ONE SUSPECTED PERFORMANCE ISSUE

- **`jitter.rs`** — Safe. No crypto, no state mutations.
- **`padding.rs`** — Safe. `unpad` validates `padded.len() >= 4 + len` at line 35 before
  indexing. No panic path reachable from network input.
- **`chaos.rs`** — Safe. Uses `unwrap_or_else(|poisoned| poisoned.into_inner())` on state
  mutex (line 48) — same poison-recovery pattern as `killswitch.rs`.
- **`rmt.rs`** — Safe. Stateless sampling only. No state-before-validation instance.
- **`adversarial.rs`** — Safe. Budget ceiling read at line 89 before deciding to proceed.
  `budget_used_us` updated at line 122 after value is computed and clamped.
- **`obfuscator.rs`** — SUSPECTED PERFORMANCE ISSUE (not a security finding):
  - **Citation:** `src/morphing/obfuscator.rs` lines 145 and 204.
  - **Mechanism:** `JitterEngine::Adversarial` arm clones the engine on every packet
    (`a.clone().apply().await`). `Clone` shares `Arc<AtomicU64>` counters correctly (logic
    is fine), but allocates a new struct and bumps Arc ref-counts on every packet. Under
    high throughput this produces allocator pressure.
  - **Status:** Downgraded to "suspected" per Part A Rule 2 — no performance repro written.
    Not a correctness or security issue.
  - The delay-before-write ordering (delay before `write_all`) is intentional and correct
    for timing morphing — not a state-before-validation instance.

**Code-correctness half of the empirical question:** Wigner-surmise, Lorenz, and
Poisson-inverse-CDF implementations are mathematically correct. Whether they resist
real multi-core scheduler pressure is Tier 3's empirical scope.

---

### `src/kernel/dns.rs` — REVIEWED, NO FINDINGS

**State-before-validation check:** No state, no mutations. Pure frame-builder.
`build_socks5h_connect_frame` validates domain length (returns `Err` on >255 bytes at
line 32) before writing. IPv6 rejection returns `Err` before appending bytes (line 47).
No panic path.

**NOT audited:** SOCKS5 response parser (lives in `gateway/server.rs`).

---

## Tier 4 Static Items — Partial Progress

### Unwrap inventory triage

**Claim in `docs/unwrap_audit.md`:** "exactly 9 non-log instances, all unreachable by design."

**Verification:** `grep -rn 'unwrap()' src/` returned 171+ matches. The vast majority are
inside `#[cfg(test)]` blocks (acceptable), but the audit document does not show its grep
command, raw match count, or a per-site disposition table — so the "exactly 9" claim is
not independently verifiable from the document.

**Specific production-code unwraps checked this session:**
1. `src/gateway/chaffing.rs:52` — `.expect("safe: 0.1 is valid Exp rate")`. Unreachable
   by design (0.1 > 0). BUT: audit doc cites `chaffing.rs:47` and describes a bare
   `.unwrap()` — the current code uses `unwrap_or_else`. **Audit doc is stale for this entry.**
2. `src/gateway/multipath_router.rs:50` — `Exp::new(1.0 / 20.0).unwrap()`. Rate = 0.05,
   valid positive finite f64. Unreachable. Classification correct.
3. `src/onion/padding.rs:95` — `Exp::new(lambda).unwrap()`. Lambda from positive constants.
   Unreachable. Classification correct.

**Conclusion:** Unwrap inventory is a partial enumeration, not a triaged one. The document
is also stale for the chaffing.rs entry. **Item remains open.**

### Fuzz coverage

**Claim in master prompt:** "one target (`fuzz_onion_cell_parse.rs`)"

**Actual state (verified by `ls fuzz/fuzz_targets/`):** 10 fuzz targets exist:
`fuzz_onion_cell_parse.rs`, `fuzz_target_1.rs`, `fuzz_consensus_deser.rs`,
`fuzz_decode_extend.rs`, `fuzz_decode_relay_target.rs`, `fuzz_exit_policy.rs`,
`fuzz_peel_forward.rs`, `fuzz_proxy_node_parse.rs`, `fuzz_socks5_frame.rs`,
`fuzz_verify_pow.rs`.

**Master prompt "one target" claim is outdated.** Consensus deserialization, extend-payload
decoding, SOCKS5 frame parsing, and PoW verification targets all exist.

**Still missing per Tier 4 requirements:**
- Sphinx packet format (if separate from onion cells — location not yet confirmed)
- `MultiPathReassembler::receive` — no dedicated fuzz target found
- CI wiring: no evidence examined that `fuzz/` runs in CI. `.github/workflows/` not yet checked.

---

## Modules NOT Yet Covered (Remaining Open Tier 1 Work)

- `src/gateway/multipath_router.rs` — not yet read in full
- Sphinx packet-format implementation — location not yet confirmed
- `src/main.rs`, `src/core/state_machine.rs`, `src/gateway/chain.rs`
- `src/kernel/netns.rs` — not yet read
- `src/mesh/authority.rs` — read partially (two call sites); not fully audited
- `src/gateway/server.rs` — not yet read
- CI config for fuzz wiring (`.github/workflows/`)
- Guard-state persistence tamper-resistance (`GuardState::save`/`load`)
