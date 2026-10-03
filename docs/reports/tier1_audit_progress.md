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

---

## Session 3 Results

### `src/gateway/multipath_router.rs` — REVIEWED, NO SECURITY FINDINGS

**State-before-validation check:** No AEAD/signature/MAC/PoW logic in this file.
State mutations:
- `path_loads[c_idx] += 1` at line 107 — load-balancing counter, not a security-relevant
  state. No validation to order it against.
- `client_seqs[c_idx] += 1` at line 112 — onion-circuit sequence counter, advanced inside
  a locked `circuits_fwd[c_idx]` guard, before the `OnionCell::new` call. No crypto check
  here, but this is a local send-side counter with no security invariant depending on it
  (the relay-side AEAD decryption in the receive path is what protects against replay —
  verified separately in `transport.rs`). Not a state-before-validation instance.
- `read_bytes[idx] += n` at line 200, then `reassembler.receive(data)` at line 215 —
  the byte accumulator is not a security counter; it tracks how many bytes of the fixed-size
  `ONION_CELL_SIZE` frame have arrived. `reassembler.receive()` validates the multipath
  header. Order is correct.

**`Exp::new(1.0 / 20.0).unwrap()` at line 50:** Rate is 0.05, valid positive finite f64.
Unreachable by design. Consistent with audit doc's classification.

**`tokio::select!` cancel-safety (Tier 4):** The `poll_fn` based read at lines 168–195
manually tracks `read_bytes[i]` per upstream. This is cancel-safe by construction — the
`poll_fn` is stateless; state lives in `read_bytes` which persists across polls.
No data loss on cancellation. ✓

**`stream_multipath_circuits` outer `tokio::select!` (lines 247–255):** Selects `bwd`
vs. `fwd`. `fwd` is pinned and guarded with `if !fwd_done`, which is the standard Tokio
pattern for re-polling a completed future. Cancel-safe. ✓

**NOT audited:** Sphinx packet format (not in this file).

---

### `src/kernel/netns.rs` — REVIEWED, NO FINDINGS

**State-before-validation check:** No state, no mutations. Pure nftables rule-generator
and shell command wrapper.

**`generate_nftables_rules`:** Validates `authorized_proxy_ip` via `str::parse::<IpAddr>()`
(line 25), returning `Err` on invalid input **before** formatting any output. ✓

**`apply_nftables_rules`:** Calls `generate_nftables_rules()?` at line 60 (propagating
error), then pipes to `nft -f -`. Process exit code is checked (lines 74–80); on non-zero
exit, returns `Err` with the stderr message. No state mutation on failure.

**`flush_nftables_rules`:** Calls `nft delete table ...`, checks exit code at line 93.
Returns `Err` on failure.

**Kill-switch fail-closed under `kill -9` (master prompt's specific question for this
module):** `netns.rs` generates and applies nftables rules. Once applied to the kernel,
nftables rules persist independently of the process — if the daemon is `kill -9`'d, the
rules remain in effect, blocking all non-proxy traffic. **This is the correct
fail-closed behavior.** Flushing only happens in the graceful-exit path in `main.rs`
(lines 752–762). A hard kill leaves rules intact. ✓

---

### `src/core/state_machine.rs` — REVIEWED, NO FINDINGS

**State-before-validation check:** Not applicable — this module has no AEAD/sig/PoW checks.
Its entire purpose is a type-state pattern enforcing that only `GuardedSocket<ActiveGuarded>`
can transmit data, and that the `Verifying → ActiveGuarded` transition (via `mark_verified`)
is only reachable by calling `begin_verification()` first, which can only be called on
`Uninitialized`.

**Kill-switch check:** `send_guarded` and `recv_guarded` both check the `AtomicBool` via
`Ordering::SeqCst` before any I/O (lines 101, 115). `poll_read` and `poll_write` also check
at the start of each poll (lines 156, 179). No data flows to/from a tripped socket.

**`fail_verification` (line 86):** immediately `store(true, SeqCst)` on the kill-switch
**before** returning the `DroppedFailClosed` socket. This is fail-closed: even if the
caller doesn't inspect the returned socket, the kill-switch is already tripped.

**`Drop` impl (line 218–226):** spawns a task to call `.shutdown()` on the inner stream.
This is a best-effort graceful close; there is no panic or state-before-validation issue.

---

### `src/main.rs` — REVIEWED, ONE OPEN QUESTION

**State-before-validation check:** No direct AEAD/sig/PoW mutations visible in `main.rs`
itself. Consensus retrieval loop (lines 554–663) fetches documents, validates peer keys
against `auth_keys`, and calls `load_from_multi_consensus` — all state mutations delegated
to `pool.rs` (verified safe in Session 2).

**`--enable-firewall-killswitch` nftables failure (lines 346–353):** On `apply_nftables_rules()`
failure, the daemon **logs a warning and continues** without the kernel-level killswitch
(falls back to process-level). This is exactly the "fail-open-with-a-warning" pattern that
Part A Rule 7 identifies as not a real fix.

**Citation:** `src/main.rs` lines 346–353.
**Mechanism:** Operator enables `--enable-firewall-killswitch` expecting kernel-level
traffic isolation. If `nft` is unavailable or `CAP_NET_ADMIN` is missing, the daemon
continues with only the application-layer kill-switch, without any indication to the user
beyond a log line that may not be visible.
**Status:** SUSPECTED FINDING — mismatches Part A Rule 7 (warn-and-proceed ≠ fix).
Downgraded from confirmed because `--strict-fail-closed` (line 155) exists as an operator
escape hatch that will abort startup on precisely this condition. If `--strict-fail-closed`
is always used alongside `--enable-firewall-killswitch`, the behavior is correct.
The question is whether the documentation makes this coupling clear enough, or whether a
user can accidentally run with `--enable-firewall-killswitch` alone and believe they have
kernel-level isolation when they don't. **Not a code bug if documented clearly; needs a
doc check against `THREAT_MODEL.md` or the README.**

**`allow_open_socks5` / `allow_private_exit` gate (lines 415–420):** Requires explicit
`--i-know-this-is-insecure` flag to proceed. Correct fail-closed design per Rule 4.

**Consensus `quorum_threshold = 0` clamp (lines 529–536):** Clamps to 1 if authorities are
configured and threshold is 0, with a warning. This is correct — 0-of-N consensus would be
vacuously true.

---

## Tier 4 Fixes Applied This Session

### CI fuzz wiring — FIXED
**Citation:** `.github/workflows/ci.yml` lines 53–65 (after fix).
**Before:** 3 of 10 targets ran in CI.
**After:** All 10 existing targets + the new `fuzz_multipath_reassembler` now run
for 60 seconds each on every push/PR to `main`.
**Evidence:** diff committed in this session.

### `fuzz_multipath_reassembler` — ADDED
**Citation:** `fuzz/fuzz_targets/fuzz_multipath_reassembler.rs` (new file).
**Coverage:** Exercises `MultiPathReassembler::receive` and `pop_next_buffered` with
arbitrary byte inputs including frames shorter than 8 bytes, arbitrary sequence numbers,
and sequences pushing the `MAX_SEQ_GAP`/`MAX_BUFFERED_ENTRIES` bounds established by the
F5 fix. Registered in `fuzz/Cargo.toml` and wired into CI.

---

## Modules NOT Yet Covered (Remaining Open Tier 1 Work)

- `src/gateway/chain.rs` — not yet read
- `src/gateway/server.rs` — not yet read in full (only partial coverage of auth paths)
- `src/mesh/authority.rs` — not yet fully audited
- Sphinx packet format — location not yet confirmed (not in `multipath_router.rs`)
- Guard-state persistence (`GuardState::save`/`load`) tamper-resistance
- `--enable-firewall-killswitch` + `--strict-fail-closed` coupling documentation (open question from `main.rs` audit)

