# Panic/Unwrap/Expect Audit

An exhaustive audit of `panic!`, `unwrap()`, and `expect()` usages across `src/` (excluding `cfg(test)` and test modules) reveals exactly 9 non-log instances. All 9 have been classified as **unreachable by design, provably**.

## Classification

### Cryptographic Invariants (Provably Safe)
1. **`src/mesh/transport.rs:288` & `293`**:
   - `expect("safe: HKDF-Expand only fails above 8160 bytes...")`
   - *Classification*: Unreachable by design. HKDF-Expand only returns an `Err` if the requested output size > 255 * HashLen. AnonGuard requests 32 bytes from SHA-256 (32 * 255 = 8160 limit), which is statically safe.
2. **`src/onion/circuit.rs:112` & `134`**:
   - `expect("safe: ChaCha20Poly1305 in-place detached encryption...")`
   - *Classification*: Unreachable by design. In-place authenticated encryption can only fail if the provided nonce length or key length is invalid. Both are fixed arrays (`[u8; 32]` and `[u8; 12]`), and the buffer payload length is statically verified.

### Math & Statistics (Provably Safe)
3. **`src/gateway/multipath_router.rs:50`**, **`src/gateway/chaffing.rs:47`**, **`src/onion/padding.rs:95`**:
   - `Exp::new(lambda).unwrap()`
   - *Classification*: Unreachable by design. The exponential distribution constructor `Exp::new()` only fails if `lambda <= 0` or is `NaN`. In all three usages, `lambda` is derived from static, positive constants or strictly positive config defaults (e.g. `1.0 / 20.0`).

### State & Constants (Provably Safe)
4. **`src/gateway/chaffing.rs:86`**:
   - `let ip_parts: Vec<u8> = host.split('.').map(|s| s.parse().unwrap()).collect();`
   - *Classification*: Unreachable by design. `host` is strictly drawn from `self.decoy_targets`, which is hard-coded to valid IPv4 addresses (`"1.1.1.1"`, `"8.8.8.8"`, `"9.9.9.9"`).
5. **`src/gateway/multipath_router.rs:93`**:
   - `client_buffer.pop_front().unwrap()`
   - *Classification*: Unreachable by design. The call is bounded by a loop `0..chunk_size`, where `chunk_size` is calculated dynamically as `std::cmp::min(client_buffer.len(), max_data)`. Thus, it is impossible for the buffer to be empty on pop.

*Conclusion: Zero instances are reachable from network input. No fuzz targets or Result-propagations are required.*
