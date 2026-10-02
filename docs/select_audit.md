# `tokio::select!` Cancel-Safety Audit

1. **`src/main.rs:377`**: `authority.run()` vs `ctrl_c()`. Safe. Dropping `authority.run()` is standard graceful termination.
2. **`src/main.rs:394`**: `tracker.run()` vs `ctrl_c()`. Safe.
3. **`src/main.rs:650`**: `gateway.run()` vs `ctrl_c()` vs `SIGTERM`. Safe.
4. **`src/morphing/obfuscator.rs:71`**: `tokio::io::copy_bidirectional` vs `kill_switch.changed()`. Safe. `copy_bidirectional` is safely dropped, enforcing disconnection.
5. **`src/morphing/obfuscator.rs:222`**: `tokio::join!` vs `kill_switch.changed()`. Safe.
6. **`src/gateway/multipath_router.rs:65`**: `client_read.read(&mut buf)` vs `tokio::time::sleep(delay)`. Safe, `read()` is cancel-safe in Tokio.
7. **`src/gateway/multipath_router.rs:247`**: Pinned futures `&mut bwd` vs `&mut fwd`. Safe.
