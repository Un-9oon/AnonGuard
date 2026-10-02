# Lock Order Audit

## `src/mesh/pool.rs`
`ProxyPool` manages multiple `RwLock`s. When multiple locks must be held, the enforced acquisition order to prevent deadlocks is strictly top-down:
1. `nodes` 
2. `identity_keys`
3. `guard_state` 
4. `guard_state_path`

*Verified: `load_from_multi_consensus` acquires `nodes` then `identity_keys` (Safe).*
*Verified: `get_diverse_onion_chain_with_exit` acquires `nodes`, then `guard_state`, then `guard_state_path` (Safe).*

## `src/mesh/tracker.rs`
The rendezvous tracker maintains:
- `Directory: Arc<RwLock<HashMap<String, ReverseNodeEntry>>>`
- `ReverseNodeEntry::streams: Arc<Mutex<Vec<...>>>`

The enforced acquisition order is:
1. `Directory`
2. `ReverseNodeEntry::streams`

*Verified: `CONNECT_REVERSE` drops the `Directory` lock before acquiring `streams` (Safe).*
*Verified: `REGISTER_REVERSE` and `GET /nodes` hold `Directory` while acquiring `streams` (Safe, matches order).*

## `src/gateway/server.rs` (`IpGuard`)
The `GatewayServer` tracks per-IP connection counts via:
- `ip_connections: Arc<RwLock<HashMap<IpAddr, u32>>>`

*Verified: This lock is only ever acquired in isolation (increment on accept, decrement in `IpGuard::drop()`). It never nests with other locks (Safe).*
