import re

with open('src/gateway/server.rs', 'r') as f:
    content = f.read()

# 1. Update signature
old_sig = """pub async fn handle_onion_relay_connection(
    mut client: TcpStream,
    kill_switch: Option<KillSwitchController>,
    jitter: Option<JitterEngine>,
    exit_policy: Option<crate::kernel::ExitPolicy>,
    relay_identity_key: &Ed25519SigningKey,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {"""
new_sig = """pub async fn handle_onion_relay_connection(
    mut client: GuardedSocket<ActiveGuarded>,
    kill_switch_arc: std::sync::Arc<std::sync::atomic::AtomicBool>,
    jitter: Option<JitterEngine>,
    exit_policy: Option<crate::kernel::ExitPolicy>,
    relay_identity_key: &Ed25519SigningKey,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {"""
content = content.replace(old_sig, new_sig, 1)

# 2. Update caller (in Relay mode where handle_onion_relay_connection is called)
# Notice we added `kill_switch.atomic_handle()`
# Old call was:
#                        let _ = handle_onion_relay_connection(
#                            client,
#                            Some(kill_switch.clone()),
#                            jitter.clone(),
#                            Some(exit_policy),
#                            &relay_identity_key,
#                        )
#                        .await;
caller_regex = re.compile(r'let _ = handle_onion_relay_connection\(\s*client,\s*Some\(kill_switch\.clone\(\)\),\s*jitter\.clone\(\),\s*Some\(exit_policy\),\s*&relay_identity_key,\s*\)\s*\.await;', re.MULTILINE)
new_caller = """let _ = handle_onion_relay_connection(
                            client,
                            kill_switch.atomic_handle(),
                            jitter.clone(),
                            Some(exit_policy),
                            &relay_identity_key,
                        )
                        .await;"""
content = caller_regex.sub(new_caller, content, 1)

# 3. Update the loop variables inside handle_onion_relay_connection
old_loop_vars = """    let mut downstream: Option<TcpStream> = None;
    let mut is_exit = false;
    let mut rx_kill = kill_switch.as_ref().map(|ks| ks.subscribe());

    loop {
        if let Some(ref ks) = kill_switch {
            if ks.is_tripped() {
                break;
            }
        }

        let mut client_buf = [0u8; ONION_CELL_SIZE];

        let kill_wait = async {
            if let Some(ref mut rx) = rx_kill {
                while rx.changed().await.is_ok() {
                    if *rx.borrow() {
                        return;
                    }
                }
            } else {
                std::future::pending::<()>().await;
            }
        };"""
new_loop_vars = """    let mut downstream: Option<GuardedSocket<ActiveGuarded>> = None;
    let mut is_exit = false;

    loop {
        let mut client_buf = [0u8; ONION_CELL_SIZE];"""
content = content.replace(old_loop_vars, new_loop_vars, 1)

# 4. Remove `_ = kill_wait => break,` everywhere
content = content.replace("_ = kill_wait => break,\n", "")

# 5. Fix the first EXTEND branch
old_extend_1 = """                        Ok(PeelResult::AddressedToThisRelay(CellCommand::Extend, payload)) => {
                            if let Ok((next_h, next_p, next_pub)) = decode_extend_payload(&payload) {
                                match policy.resolve_and_connect(&next_h, next_p).await {
                                    Ok(mut next_s) => {
                                        if let Ok(c_cell) = build_create_cell(relay_hop.circuit_id, &next_pub) {
                                            if next_s.write_all(&c_cell.serialize()).await.is_ok() {
                                                let mut resp = [0u8; ONION_CELL_SIZE];
                                                if next_s.read_exact(&mut resp).await.is_ok() {
                                                    relay_hop.wrap_backward_aead(&mut resp);
                                                    let _ = client.write_all(&resp).await;
                                                    downstream = Some(next_s);
                                                    is_exit = false;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Relay blocked or failed to connect to next hop {}:{}: {}", next_h, next_p, e);
                                        break;
                                    }
                                }
                            }
                        }"""
new_extend_1 = """                        Ok(PeelResult::AddressedToThisRelay(CellCommand::Extend, payload)) => {
                            let extend_ok = async {
                                let (next_h, next_p, next_pub) = decode_extend_payload(&payload)
                                    .map_err(|e| format!("bad EXTEND payload: {e}"))?;
                                let mut next_s = policy.resolve_and_connect(&next_h, next_p).await
                                    .map_err(|e| format!("next hop {next_h}:{next_p} unreachable: {e}"))?;
                                let c_cell = build_create_cell(relay_hop.circuit_id, &next_pub)
                                    .map_err(|e| format!("failed to build CREATE cell: {e}"))?;
                                next_s.write_all(&c_cell.serialize()).await
                                    .map_err(|e| format!("failed to write CREATE to next hop: {e}"))?;
                                let mut resp = [0u8; ONION_CELL_SIZE];
                                next_s.read_exact(&mut resp).await
                                    .map_err(|e| format!("no CREATED response from next hop: {e}"))?;
                                Ok::<_, String>((next_s, resp))
                            }.await;

                            match extend_ok {
                                Ok((next_s, mut resp)) => {
                                    relay_hop.wrap_backward_aead(&mut resp);
                                    if client.write_all(&resp).await.is_err() { break; }
                                    downstream = Some(GuardedSocket::new(next_s, kill_switch_arc.clone()).begin_verification().mark_verified());
                                    is_exit = false;
                                }
                                Err(e) => {
                                    error!("EXTEND failed on circuit {}: {}", relay_hop.circuit_id, e);
                                    let seq = relay_hop.next_send_seq;
                                    relay_hop.next_send_seq += 1;
                                    if let Ok(destroy_cell) = OnionCell::new(relay_hop.circuit_id, seq, CellCommand::Destroy, 0, &[]) {
                                        let mut wire = destroy_cell.serialize();
                                        relay_hop.wrap_backward_aead(&mut wire);
                                        let _ = client.write_all(&wire).await;
                                    }
                                    break;
                                }
                            }
                        }"""
content = content.replace(old_extend_1, new_extend_1, 1)


# 6. Fix the second EXTEND branch
old_extend_2 = """                            Ok(PeelResult::AddressedToThisRelay(CellCommand::Extend, payload)) => {
                                if let Ok((next_h, next_p, next_pub)) = decode_extend_payload(&payload) {
                                    if let Ok(mut next_s) = policy.resolve_and_connect(&next_h, next_p).await {
                                        if let Ok(c_cell) = build_create_cell(relay_hop.circuit_id, &next_pub) {
                                            if next_s.write_all(&c_cell.serialize()).await.is_ok() {
                                                let mut resp = [0u8; ONION_CELL_SIZE];
                                                if next_s.read_exact(&mut resp).await.is_ok() {
                                                    relay_hop.wrap_backward_aead(&mut resp);
                                                    let _ = client.write_all(&resp).await;
                                                    downstream = Some(next_s);
                                                }
                                            }
                                        }
                                    }
                                }
                            }"""
new_extend_2 = """                            Ok(PeelResult::AddressedToThisRelay(CellCommand::Extend, payload)) => {
                                let extend_ok = async {
                                    let (next_h, next_p, next_pub) = decode_extend_payload(&payload)
                                        .map_err(|e| format!("bad EXTEND payload: {e}"))?;
                                    let mut next_s = policy.resolve_and_connect(&next_h, next_p).await
                                        .map_err(|e| format!("next hop {next_h}:{next_p} unreachable: {e}"))?;
                                    let c_cell = build_create_cell(relay_hop.circuit_id, &next_pub)
                                        .map_err(|e| format!("failed to build CREATE cell: {e}"))?;
                                    next_s.write_all(&c_cell.serialize()).await
                                        .map_err(|e| format!("failed to write CREATE to next hop: {e}"))?;
                                    let mut resp = [0u8; ONION_CELL_SIZE];
                                    next_s.read_exact(&mut resp).await
                                        .map_err(|e| format!("no CREATED response from next hop: {e}"))?;
                                    Ok::<_, String>((next_s, resp))
                                }.await;

                                match extend_ok {
                                    Ok((next_s, mut resp)) => {
                                        relay_hop.wrap_backward_aead(&mut resp);
                                        if client.write_all(&resp).await.is_err() { break; }
                                        downstream = Some(GuardedSocket::new(next_s, kill_switch_arc.clone()).begin_verification().mark_verified());
                                    }
                                    Err(e) => {
                                        error!("EXTEND failed on circuit {}: {}", relay_hop.circuit_id, e);
                                        let seq = relay_hop.next_send_seq;
                                        relay_hop.next_send_seq += 1;
                                        if let Ok(destroy_cell) = OnionCell::new(relay_hop.circuit_id, seq, CellCommand::Destroy, 0, &[]) {
                                            let mut wire = destroy_cell.serialize();
                                            relay_hop.wrap_backward_aead(&mut wire);
                                            let _ = client.write_all(&wire).await;
                                        }
                                        break;
                                    }
                                }
                            }"""
content = content.replace(old_extend_2, new_extend_2, 1)

# 7. Update target_s wrapping in RELAY branch
old_relay = """                                match policy.resolve_and_connect(&target_h, target_p).await {
                                    Ok(target_s) => {
                                        let seq = relay_hop.next_send_seq;
                                        relay_hop.next_send_seq += 1;
                                        if let Ok(resp_cell) = OnionCell::new(
                                            relay_hop.circuit_id,
                                            seq,
                                            CellCommand::Relay,
                                            0,
                                            b"CONNECTED",
                                        ) {
                                            let mut resp = resp_cell.serialize();
                                            relay_hop.wrap_backward_aead(&mut resp);
                                            let _ = client.write_all(&resp).await;
                                            downstream = Some(target_s);
                                            is_exit = true;
                                        }
                                    }"""
new_relay = """                                match policy.resolve_and_connect(&target_h, target_p).await {
                                    Ok(target_s) => {
                                        let seq = relay_hop.next_send_seq;
                                        relay_hop.next_send_seq += 1;
                                        if let Ok(resp_cell) = OnionCell::new(
                                            relay_hop.circuit_id,
                                            seq,
                                            CellCommand::Relay,
                                            0,
                                            b"CONNECTED",
                                        ) {
                                            let mut resp = resp_cell.serialize();
                                            relay_hop.wrap_backward_aead(&mut resp);
                                            let _ = client.write_all(&resp).await;
                                            downstream = Some(GuardedSocket::new(target_s, kill_switch_arc.clone()).begin_verification().mark_verified());
                                            is_exit = true;
                                        }
                                    }"""
content = content.replace(old_relay, new_relay, 1)

with open('src/gateway/server.rs', 'w') as f:
    f.write(content)
