//! Local proof-of-concept tests for round-3 review. Not part of the upstream suite.
use anonguard::core::state_machine::GuardedSocket;
use anonguard::gateway::server::handle_onion_relay_connection;
use anonguard::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE};
use anonguard::onion::circuit::{
    build_create_cell, encode_relay_target, perform_client_relay_handshake, process_created_cell,
    OnionCircuit, RelayCircuitHop,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn deliver(client: &mut OnionCircuit, cell: &[u8; ONION_CELL_SIZE]) -> Result<(), String> {
    let mut w = *cell;
    client
        .unwrap_backward(&mut w)
        .map(|_| ())
        .map_err(|e| format!("{e}"))
}

#[test]
fn poc_replay_window_gap_off_by_one() {
    let (ck, rk) = perform_client_relay_handshake();
    let cid = 0x1122_3344;
    let mut client = OnionCircuit::new(cid);
    client.add_hop(ck).unwrap();
    let mut relay = RelayCircuitHop::new(cid, rk, 0);

    let mut cells = Vec::new();
    for n in 1..=6u8 {
        let c = OnionCell::new(cid, 0, CellCommand::Data, 1, &[n]).unwrap();
        let mut w = c.serialize();
        relay.wrap_backward_originate(&mut w).unwrap();
        cells.push(w);
    }
    // in-order delivery of counters 1,2,3
    for i in 0..3 {
        deliver(&mut client, &cells[i]).expect("in-order cell rejected");
    }
    // cells 4 and 5 are dropped in transit (e.g. by a malicious middle relay); 6 arrives
    deliver(&mut client, &cells[5]).expect("cell 6 rejected");

    let replay_1 = deliver(&mut client, &cells[0]);
    println!(
        "replay of already-delivered counter 1 after gap: {:?}",
        replay_1
    );
    let late_4 = deliver(&mut client, &cells[3]);
    println!(
        "legit never-seen counter 4 arriving late:       {:?}",
        late_4
    );

    assert!(replay_1.is_err(), "replay should be rejected");
    assert!(late_4.is_ok(), "legit cell should be accepted");
}

async fn one_hop_exit(dest: SocketAddr) -> (TcpStream, OnionCircuit) {
    one_hop_exit_opt(dest, false).await
}

/// `chunked`: put a proxy between client and relay that re-segments the client->relay byte
/// stream into 700-byte pieces (what a 1500-byte-MTU path does to 1024-byte cells).
async fn one_hop_exit_opt(dest: SocketAddr, chunked: bool) -> (TcpStream, OnionCircuit) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        let ks = Arc::new(AtomicBool::new(false));
        let g = GuardedSocket::new(s, ks.clone())
            .begin_verification()
            .mark_verified();
        let _ = handle_onion_relay_connection(
            g,
            ks,
            None,
            Some(anonguard::kernel::ExitPolicy::new(true)),
            &sk,
            true,
            anonguard::mesh::pool::ProxyPool::new(),
        )
        .await;
    });

    let addr = if chunked {
        let pl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let paddr = pl.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = pl.accept().await.unwrap();
            let mut r = TcpStream::connect(addr).await.unwrap();
            r.set_nodelay(true).unwrap();
            let (mut cr, mut cw) = c.split();
            let (mut rr, mut rw) = r.split();
            let c2s = async {
                let mut buf = [0u8; 16384];
                loop {
                    let n = cr.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    for piece in buf[..n].chunks(700) {
                        if rw.write_all(piece).await.is_err() {
                            return;
                        }
                        let _ = rw.flush().await;
                        tokio::time::sleep(Duration::from_micros(700)).await;
                    }
                }
            };
            let s2c = tokio::io::copy(&mut rr, &mut cw);
            let _ = tokio::join!(c2s, s2c);
        });
        paddr
    } else {
        addr
    };
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.set_nodelay(true).unwrap();
    let cid = 0x2a2b_2c2d;
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let create = build_create_cell(cid, &public, 0).unwrap();
    s.write_all(&create.serialize()).await.unwrap();
    let mut buf = [0u8; ONION_CELL_SIZE];
    s.read_exact(&mut buf).await.unwrap();
    let created = OnionCell::parse(&buf).unwrap();
    let keys = process_created_cell(&created, secret, public.as_bytes(), &pk, cid, 0).unwrap();
    let mut circ = OnionCircuit::new(cid);
    circ.add_hop(keys).unwrap();

    let payload = encode_relay_target(&dest.ip().to_string(), dest.port()).unwrap();
    let mut rc = OnionCell::new(cid, 1, CellCommand::Relay, 0, &payload).unwrap();
    let w = circ.wrap_forward(&mut rc).unwrap();
    s.write_all(&w).await.unwrap();
    let mut rb = [0u8; ONION_CELL_SIZE];
    s.read_exact(&mut rb).await.unwrap();
    let (_, resp) = circ.unwrap_backward(&mut rb).unwrap();
    assert_eq!(resp.command, CellCommand::Relay);
    (s, circ)
}

async fn run_case(split: bool) -> (bool, bool) {
    let received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let dest_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest_addr = dest_l.local_addr().unwrap();
    let rec = received.clone();
    tokio::spawn(async move {
        let (s, _) = dest_l.accept().await.unwrap();
        let (mut r, mut w) = s.into_split();
        // destination trickles data back (a normal bidirectional exchange)
        tokio::spawn(async move {
            loop {
                if w.write_all(b".").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        });
        let mut b = [0u8; 2048];
        loop {
            match r.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => rec.lock().unwrap().extend_from_slice(&b[..n]),
            }
        }
    });

    let (mut s, mut circ) = one_hop_exit(dest_addr).await;
    let cid = circ.circuit_id;

    let mut b = OnionCell::new(cid, 0, CellCommand::Data, 1, b"PAYLOAD-B").unwrap();
    let wb = circ.wrap_forward(&mut b).unwrap();
    if split {
        s.write_all(&wb[..512]).await.unwrap();
        s.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        s.write_all(&wb[512..]).await.unwrap();
    } else {
        s.write_all(&wb).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(600)).await;

    let mut c = OnionCell::new(cid, 0, CellCommand::Data, 1, b"PAYLOAD-C").unwrap();
    let wc = circ.wrap_forward(&mut c).unwrap();
    s.write_all(&wc).await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;

    let got = received.lock().unwrap().clone();
    let has = |needle: &[u8]| got.windows(needle.len()).any(|w| w == needle);
    (has(b"PAYLOAD-B"), has(b"PAYLOAD-C"))
}

#[tokio::test]
async fn poc_relay_read_exact_cancel_desync() {
    let (b1, c1) = run_case(false).await;
    println!("control (whole-cell writes):    B delivered={b1}, C delivered={c1}");
    let (b2, c2) = run_case(true).await;
    println!("cell split across two segments: B delivered={b2}, C delivered={c2}");
    assert!(b1 && c1, "control must work");
    assert!(b2, "a cell that straddles two reads should be delivered");
}

/// Bulk client->exit upload while the destination is also sending: count how many of the
/// N uploaded cells actually reach the destination.
#[tokio::test]
async fn poc_relay_burst_loss_rate() {
    const TOTAL: usize = 300;
    const BATCH: usize = 10;
    let received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let dest_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest_addr = dest_l.local_addr().unwrap();
    let rec = received.clone();
    tokio::spawn(async move {
        let (s, _) = dest_l.accept().await.unwrap();
        let (mut r, mut w) = s.into_split();
        tokio::spawn(async move {
            loop {
                if w.write_all(b"x").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let mut b = [0u8; 4096];
        loop {
            match r.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => rec.lock().unwrap().extend_from_slice(&b[..n]),
            }
        }
    });
    let (s, mut circ) = one_hop_exit_opt(dest_addr, true).await;
    let cid = circ.circuit_id;
    let (mut rd, mut wr) = s.into_split();
    tokio::spawn(async move {
        let mut sink = [0u8; 8192];
        while let Ok(n) = rd.read(&mut sink).await {
            if n == 0 {
                break;
            }
        }
    });
    let mut n = 0usize;
    while n < TOTAL {
        let mut burst = Vec::with_capacity(BATCH * ONION_CELL_SIZE);
        for _ in 0..BATCH {
            let tag = format!("T{:05}", n);
            let mut c = OnionCell::new(cid, 0, CellCommand::Data, 1, tag.as_bytes()).unwrap();
            burst.extend_from_slice(&circ.wrap_forward(&mut c).unwrap());
            n += 1;
        }
        wr.write_all(&burst).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let got = received.lock().unwrap().clone();
    let mut delivered = 0usize;
    let mut i = 0;
    while i + 6 <= got.len() {
        if got[i] == b'T' && got[i + 1..i + 6].iter().all(|b| b.is_ascii_digit()) {
            delivered += 1;
            i += 6;
        } else {
            i += 1;
        }
    }
    println!("uploaded {TOTAL} cells in bursts of {BATCH} (re-segmented to 700B pieces) while destination replies; delivered {delivered}");
    assert_eq!(delivered, TOTAL, "all cells should be delivered");
}
