//! Task F: Morphing Engine Evaluation
//!
//! This test file evaluates AnonGuard's traffic morphing engine by calling the
//! ACTUAL implementation functions — NOT a reimplementation.
//!
//! Specifically: `morph_bidirectional_guarded` from `anonguard::morphing` with
//! all three JitterEngine variants (Poisson, Chaos/Lorenz, RMT).
//!
//! Each test:
//! 1. Calls the real morphing function.
//! 2. Measures the observed throughput (bytes transferred / elapsed time).
//! 3. Verifies byte-exact content preservation after morphing.
//! 4. Verifies that the function completes (does not hang or panic).

use anonguard::morphing::{
    morph_bidirectional_guarded, JitterEngine, LorenzAttractor, PoissonJitter, RmtEnsemble,
    RmtTimingEngine,
};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAYLOAD_SIZE: usize = 32 * 1024; // 32 KB

/// Helper: run morph_bidirectional_guarded with the given JitterEngine.
///
/// Returns (bytes_from_a_to_b, bytes_from_b_to_a, elapsed_ms).
async fn run_morph(jitter: JitterEngine) -> (u64, u64, u64) {
    let (client_a, mut server_a) = tokio::io::duplex(65536);
    let (client_b, mut server_b) = tokio::io::duplex(65536);

    let jitter_clone = jitter.clone();

    // Spawn the morphing engine (it reads/writes the server sides).
    let morph_task = tokio::spawn(async move {
        morph_bidirectional_guarded(&mut server_a, &mut server_b, Some(jitter_clone), None).await
    });

    let payload_a = vec![0xA5u8; PAYLOAD_SIZE];
    let payload_b = vec![0x5Au8; PAYLOAD_SIZE];
    let expected_a = payload_a.clone();
    let expected_b = payload_b.clone();

    let (mut client_a_read, mut client_a_write) = tokio::io::split(client_a);
    let (mut client_b_read, mut client_b_write) = tokio::io::split(client_b);

    let start = Instant::now();

    let write_a = tokio::spawn(async move {
        client_a_write.write_all(&payload_a).await.unwrap();
        client_a_write.shutdown().await.unwrap();
    });

    let read_b = tokio::spawn(async move {
        let mut buf = Vec::new();
        client_b_read.read_to_end(&mut buf).await.unwrap();
        buf
    });

    let write_b = tokio::spawn(async move {
        client_b_write.write_all(&payload_b).await.unwrap();
        client_b_write.shutdown().await.unwrap();
    });

    let read_a = tokio::spawn(async move {
        let mut buf = Vec::new();
        client_a_read.read_to_end(&mut buf).await.unwrap();
        buf
    });

    let (res_wa, res_rb, res_wb, res_ra) = tokio::join!(write_a, read_b, write_b, read_a);

    res_wa.unwrap();
    res_wb.unwrap();
    let received_by_b = res_rb.unwrap();
    let received_by_a = res_ra.unwrap();

    let elapsed = start.elapsed().as_millis() as u64;
    let _ = morph_task.await;

    assert_eq!(
        received_by_b, expected_a,
        "Bytes transferred A→B must be byte-exact after morphing"
    );
    assert_eq!(
        received_by_a, expected_b,
        "Bytes transferred B→A must be byte-exact after morphing"
    );

    (PAYLOAD_SIZE as u64, PAYLOAD_SIZE as u64, elapsed)
}

/// Task F evaluation — Poisson JitterEngine.
///
/// Calls `morph_bidirectional_guarded` with `JitterEngine::Poisson`.
/// Verifies byte-exact content preservation and measures throughput.
#[tokio::test]
async fn test_morph_bidirectional_poisson_jitter() {
    let jitter = JitterEngine::Poisson(PoissonJitter::new(
        0.5,  // rate: 0.5 packets/ms (2ms mean inter-packet gap)
        1.0,  // min_ms
        10.0, // max_ms
    ));

    let (a_to_b, b_to_a, elapsed_ms) = run_morph(jitter).await;

    let throughput_kbps = if elapsed_ms > 0 {
        ((a_to_b + b_to_a) * 8 * 1000) / (elapsed_ms * 1024)
    } else {
        0
    };

    println!(
        "[Poisson] Transferred {}/{} bytes in {}ms (~{} kbps)",
        a_to_b, b_to_a, elapsed_ms, throughput_kbps
    );

    // The morphed stream must transfer all bytes in both directions.
    assert_eq!(a_to_b, PAYLOAD_SIZE as u64);
    assert_eq!(b_to_a, PAYLOAD_SIZE as u64);
    // Throughput with Poisson jitter should be non-zero (function must not hang).
    assert!(
        elapsed_ms < 30_000,
        "Morphed transfer must complete within 30s"
    );
}

/// Task F evaluation — Chaos/Lorenz JitterEngine.
///
/// Calls `morph_bidirectional_guarded` with `JitterEngine::Chaos` (Lorenz Attractor).
/// Verifies byte-exact content preservation.
#[tokio::test]
async fn test_morph_bidirectional_chaos_lorenz_jitter() {
    // Lorenz attractor parameters: sigma=10.0, rho=28.0, beta=8/3, dt=0.01
    let lorenz = LorenzAttractor::new(10.0, 28.0, 8.0 / 3.0, 0.01);
    let jitter = JitterEngine::Chaos(lorenz);

    let (a_to_b, b_to_a, elapsed_ms) = run_morph(jitter).await;

    let throughput_kbps = if elapsed_ms > 0 {
        ((a_to_b + b_to_a) * 8 * 1000) / (elapsed_ms * 1024)
    } else {
        0
    };

    println!(
        "[Chaos/Lorenz] Transferred {}/{} bytes in {}ms (~{} kbps)",
        a_to_b, b_to_a, elapsed_ms, throughput_kbps
    );

    assert_eq!(a_to_b, PAYLOAD_SIZE as u64);
    assert_eq!(b_to_a, PAYLOAD_SIZE as u64);
    assert!(
        elapsed_ms < 30_000,
        "Morphed transfer must complete within 30s"
    );
}

/// Task F evaluation — RMT JitterEngine.
///
/// Calls `morph_bidirectional_guarded` with `JitterEngine::Rmt`.
/// Verifies byte-exact content preservation.
#[tokio::test]
async fn test_morph_bidirectional_rmt_jitter() {
    let rmt = RmtTimingEngine::new(RmtEnsemble::GOE, 1.0, 500); // 1ms mean, 500-byte base chunk size
    let jitter = JitterEngine::Rmt(rmt);

    let (a_to_b, b_to_a, elapsed_ms) = run_morph(jitter).await;

    let throughput_kbps = if elapsed_ms > 0 {
        ((a_to_b + b_to_a) * 8 * 1000) / (elapsed_ms * 1024)
    } else {
        0
    };

    println!(
        "[RMT] Transferred {}/{} bytes in {}ms (~{} kbps)",
        a_to_b, b_to_a, elapsed_ms, throughput_kbps
    );

    assert_eq!(a_to_b, PAYLOAD_SIZE as u64);
    assert_eq!(b_to_a, PAYLOAD_SIZE as u64);
    assert!(
        elapsed_ms < 30_000,
        "Morphed transfer must complete within 30s"
    );
}

/// Task F evaluation — killswitch abort.
///
/// Calls `morph_bidirectional_guarded` with a pre-tripped kill switch.
/// Must return an error immediately (not hang or transfer any data).
#[tokio::test]
async fn test_morph_bidirectional_killswitch_abort() {
    use anonguard::kernel::KillSwitchController;

    let (mut a, mut b) = tokio::io::duplex(4096);
    let ks = KillSwitchController::with_threshold(1, std::time::Duration::from_secs(1));
    ks.trip("test: pre-tripped kill switch");

    let jitter = JitterEngine::Poisson(PoissonJitter::new(0.5, 1.0, 10.0));
    let result = morph_bidirectional_guarded(&mut a, &mut b, Some(jitter), Some(ks)).await;

    assert!(
        result.is_err(),
        "morph_bidirectional_guarded must return Err when kill switch is pre-tripped"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ConnectionAborted,
        "Kill switch error must be ConnectionAborted"
    );
}

/// Task F evaluation — zero-jitter pass-through.
///
/// Calls `morph_bidirectional_guarded` with `jitter = None`.
/// Should transparently copy bytes (like tokio::io::copy_bidirectional).
#[tokio::test]
async fn test_morph_bidirectional_no_jitter() {
    let (mut client_a, mut server_a) = tokio::io::duplex(65536);
    let (mut client_b, mut server_b) = tokio::io::duplex(65536);

    let morph_task = tokio::spawn(async move {
        morph_bidirectional_guarded(&mut server_a, &mut server_b, None, None).await
    });

    let payload = vec![0xBEu8; 8192];
    let expected = payload.clone();

    let client_task = tokio::spawn(async move {
        client_a.write_all(&payload).await.unwrap();
        let _ = client_a.shutdown().await;
        let mut received = Vec::new();
        client_a.read_to_end(&mut received).await.unwrap();
        received
    });

    let _ = client_b.shutdown().await;
    let mut received_by_b = Vec::new();
    client_b.read_to_end(&mut received_by_b).await.unwrap();

    let _received_by_a = client_task.await.unwrap();
    let _ = morph_task.await;

    assert_eq!(
        received_by_b, expected,
        "Zero-jitter pass-through must preserve bytes exactly"
    );
    println!(
        "[No Jitter] Transferred {} bytes (pass-through mode)",
        received_by_b.len()
    );
}
