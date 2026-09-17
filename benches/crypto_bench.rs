use anonguard::mesh::sybil::{solve_pow_bounded, verify_pow};
use anonguard::onion::cell::{CellCommand, OnionCell};
use anonguard::onion::circuit::{HopKeys, RelayCircuitHop};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn bench_pow(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof of Work");
    let difficulty: u32 = 20;
    let timestamp: u64 = 1600000000;

    group.bench_function("solve_pow_20", |b| {
        b.iter(|| {
            solve_pow_bounded(black_box("test_domain"), black_box(timestamp), difficulty).unwrap()
        })
    });

    let nonce = solve_pow_bounded("test_domain", timestamp, difficulty).unwrap();
    group.bench_function("verify_pow", |b| {
        b.iter(|| {
            verify_pow(
                black_box("test_domain"),
                black_box(timestamp),
                black_box(nonce),
                black_box(difficulty),
                black_box(timestamp),
            )
        })
    });
    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("AEAD Cell Crypto");

    let forward_key = [1u8; 32];
    let backward_key = [2u8; 32];
    let mac_key = [3u8; 32];
    let mut hop = RelayCircuitHop::new(
        1234,
        HopKeys {
            forward_key,
            backward_key,
            forward_mac: mac_key,
            backward_mac: mac_key,
        },
        0,
    );

    let payload = vec![0u8; 995];
    let cell = OnionCell::new(1234, 1, CellCommand::Data, 1, &payload).unwrap();
    let raw = cell.serialize();

    group.bench_function("peel_forward", |b| {
        b.iter(|| {
            let mut scratch = raw;
            let seq = hop.expected_recv_seq;
            scratch[4..8].copy_from_slice(&seq.to_be_bytes());
            black_box(hop.peel_forward(&mut scratch).unwrap())
        })
    });

    group.finish();
}

criterion_group!(benches, bench_pow, bench_aead);
criterion_main!(benches);
