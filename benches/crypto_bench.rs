use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use anonguard::mesh::sybil::{solve_pow, verify_pow};
use anonguard::onion::cell::{OnionCell, CellCommand};
use anonguard::onion::circuit::RelayCircuitHop;

fn bench_pow(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof of Work");
    let difficulty = 20; 
    let timestamp = 1600000000;
    
    group.bench_function("solve_pow_20", |b| {
        b.iter(|| solve_pow(black_box("test_domain"), black_box(timestamp), difficulty))
    });

    let nonce = solve_pow("test_domain", timestamp, difficulty);
    group.bench_function("verify_pow", |b| {
        b.iter(|| verify_pow(black_box("test_domain"), black_box(timestamp), black_box(timestamp), black_box(nonce), difficulty))
    });
    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("AEAD Cell Crypto");
    
    let forward_key = [1u8; 32];
    let backward_key = [2u8; 32];
    let mac_key = [3u8; 32];
    let mut hop = RelayCircuitHop::new(1234, forward_key, backward_key, mac_key);
    
    let payload = vec![0u8; 995];
    let cell = OnionCell::new(1234, 1, CellCommand::Data, 1, &payload).unwrap();
    let raw = cell.serialize();

    group.bench_function("peel_forward", |b| {
        b.iter(|| {
            let mut scratch = raw.clone();
            let seq = hop.expected_recv_seq;
            scratch[4..8].copy_from_slice(&seq.to_be_bytes());
            black_box(hop.peel_forward(&mut scratch).unwrap())
        })
    });
    
    group.finish();
}

criterion_group!(benches, bench_pow, bench_aead);
criterion_main!(benches);
