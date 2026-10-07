use anonguard::mesh::sybil::{solve_pow_bounded, verify_pow};
use anonguard::onion::cell::{CellCommand, OnionCell};
use anonguard::onion::circuit::{derive_hop_keys, OnionCircuit, PeelOutcome, RelayCircuitHop};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
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

    let shared_secret = [71; 64];
    let mut client = OnionCircuit::new(1234);
    client
        .add_hop(derive_hop_keys(&shared_secret).unwrap())
        .unwrap();
    let payload = vec![0u8; 995];

    group.bench_function("peel_forward_authenticated", |b| {
        b.iter_batched(
            || {
                let mut cell = OnionCell::new(1234, 0, CellCommand::Data, 1, &payload).unwrap();
                let raw = client.wrap_forward(&mut cell).unwrap();
                let mut relay =
                    RelayCircuitHop::new(1234, derive_hop_keys(&shared_secret).unwrap(), 0);
                relay.expected_recv_seq = cell.sequence_no;
                (relay, raw)
            },
            |(mut relay, mut raw)| {
                let outcome = relay.peel_forward(black_box(&mut raw)).unwrap();
                assert!(matches!(
                    outcome,
                    PeelOutcome::AddressedToThisRelay {
                        command: CellCommand::Data,
                        len: 995
                    }
                ));
                black_box(outcome)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_cell(c: &mut Criterion) {
    let mut group = c.benchmark_group("OnionCell Parsing and Serialization");

    let payload = vec![0u8; 995];
    let cell = OnionCell::new(1234, 1, CellCommand::Data, 1, &payload).unwrap();
    let raw = cell.serialize();

    group.bench_function("cell_serialize", |b| b.iter(|| black_box(cell.serialize())));

    group.bench_function("cell_parse", |b| {
        b.iter(|| black_box(OnionCell::parse(black_box(&raw)).unwrap()))
    });

    group.finish();
}

criterion_group!(benches, bench_pow, bench_aead, bench_cell);
criterion_main!(benches);
