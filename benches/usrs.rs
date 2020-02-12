
extern crate criterion;

use criterion::{Criterion, BatchSize, BenchmarkId, Bencher, criterion_group, criterion_main};

use sha3::{Sha3_256};
use pairing::bls12_381::*;
use pistis::poe::*;
use pistis::ro::RO;
use pistis::usrs::*;
use rand::Rng;

type Fischlin = FischlinTransform<DualProofOfExponentSigmaProtocol<G2Affine, Sha3_256>>;

const DS: &'static [usize] = &[
    0x00_00_10, 0x00_00_20, 0x00_00_40, 0x00_00_80, 0x00_01_00,
    0x00_02_00, 0x00_04_00, 0x00_08_00, 0x00_10_00, 0x00_20_00,
    //0x00_40_00, 0x00_80_00, 0x01_00_00, 0x02_00_00, 0x04_00_00,
    //0x08_00_00, 0x10_00_00,
];

fn bench_update(b: &mut Bencher, &d: &usize) {
    b.iter_batched(
        || {
            let mut rng = Sha3_256::query(&[
                0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a,
                0x60, 0x1d, 0xe2, 0x7e, 0xa8, 0x97, 0x34, 0xb9,
            ]).into_rng();
            (USRS::<Bls12>::new(d).permute(&rng.gen()), rng)
        },
        |(srs, mut rng)| Update::<Bls12, Fischlin>::new(&srs, &mut rng),
        BatchSize::SmallInput,
    );
}

fn bench_update_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("USRS update");
    for d in DS.iter() {
        group.bench_with_input(BenchmarkId::new("update", format!("d={}", *d)), d, bench_update);
    }
    group.finish();
}

fn bench_verify(b: &mut Bencher, &d: &usize) {
    b.iter_batched(
        || {
            let mut rng = Sha3_256::query(&[
                0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a,
                0x60, 0x1d, 0xe2, 0x7e, 0xa8, 0x97, 0x34, 0xb9,
            ]).into_rng();
            let srs = USRS::new(d).permute(&rng.gen());
            let upd = Update::<Bls12, Fischlin>::new(&srs, &mut rng);
            (srs, upd, rng)
        },
        |(srs, upd, mut rng)| upd.verify(&srs, &mut rng),
        BatchSize::SmallInput,
    );
}

fn bench_verify_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("USRS update");
    for d in DS.iter() {
        group.bench_with_input(BenchmarkId::new("verify", format!("d={}", *d)), d, bench_verify);
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_update_all, bench_verify_all
}
criterion_main!(benches);
