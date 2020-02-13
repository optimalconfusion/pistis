extern crate criterion;

use criterion::{
    criterion_group, criterion_main, BatchSize, Bencher, Criterion,
};

use ff::Field;
use group::{CurveAffine, CurveProjective};
use pairing::bls12_381::*;
use pistis::poe::*;
use pistis::ro::RO;
use sha3::Sha3_256;

type Fischlin<C> =
    FischlinTransform<DualProofOfExponentSigmaProtocol<C, Sha3_256>>;
type Sigma<C> = DualProofOfExponentSigmaProtocol<C, Sha3_256>;

fn bench_prove<
    C: CurveAffine,
    N: NIZK<X = CurvePair<C>, W = FieldPair<C::Scalar>>,
>(
    b: &mut Bencher,
) {
    b.iter_batched(
        || {
            let mut rng = Sha3_256::query(&[
                0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a, 0x60, 0x1d,
                0xe2, 0x7e, 0xa8, 0x97, 0x34, 0xb9,
            ])
            .into_rng();
            let (a, b) =
                (C::Scalar::random(&mut rng), C::Scalar::random(&mut rng));
            (
                CurvePair(
                    C::one().mul(a).into_affine(),
                    C::one().mul(b).into_affine(),
                ),
                FieldPair(a, b),
                rng,
            )
        },
        |(x, w, mut rng)| N::prove(x, w, &mut rng),
        BatchSize::SmallInput,
    );
}

fn bench_prove_all(c: &mut Criterion) {
    let mut fischlin = c.benchmark_group("prove Fischlin");
    fischlin.bench_function("G1", bench_prove::<G1Affine, Fischlin<G1Affine>>);
    fischlin.bench_function("G2", bench_prove::<G2Affine, Fischlin<G2Affine>>);
    fischlin.finish();
    let mut sigma = c.benchmark_group("prove Sigma");
    sigma.bench_function("G1", bench_prove::<G1Affine, Sigma<G1Affine>>);
    sigma.bench_function("G2", bench_prove::<G2Affine, Sigma<G2Affine>>);
    sigma.finish();
}

fn bench_verify<
    C: CurveAffine,
    N: NIZK<X = CurvePair<C>, W = FieldPair<C::Scalar>>,
>(
    b: &mut Bencher,
) {
    b.iter_batched(
        || {
            let mut rng = Sha3_256::query(&[
                0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a, 0x60, 0x1d,
                0xe2, 0x7e, 0xa8, 0x97, 0x34, 0xb9,
            ])
            .into_rng();
            let (a, b) =
                (C::Scalar::random(&mut rng), C::Scalar::random(&mut rng));
            let (x, w) = (
                CurvePair(
                    C::one().mul(a).into_affine(),
                    C::one().mul(b).into_affine(),
                ),
                FieldPair(a, b),
            );
            (x, N::prove(x, w, &mut rng))
        },
        |(x, pi)| N::verify(x, &pi),
        BatchSize::SmallInput,
    );
}

fn bench_verify_all(c: &mut Criterion) {
    let mut fischlin = c.benchmark_group("verify Fischlin");
    fischlin.bench_function("G1", bench_verify::<G1Affine, Fischlin<G1Affine>>);
    fischlin.bench_function("G2", bench_verify::<G2Affine, Fischlin<G2Affine>>);
    fischlin.finish();
    let mut sigma = c.benchmark_group("verify Sigma");
    sigma.bench_function("G1", bench_verify::<G1Affine, Sigma<G1Affine>>);
    sigma.bench_function("G2", bench_verify::<G2Affine, Sigma<G2Affine>>);
    sigma.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = bench_prove_all, bench_verify_all
}
criterion_main!(benches);
