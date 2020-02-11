#![feature(test)]

extern crate test;

use ff::Field;
use group::{CurveAffine, CurveProjective};
use pairing::bls12_381::*;
use pistis::poe::{
    CurvePair, DualProofOfExponentSigmaProtocol, FieldPair, FischlinTransform,
    NIZK,
};
use pistis::ro::RO;
use sha3::Sha3_256;
use test::Bencher;

type Fischlin<C> =
    FischlinTransform<DualProofOfExponentSigmaProtocol<C, Sha3_256>>;
type Sigma<C> = DualProofOfExponentSigmaProtocol<C, Sha3_256>;

fn bench_prove<
    C: CurveAffine,
    N: NIZK<X = CurvePair<C>, W = FieldPair<C::Scalar>>,
>(
    b: &mut Bencher,
) {
    const SAMPLES: usize = 1_000;
    let mut rng = Sha3_256::query(&[
        0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a, 0x60, 0x1d, 0xe2, 0x7e,
        0xa8, 0x97, 0x34, 0xb9,
    ])
    .into_rng();
    let bases =
        [(C::Scalar::random(&mut rng), C::Scalar::random(&mut rng)); SAMPLES];
    let pairs = bases
        .iter()
        .map(|(e1, e2)| {
            (
                CurvePair(
                    C::one().mul(*e1).into_affine(),
                    C::one().mul(*e2).into_affine(),
                ),
                FieldPair(*e1, *e2),
            )
        })
        .collect::<Vec<_>>();
    let mut idx = 0;
    b.iter(|| {
        idx = (idx + 1) % SAMPLES;
        N::prove(pairs[idx].0, pairs[idx].1, &mut rng)
    });
}

fn bench_verify<
    C: CurveAffine,
    N: NIZK<X = CurvePair<C>, W = FieldPair<C::Scalar>>,
>(
    b: &mut Bencher,
) {
    const SAMPLES: usize = 1_000;
    let mut rng = Sha3_256::query(&[
        0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a, 0x60, 0x1d, 0xe2, 0x7e,
        0xa8, 0x97, 0x34, 0xb9,
    ])
    .into_rng();
    let bases =
        [(C::Scalar::random(&mut rng), C::Scalar::random(&mut rng)); SAMPLES];
    let pairs = bases
        .iter()
        .map(|(e1, e2)| {
            let x = CurvePair(
                C::one().mul(*e1).into_affine(),
                C::one().mul(*e2).into_affine(),
            );
            (x, N::prove(x, FieldPair(*e1, *e2), &mut rng))
        })
        .collect::<Vec<_>>();
    let mut idx = 0;
    b.iter(|| {
        idx = (idx + 1) % SAMPLES;
        N::verify(pairs[idx].0, &pairs[idx].1)
    });
}

#[bench]
fn bench_prove_fischlin_g1(b: &mut Bencher) {
    bench_prove::<G1Affine, Fischlin<G1Affine>>(b);
}

#[bench]
fn bench_prove_fischlin_g2(b: &mut Bencher) {
    bench_prove::<G2Affine, Fischlin<G2Affine>>(b);
}

#[bench]
fn bench_prove_sigma_g1(b: &mut Bencher) {
    bench_prove::<G1Affine, Sigma<G1Affine>>(b);
}

#[bench]
fn bench_prove_sigma_g2(b: &mut Bencher) {
    bench_prove::<G2Affine, Sigma<G2Affine>>(b);
}

#[bench]
fn bench_verify_fischlin_g1(b: &mut Bencher) {
    bench_verify::<G1Affine, Fischlin<G1Affine>>(b);
}

#[bench]
fn bench_verify_fischlin_g2(b: &mut Bencher) {
    bench_verify::<G2Affine, Fischlin<G2Affine>>(b);
}

#[bench]
fn bench_verify_sigma_g1(b: &mut Bencher) {
    bench_verify::<G1Affine, Sigma<G1Affine>>(b);
}

#[bench]
fn bench_verify_sigma_g2(b: &mut Bencher) {
    bench_verify::<G2Affine, Sigma<G2Affine>>(b);
}
