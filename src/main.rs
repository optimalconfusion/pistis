extern crate ff;
extern crate group;
extern crate pairing;
extern crate rand;
extern crate rand_core;
extern crate rayon;
extern crate sha3;

pub mod poe;
pub mod ro;
pub mod usrs;
mod util;

use std::time::Instant;
use ff::ScalarEngine;
use pairing::bls12_381::Bls12;
use pairing::Engine;
use rand_core::block::BlockRng;
use ro::{RO, ROOutput};
use poe::{
    CurvePair, DualProofOfExponentSigmaProtocol, FieldPair, FischlinTransform,
    ImplicitNIZK, NIZK,
};
use sha3::Sha3_256;
use usrs::{Update, USRS};

type Pairing = Bls12;
type Hash = Sha3_256;

type Implicit = ImplicitNIZK<
    CurvePair<<Pairing as Engine>::G2Affine>,
    FieldPair<<Pairing as ScalarEngine>::Fr>,
    Hash,
>;
type Sigma =
    DualProofOfExponentSigmaProtocol<<Pairing as Engine>::G2Affine, Hash>;
type Fischlin = FischlinTransform<
    DualProofOfExponentSigmaProtocol<<Pairing as Engine>::G2Affine, Hash>,
>;

fn run_test_update<
    N: NIZK<
        X = CurvePair<<Pairing as Engine>::G2Affine>,
        W = FieldPair<<Pairing as ScalarEngine>::Fr>,
    >,
    H: RO + ?Sized,
>(
    srs: USRS<Pairing>,
    rng: &mut BlockRng<ROOutput<H>>,
)
where
  ROOutput<H>: Send,
{
    let start = Instant::now();
    let u1 = Update::<Pairing, N>::new(&srs, rng);
    println!("{} ms", start.elapsed().as_millis());
    let start = Instant::now();
    assert!(u1.verify(&srs, rng));
    println!("{} ms", start.elapsed().as_millis());
}

fn main() {
    let mut rng = Sha3_256::query(&[
        0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a,
        0x60, 0x1d, 0xe2, 0x7e, 0xa8, 0x97, 0x34, 0xb9,
    ]).into_rng();

    let srs0: USRS<Pairing> = USRS::new(100_000);
    let srs1 = Update::<Pairing, Implicit>::new(&srs0, &mut rng).into();
    if option_env!("PISTIS_FISCHLIN").is_some() {
        run_test_update::<Fischlin, _>(srs1, &mut rng);
    } else if option_env!("PISTIS_SIGMA").is_some() {
        run_test_update::<Sigma, _>(srs1, &mut rng);
    } else {
        run_test_update::<Implicit, _>(srs1, &mut rng);
    }
}
