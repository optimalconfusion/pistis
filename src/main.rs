extern crate ff;
extern crate group;
extern crate pairing;
extern crate rand;
extern crate rand_core;
extern crate sha3;

pub mod poe;
pub mod ro;
pub mod usrs;

use pairing::bls12_381::Bls12;
use pairing::Engine;
use ff::ScalarEngine;
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha3::Sha3_256;
use usrs::{Update, USRS};
use poe::{FischlinTransform, DualProofOfExponentSigmaProtocol, ImplicitNIZK, CurvePair, FieldPair, NIZK};

type Pairing = Bls12;
type Hash = Sha3_256;

type Implicit = ImplicitNIZK<CurvePair<<Pairing as Engine>::G2Affine>, FieldPair<<Pairing as ScalarEngine>::Fr>, Hash>;
type Sigma = DualProofOfExponentSigmaProtocol<<Pairing as Engine>::G2Affine, Hash>;
type Fischlin = FischlinTransform<DualProofOfExponentSigmaProtocol<<Pairing as Engine>::G2Affine, Hash>>;

fn run_test_update<N: NIZK<X=CurvePair<<Pairing as Engine>::G2Affine>,W=FieldPair<<Pairing as ScalarEngine>::Fr>>, R: Rng + ?Sized>(srs: USRS<Pairing>, rng: &mut R) {
    let u1 = Update::<Pairing, N>::new(&srs, rng);
    assert!(u1.verify(&srs));
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42);

    let srs0: USRS<Pairing> = USRS::new(1_000);
    let srs1 = Update::<Pairing, Implicit>::new(&srs0, &mut rng).into();
    if option_env!("PISTIS_FISCHLIN").is_some() {
        run_test_update::<Fischlin, _>(srs1, &mut rng);
    } else if option_env!("PISTIS_SIGMA").is_some() {
        run_test_update::<Sigma, _>(srs1, &mut rng);
    } else {
        run_test_update::<Implicit, _>(srs1, &mut rng);
    }
}
