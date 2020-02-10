extern crate ff;
extern crate group;
extern crate pairing;
extern crate rand;
extern crate rand_chacha;
extern crate sha3;

pub mod poe;
pub mod ro;
pub mod usrs;

use pairing::bls12_381::Bls12;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha3::Sha3_256;
use usrs::{Update, USRS};

fn main() {
    let mut rng = StdRng::seed_from_u64(42);

    let srs0: USRS<Bls12> = USRS::new(1_000);
    let u1 = Update::<Bls12, Sha3_256>::new(&srs0, &mut rng);
    assert!(u1.verify(&srs0));
    //let srs1: USRS<Bls12> = u1.into();
    //let t2 = rng.gen();
    //let u2 = Update::new(&srs1, &t2);
    //assert!(u2.verify(&srs1));
}
