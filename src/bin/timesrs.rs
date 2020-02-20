use pairing::bls12_381::*;
use pistis::poe::*;
use pistis::ro::RO;
use pistis::usrs::*;
use rand::Rng;
use sha3::Sha3_256;
use std::time::Instant;

const DS: &'static [usize] = &[
    0x00_00_10, 0x00_00_20, 0x00_00_40, 0x00_00_80, 0x00_01_00, 0x00_02_00,
    0x00_04_00, 0x00_08_00, 0x00_10_00, 0x00_20_00, 0x00_40_00, 0x00_80_00,
    0x01_00_00, 0x02_00_00, 0x04_00_00, 0x08_00_00, 0x10_00_00,
];

type Fischlin =
    FischlinTransform<DualProofOfExponentSigmaProtocol<G1Affine, Sha3_256>>;

fn main() {
    let mut rng = Sha3_256::query(&[
        0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a, 0x60, 0x1d, 0xe2, 0x7e,
        0xa8, 0x97, 0x34, 0xb9,
    ])
    .into_rng();
    //// Test plain updates/verifies
    //for d in DS.iter() {
    //    let srs = USRS::new(*d).permute(&rng.gen());
    //    let t0 = Instant::now();
    //    let upd = Update::<Bls12, Fischlin>::new(&srs, &mut rng);
    //    println!("P {},{}", d, t0.elapsed().as_millis());
    //    let t0 = Instant::now();
    //    assert!(upd.verify(&srs, &mut rng));
    //    println!("V {},{}", d, t0.elapsed().as_millis());
    //}
    // For d=1000, prove and verify update chains up to length 10,000
    for l in (1..=100).map(|i| i * 100) {
        let mut agg = AggregateUpdate::<Bls12, Fischlin>::new(2);
        for _ in 0..l {
            agg.append(Update::new(agg.as_ref(), &mut rng));
        }
        let t0 = Instant::now();
        assert!(agg.verify(&mut rng));
        println!("AV {},{}", l, t0.elapsed().as_millis());
    }
}
