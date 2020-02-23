use pairing::bls12_381::*;
use pistis::poe::*;
use pistis::ro::RO;
use pistis::usrs::*;
use rand::Rng;
use sha3::Sha3_256;
use std::time::Instant;
use std::io::{Write, stdout};
use std::fs::{create_dir_all, File};

const DS: &'static [usize] = &[
    0x00_00_02, 0x00_00_04, 0x00_00_08, 0x00_00_10, 0x00_00_20,
    0x00_00_40, 0x00_00_80, 0x00_01_00, 0x00_02_00, 0x00_04_00, 0x00_08_00,
    0x00_10_00, 0x00_20_00, 0x00_40_00, 0x00_80_00, 0x01_00_00, 0x02_00_00,
    0x04_00_00, 0x08_00_00, 0x10_00_00,
];

type Fischlin =
    FischlinTransform<DualProofOfExponentSigmaProtocol<G1Affine>, Sha3_256>;

fn main() {
    let mut rng = Sha3_256::query(&[
        0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a, 0x60, 0x1d, 0xe2, 0x7e,
        0xa8, 0x97, 0x34, 0xb9,
    ])
    .into_rng();
    create_dir_all("data").unwrap();
    let mut prove_data = File::create("data/prove.csv").unwrap();
    writeln!(&mut prove_data, "#d,runtime (prove(d))").unwrap();
    let mut verify_data = File::create("data/verify.csv").unwrap();
    writeln!(&mut prove_data, "#d,runtime (verify(d))").unwrap();
    let mut agg_data = File::create("data/agg_verify.csv").unwrap();
    writeln!(&mut prove_data, "#l,runtime (aggregate_verify(l, 2))").unwrap();
    // Test plain updates/verifies
    for d in DS.iter() {
        print!("{}/", d);
        stdout().flush().unwrap();
        let srs = USRS::new(*d).permute(&rng.gen());
        print!("S");
        stdout().flush().unwrap();
        let t0 = Instant::now();
        let upd = Update::<Bls12, Fischlin>::new(&srs, &mut rng);
        writeln!(&mut prove_data, "{},{}", d, t0.elapsed().as_millis()).unwrap();
        print!("P");
        stdout().flush().unwrap();
        let t0 = Instant::now();
        assert!(upd.verify(&srs, &mut rng));
        writeln!(&mut verify_data, "{},{}", d, t0.elapsed().as_millis()).unwrap();
        println!("V");
    }
    // For d=2, prove and verify update chains up to length 10,000
    let mut agg = AggregateUpdate::<Bls12, Fischlin>::new(2);
    for l in (1..=100).map(|i| i * 100) {
        print!("{}/", l);
        stdout().flush().unwrap();
        for _ in 0..100 {
            agg.append(Update::new(agg.as_ref(), &mut rng));
        }
        print!("S");
        stdout().flush().unwrap();
        let t0 = Instant::now();
        assert!(agg.verify(&mut rng));
        writeln!(&mut agg_data, "{},{}", l, t0.elapsed().as_millis()).unwrap();
        println!("AV");
    }
}
