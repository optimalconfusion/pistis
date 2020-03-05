use pairing::bls12_381::*;
use pistis::poe::*;
use pistis::ro::RO;
use pistis::usrs::*;
use rand::Rng;
use sha3::Sha3_256;
use std::env::args;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{stdout, Write};
use std::path::Path;
use std::time::Instant;

const DS: &'static [usize] = &[
    0x00_00_02, 0x00_00_04, 0x00_00_08, 0x00_00_10, 0x00_00_20, 0x00_00_40,
    0x00_00_80, 0x00_01_00, 0x00_02_00, 0x00_04_00, 0x00_08_00, 0x00_10_00,
    0x00_20_00, 0x00_40_00, 0x00_80_00, 0x01_00_00, 0x02_00_00, 0x04_00_00,
    0x08_00_00, 0x10_00_00,
];

const TRIALS_SMALL: usize = 100;
const TRIALS_LARGE: usize = 10;

type Fischlin =
    FischlinTransform<DualProofOfExponentSigmaProtocol<G1Affine>, Sha3_256>;

fn file<P: AsRef<Path>>(path: P) -> File {
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .unwrap()
}

fn main() {
    let mut skip = match args().skip(1).next().map(|arg| arg.parse::<usize>()) {
        Some(Ok(skip)) => skip,
        _ => 0,
    };
    let mut rng = Sha3_256::query(&[
        0x2a, 0xb1, 0x74, 0x52, 0x0f, 0x19, 0x34, 0x2a, 0x60, 0x1d, 0xe2, 0x7e,
        0xa8, 0x97, 0x34, 0xb9,
    ])
    .into_rng();
    create_dir_all("data").unwrap();
    let mut prove_data = file("data/prove.csv");
    let mut verify_data = file("data/verify.csv");
    let mut agg_data = file("data/agg_verify.csv");
    // Test plain updates/verifies
    for (i, d) in DS.iter().enumerate().skip(skip) {
        let trials = if *d < 0x01_00_00 {
            TRIALS_SMALL
        } else {
            TRIALS_LARGE
        };
        print!("{} - {}/", i, d);
        stdout().flush().unwrap();
        let srss = (0..trials)
            .map(|_| USRS::new(*d).permute(&rng.gen()))
            .collect::<Vec<_>>();
        print!("S");
        stdout().flush().unwrap();
        let tu_upd = srss
            .iter()
            .map(|srs| {
                let t0 = Instant::now();
                let upd = Update::<Bls12, Fischlin>::new(&srs, &mut rng);
                let tu = t0.elapsed().as_millis();
                (tu, upd)
            })
            .collect::<Vec<_>>();
        print!("P");
        let tv = srss
            .iter()
            .zip(tu_upd.iter())
            .map(|(srs, (_, upd))| {
                let t0 = Instant::now();
                assert!(upd.verify(&srs, &mut rng));
                t0.elapsed().as_millis()
            })
            .collect::<Vec<_>>();
        let avg_tu: u128 =
            tu_upd.iter().map(|(t, _)| *t).sum::<u128>() / trials as u128;
        let avg_tv: u128 = tv.into_iter().sum::<u128>() / trials as u128;
        writeln!(&mut prove_data, "{},{}", d, avg_tu).unwrap();
        writeln!(&mut verify_data, "{},{}", d, avg_tv).unwrap();
        println!("V");
    }
    if skip > DS.len() {
        skip -= DS.len();
    } else {
        skip = 0;
    }
    // For d=2, prove and verify update chains up to length 10,000
    let mut aggs = (0..TRIALS_SMALL)
        .map(|_| AggregateUpdate::<Bls12, Fischlin>::new(2))
        .collect::<Vec<_>>();
    for i in (0..=3).skip(skip) {
        let l = i * 100;
        print!("{} - {}/", i + DS.len(), l);
        stdout().flush().unwrap();
        let tav: u128 = aggs
            .iter_mut()
            .map(|agg| {
                let t0 = Instant::now();
                assert!(agg.verify(&mut rng));
                t0.elapsed().as_millis()
            })
            .sum::<u128>()
            / TRIALS_SMALL as u128;
        writeln!(&mut agg_data, "{},{}", l, tav).unwrap();
        print!("AV");
        stdout().flush().unwrap();
        for _ in 0..100 {
            for agg in aggs.iter_mut() {
                agg.append(Update::new(agg.as_ref(), &mut rng));
            }
        }
        println!("S");
    }
}
