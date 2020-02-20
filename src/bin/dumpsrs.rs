use pistis::usrs::USRS;
use pistis::ro::RO;
use rand::Rng;
use sha3::Sha3_256;
use pairing::bls12_381::Bls12;
use std::fs::File;

pub fn main() {
    let mut rng = Sha3_256::query(&[
        0x1d, 0xe2, 0x4c, 0xd1, 0xea, 0x6d, 0x83, 0x66, 0x6c, 0x3f, 0x12, 0x6e,
        0x5d, 0xc1, 0x1c, 0xbc,
    ]).into_rng();
    let srs = USRS::<Bls12>::new(100_000).permute(&rng.gen());
    let f = File::create("test.srs").unwrap();
    srs.export(f).unwrap();
}
