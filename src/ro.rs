use sha3::{Digest, Sha3_256};

pub trait RO {
    const RO_SIZE: usize;
    fn query(i: &[u8]) -> Vec<u8>;

    fn seq_query(i: &[&[u8]]) -> Vec<u8> {
        let mut vec = Vec::new();
        for inp in i.iter() {
            vec.extend(inp.iter());
        }
        Self::query(&vec[..])
    }
}

impl RO for Sha3_256 {
    const RO_SIZE: usize = 32;

    fn query(i: &[u8]) -> Vec<u8> {
        let mut sha = Sha3_256::new();
        sha.input(i);
        sha.result().to_vec()
    }

    fn seq_query(i: &[&[u8]]) -> Vec<u8> {
        let mut sha = Sha3_256::new();
        for inp in i.iter() {
            sha.input(inp.iter());
        }
        sha.result().to_vec()
    }
}
