use sha3::{Digest, Sha3_256};
use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::{CryptoRng, SeedableRng};
use std::marker::PhantomData;

pub struct ROOutput<H: RO + ?Sized> {
    raw: H::RawOutput,
    ctr: usize,
    phantom: PhantomData<H>,
}

impl<H: RO + ?Sized> ROOutput<H> {
    pub fn new(raw: H::RawOutput) -> Self {
        ROOutput {
            raw: raw,
            ctr: 0,
            phantom: PhantomData,
        }
    }

    pub fn raw(self) -> H::RawOutput {
        self.raw
    }

    pub fn into_rng(self) -> BlockRng<Self> {
        BlockRng::new(self)
    }
}

impl<H: RO + ?Sized> BlockRngCore for ROOutput<H> {
    type Item = u32;
    type Results = Vec<u32>;

    fn generate(&mut self, results: &mut Self::Results) {
        let outp = H::seq_query(&[self.raw.as_ref(), &self.ctr.to_le_bytes()[..]][..]).raw();
        let mut iter = outp.as_ref().iter();
        self.ctr += 1;
        *results = Vec::new();
        loop {
            let mut nxt = [0; 4];
            for i in 0..4 {
                if let Some(&b) = iter.next() {
                    nxt[i] = b;
                } else {
                    break;
                }
            }
            results.push(u32::from_le_bytes(nxt));
        }
    }
}

impl<H: RO + ?Sized> SeedableRng for ROOutput<H> {
    type Seed = H::RawOutput;

    fn from_seed(seed: Self::Seed) -> Self {
        Self::new(seed)
    }
}

impl<H: RO + ?Sized> CryptoRng for ROOutput<H> { }

pub trait RO {
    type RawOutput: AsRef<[u8]> + AsMut<[u8]> + Default;

    fn query(i: &[u8]) -> ROOutput<Self>;

    fn seq_query(i: &[&[u8]]) -> ROOutput<Self> {
        let mut vec = Vec::new();
        for inp in i.iter() {
            vec.extend(inp.iter());
        }
        Self::query(&vec[..])
    }
}

impl RO for Sha3_256 {
    type RawOutput = [u8; 32];

    fn query(i: &[u8]) -> ROOutput<Self> {
        let mut sha = Sha3_256::new();
        sha.input(i);
        let mut res = Self::RawOutput::default();
        res.copy_from_slice(sha.result().as_ref());
        ROOutput::new(res)
    }

    fn seq_query(i: &[&[u8]]) -> ROOutput<Self> {
        let mut sha = Sha3_256::new();
        for inp in i.iter() {
            sha.input(inp.iter());
        }
        let mut res = Self::RawOutput::default();
        res.copy_from_slice(sha.result().as_ref());
        ROOutput::new(res)
    }
}
