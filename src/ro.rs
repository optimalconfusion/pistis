use crate::util::Split;
use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::{CryptoRng, SeedableRng};
use sha3::{Digest, Sha3_256};
use std::marker::PhantomData;

impl<H: RO + ?Sized> Split for BlockRng<ROOutput<H>> {
    fn split(&mut self) -> Self {
        let mut res = H::BlockOutput::default();
        self.core.generate(&mut res);
        let mut seed = H::RawOutput::default();
        for (i, w) in res.as_ref().iter().enumerate() {
            for j in 0..4 {
                seed.as_mut()[4 * i + j] = ((*w >> (32 - 8 * j)) & 0xff) as u8;
            }
        }
        BlockRng::new(ROOutput {
            raw: seed,
            ctr: 0,
            phantom: PhantomData,
        })
    }
}

/// A random oracle's output
///
/// This implements a block random number generator, by feeding back into the original random
/// oracle.
pub struct ROOutput<H: RO + ?Sized> {
    raw: H::RawOutput,
    ctr: usize,
    phantom: PhantomData<H>,
}

impl<H: RO + ?Sized> ROOutput<H> {
    /// Create a new output given raw output bits.
    pub fn new(raw: H::RawOutput) -> Self {
        ROOutput {
            raw: raw,
            ctr: 0,
            phantom: PhantomData,
        }
    }

    /// Retrieve the corresponding raw output
    pub fn raw(self) -> H::RawOutput {
        self.raw
    }

    /// Converts this output into a full RNG using domain-separation on the original random oracle.
    pub fn into_rng(self) -> BlockRng<Self> {
        BlockRng::new(self)
    }
}

impl<H: RO + ?Sized> BlockRngCore for ROOutput<H> {
    type Item = u32;
    type Results = H::BlockOutput;

    fn generate(&mut self, results: &mut Self::Results) {
        // Make RO query
        let outp =
            H::seq_query(&[self.raw.as_ref(), &self.ctr.to_le_bytes()[..]][..])
                .raw();
        let mut iter = outp.as_ref().iter();
        self.ctr += 1;
        *results = Self::Results::default();
        // Populate the u32 results vector
        for i in 0..results.as_ref().len() {
            let mut nxt = [0; 4];
            for i in 0..4 {
                nxt[i] = *iter.next().expect(
                    "Block result should match raw result in byte length",
                );
            }
            results.as_mut()[i] = u32::from_le_bytes(nxt);
        }
    }
}

impl<H: RO + ?Sized> SeedableRng for ROOutput<H> {
    type Seed = H::RawOutput;

    fn from_seed(seed: Self::Seed) -> Self {
        Self::new(seed)
    }
}

impl<H: RO + ?Sized> CryptoRng for ROOutput<H> {}

/// A random oracle.
pub trait RO {
    /// The output of the random oracle
    type RawOutput: AsRef<[u8]> + AsMut<[u8]> + Default;
    /// The output, for `BlockRngCore`.
    type BlockOutput: AsRef<[u32]> + AsMut<[u32]> + Default;

    /// Makes a simple query.
    fn query(i: &[u8]) -> ROOutput<Self>;

    /// Makes a query of sequences of sequences. Often simpler to call in practice.
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
    type BlockOutput = [u32; 8];

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
