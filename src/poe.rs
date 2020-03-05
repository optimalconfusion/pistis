use crate::ro::RO;
use crate::util::Split;
use ff::{Field, PrimeField};
use group::{CurveAffine, CurveProjective};
use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, Rng};
use rayon::prelude::*;
use std::marker::PhantomData;

pub trait Relation {
    /// The type of statements
    type X;
    /// The type of witnesses
    type W;

    /// Tests if (`x`, `w`) is in the proof relation
    fn check(x: &Self::X, w: &Self::W) -> bool;
}

/// A non-interactive zero-knowledge proof scheme
pub trait NIZK: Relation {
    /// The type of proofs
    type Proof;

    /// Creates a proof that (`x`, `w`) is in the proof relation
    ///
    /// # Panics
    ///
    /// May panic if [`check(x, w)`] is `false`.
    ///
    /// [`check(x, w)`]: #method.check
    fn prove<R: Split + Rng + CryptoRng>(
        x: &Self::X,
        w: &Self::W,
        rng: &mut R,
    ) -> Self::Proof
    where
        R: Send;
    /// Verifies a proof against a statement.
    ///
    /// Must return `true` for valid proofs, and false for unsatisfiable
    /// statements.
    fn verify(x: &Self::X, pi: &Self::Proof) -> bool;
}

/// A non-interactive zero-knowledge 'proof' for statements in which knowledge of the statement is
/// sufficient to prove knowledge of the witness. The knowledge of exponent assumption is an
/// instance of an implicit NIZK.
pub struct ImplicitNIZK<X, W, H>(PhantomData<(X, W, H)>);

impl<X, W, H> Relation for ImplicitNIZK<X, W, H> {
    type X = X;
    type W = W;

    fn check(_: &Self::X, _: &Self::W) -> bool {
        true
    }
}

impl<X, W, H> NIZK for ImplicitNIZK<X, W, H> {
    type Proof = ();

    fn prove<R: Split + Rng + CryptoRng>(
        _: &Self::X,
        _: &Self::W,
        _: &mut R,
    ) -> Self::Proof {
        ()
    }

    fn verify(_: &Self::X, _: &Self::Proof) -> bool {
        true
    }
}

/// Fischlin's transform [1] applied to a given sigma protocol.
///
/// [1] Marc Fischlin. Communication-efficient non-interactive proofs of knowledge with online
/// extractors. CRYPTO 2005.
pub struct FischlinTransform<S: SigmaProtocol, H: RO + ?Sized>(
    PhantomData<(S, H)>,
);

// Fischlin transform constants. These are the original constants presented in
// the paper + 2. Achieves 128-bit security.
const FISHLIN_ZERO_BITS: usize = 11;
const FISHLIN_REPETITIONS: usize = 12;
const FISHLIN_SAMPLES: usize = 0x8000; // 2^14
const FISHLIN_SUM: u32 = 12;

/// Iterprets as an integer of `FISHLIN_ZERO_BITS` length.
fn fischlin_bits(bytes: &[u8]) -> u32 {
    let mut word = 0;
    for i in 0..4 {
        word <<= 8;
        word |= bytes[i] as u32;
    }
    word >> (32 - FISHLIN_ZERO_BITS)
}

impl<T: SigmaProtocol, H: RO + ?Sized> Relation for FischlinTransform<T, H> {
    type X = T::X;
    type W = T::W;

    fn check(x: &Self::X, w: &Self::W) -> bool {
        T::check(x, w)
    }
}

impl<T: SigmaProtocol, H: RO + ?Sized> NIZK for FischlinTransform<T, H>
where
    Standard: Distribution<T::C>,
    T::X: AsRef<[u8]> + Sync,
    T::W: AsRef<[u8]> + Sync,
    T::T: AsRef<[u8]> + Send,
    T::C: AsRef<[u8]>,
    T::R: AsRef<[u8]> + Send,
    (T::T, u16, T::R): Sync,
{
    type Proof = Vec<(T::T, u16, T::R)>;

    fn prove<R: Split + Rng + CryptoRng>(
        x: &Self::X,
        w: &Self::W,
        rng: &mut R,
    ) -> Self::Proof
    where
        R: Send,
    {
        let rngs = (0..FISHLIN_REPETITIONS)
            .map(|_| rng.split())
            .collect::<Vec<_>>();
        // Repeat FISHLIN_REPETITIONS times, threaded, with an rng for each.
        rngs.into_par_iter()
            .enumerate()
            .map(|(i, mut rng)| {
                // Start the sigma protocol
                let (z, t) = T::prove_step_1(x, w, &mut rng);
                let mut min_idx: usize = 0;
                let mut min_r: Option<T::R> = None;
                let mut min_val: u32 = u32::max_value();
                // Sample challenges until the result has a low enough hash.
                for j in 0..FISHLIN_SAMPLES {
                    // Challenge is uniquely determined by stage 1, repetition and sample no. This
                    // departs from the paper, through RO.
                    let c = H::seq_query(
                        &[
                            x.as_ref(),
                            t.as_ref(),
                            &(i as u8).to_le_bytes()[..],
                            &(j as u16).to_le_bytes()[..],
                        ][..],
                    )
                    .into_rng()
                    .gen();
                    let r = T::prove_step_2(x, w, &z, &c);
                    // Randomness from the challenge/response pair must be low.
                    let rnd =
                        H::seq_query(&[t.as_ref(), c.as_ref(), r.as_ref()][..])
                            .raw();
                    let bits = fischlin_bits(rnd.as_ref());
                    if bits < min_val || min_r.is_none() {
                        min_r = Some(r);
                        min_val = bits;
                        min_idx = j;
                        if bits == 0 {
                            break;
                        }
                    };
                }
                (
                    t,
                    min_idx as u16,
                    min_r.expect("at least one sample is generated"),
                )
            })
            .collect::<Vec<_>>()
        // FIXME: This has a small chance of failing. (proof not being correct)
        //  - calculate the chance
        //  - if non-negligible: increase FISHLIN_SAMPLES, or simply rerun on failure.
    }

    fn verify(x: &Self::X, pi: &Self::Proof) -> bool {
        if pi.len() != FISHLIN_REPETITIONS {
            return false;
        }
        // For each repetition
        let bits = pi
            .par_iter()
            .enumerate()
            .map(|(i, &(ref t, j, ref r))| {
                // Reconstruct the challenge
                let c = H::seq_query(
                    &[
                        &x.as_ref(),
                        &t.as_ref(),
                        &(i as u8).to_le_bytes()[..],
                        &(j as u16).to_le_bytes()[..],
                    ][..],
                )
                .into_rng()
                .gen();
                // Verify sigma protocol
                if !T::finish_verify(x, t, &c, r) {
                    None
                } else {
                    // And record the result bits
                    let rnd =
                        H::seq_query(&[t.as_ref(), c.as_ref(), r.as_ref()][..])
                            .raw();
                    Some(fischlin_bits(rnd.as_ref()))
                }
            })
            .collect::<Vec<_>>();
        if bits.iter().any(|b| b.is_none()) {
            return false;
        }
        // Ensure sufficiently small sum
        bits.iter().fold(0, |n, b| n + b.unwrap()) <= FISHLIN_SUM
    }
}

/// A Sigma protocol
pub trait SigmaProtocol: Relation {
    /// Auxiliary prover information passed from the first to the second proving step.
    type Z; //: Copy;
    /// The initial commitment
    type T; //: Copy;
    /// The challenge
    type C; //: Copy;
    /// The challenge response
    type R; //: Copy;

    /// Step 1: Create commitments.
    fn prove_step_1<R: Rng + CryptoRng + ?Sized>(
        x: &Self::X,
        w: &Self::W,
        rng: &mut R,
    ) -> (Self::Z, Self::T);
    /// Step 2: Respond to challenge
    fn prove_step_2(
        x: &Self::X,
        w: &Self::W,
        z: &Self::Z,
        c: &Self::C,
    ) -> Self::R;
    /// Final verification.
    fn finish_verify(
        x: &Self::X,
        t: &Self::T,
        c: &Self::C,
        r: &Self::R,
    ) -> bool;
}

/// The Fiat-Shamir transform of a sigma protocol.
pub struct FiatShamirTransform<T: SigmaProtocol, H: RO + ?Sized>(
    PhantomData<(T, H)>,
);

impl<T: SigmaProtocol, H: RO + ?Sized> Relation for FiatShamirTransform<T, H> {
    type X = T::X;
    type W = T::W;

    fn check(x: &Self::X, w: &Self::W) -> bool {
        T::check(x, w)
    }
}

impl<T: SigmaProtocol, H: RO + ?Sized> NIZK for FiatShamirTransform<T, H>
where
    Standard: Distribution<T::C>,
    T::X: AsRef<[u8]>,
    T::T: AsRef<[u8]>,
{
    type Proof = (T::T, T::R);

    fn prove<R: Split + Rng + CryptoRng>(
        x: &Self::X,
        w: &Self::W,
        rng: &mut R,
    ) -> Self::Proof {
        assert!(T::check(x, w));
        let (z, t) = T::prove_step_1(x, w, rng);
        let c = H::seq_query(&[x.as_ref(), t.as_ref()][..]).into_rng().gen();
        let r = T::prove_step_2(x, w, &z, &c);
        (t, r)
    }

    fn verify(x: &Self::X, &(ref t, ref r): &Self::Proof) -> bool {
        let c = H::seq_query(&[x.as_ref(), t.as_ref()][..]).into_rng().gen();
        T::finish_verify(x, t, &c, r)
    }
}

/// A sigma protocol proving knowledge of pairs of exponents used to construct pairs of group
/// elements.
pub struct DualProofOfExponentSigmaProtocol<C: CurveAffine>(PhantomData<C>);

#[derive(PartialEq, Eq)]
/// A pair of curve elements
pub struct CurvePair<C: CurveAffine>(pub C, pub C, Vec<u8>);

impl<C: CurveAffine> CurvePair<C> {
    pub fn new(a: C, b: C) -> Self {
        let mut vec = Vec::new();
        vec.extend(a.into_uncompressed().as_ref().iter().cloned());
        vec.extend(b.into_uncompressed().as_ref().iter().cloned());
        CurvePair(a, b, vec)
    }
}

/// A pair of field elements
pub struct FieldPair<F: PrimeField>(pub F, pub F, Vec<u8>);

impl<F: PrimeField> FieldPair<F> {
    pub fn new(a: F, b: F) -> Self {
        let mut vec = Vec::new();
        for i in [a, b].iter() {
            for word in i.into_repr().as_ref() {
                vec.extend(word.to_le_bytes().iter())
            }
        }
        FieldPair(a, b, vec)
    }
}

impl<C: CurveAffine> AsRef<[u8]> for CurvePair<C> {
    fn as_ref(&self) -> &[u8] {
        self.2.as_ref()
    }
}

impl<F: PrimeField> AsRef<[u8]> for FieldPair<F> {
    fn as_ref(&self) -> &[u8] {
        self.2.as_ref()
    }
}

impl<F: PrimeField> Distribution<FieldPair<F>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> FieldPair<F> {
        FieldPair::new(F::random(rng), F::random(rng))
    }
}

impl<C: CurveAffine> Relation for DualProofOfExponentSigmaProtocol<C> {
    type X = CurvePair<C>;
    type W = FieldPair<C::Scalar>;

    fn check(x: &Self::X, w: &Self::W) -> bool {
        &CurvePair::new(
            C::one().mul(w.0).into_affine(),
            C::one().mul(w.1).into_affine(),
        ) == x
    }
}

impl<C: CurveAffine> SigmaProtocol for DualProofOfExponentSigmaProtocol<C> {
    type Z = FieldPair<C::Scalar>;
    type T = CurvePair<C>;
    type C = FieldPair<C::Scalar>;
    type R = FieldPair<C::Scalar>;

    fn prove_step_1<R: Rng + CryptoRng + ?Sized>(
        _: &Self::X,
        _: &Self::W,
        rng: &mut R,
    ) -> (Self::Z, Self::T) {
        let z = FieldPair::new(C::Scalar::random(rng), C::Scalar::random(rng));
        let t = CurvePair::new(
            C::one().mul(z.0).into_affine(),
            C::one().mul(z.1).into_affine(),
        );
        (z, t)
    }

    fn prove_step_2(
        _: &Self::X,
        &FieldPair(a, b, _): &Self::W,
        &FieldPair(mut v, mut w, _): &Self::Z,
        &FieldPair(mut c, mut d, _): &Self::C,
    ) -> Self::R {
        c.mul_assign(&a);
        d.mul_assign(&b);
        v.sub_assign(&c);
        w.sub_assign(&d);
        FieldPair::new(v, w)
    }

    fn finish_verify(
        &CurvePair(a, b, _): &Self::X,
        &CurvePair(t, u, _): &Self::T,
        &FieldPair(c, d, _): &Self::C,
        &FieldPair(r, s, _): &Self::R,
    ) -> bool {
        let mut t_prime = C::one().mul(r);
        t_prime.add_assign(&a.mul(c));
        let mut u_prime = C::one().mul(s);
        u_prime.add_assign(&b.mul(d));
        t_prime.into_affine() == t && u_prime.into_affine() == u
    }
}
