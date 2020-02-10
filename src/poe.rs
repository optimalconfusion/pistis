use crate::ro::RO;
use ff::{Field, PrimeField};
use group::{CurveAffine, CurveProjective};
use rand::distributions::{Distribution, Standard};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::convert::TryInto;
use std::marker::PhantomData;

pub trait NIZK {
    type X;
    type W;
    type Proof;

    fn prove<R: Rng + ?Sized>(
        x: Self::X,
        w: Self::W,
        rng: &mut R,
    ) -> Self::Proof;
    fn verify(x: Self::X, pi: &Self::Proof) -> bool;
}

pub struct ImplicitNIZK<X, W, H>(PhantomData<(X, W, H)>);

impl<X, W, H> NIZK for ImplicitNIZK<X, W, H> {
    type X = X;
    type W = W;
    type Proof = ();

    fn prove<R: Rng + ?Sized>(
        _: Self::X,
        _: Self::W,
        _: &mut R,
    ) -> Self::Proof {
        ()
    }

    fn verify(_: Self::X, _: &Self::Proof) -> bool {
        true
    }
}

pub struct FischlinTransform<S: SigmaProtocol>(PhantomData<S>);

// Fischlin transform constants. These are the original constants presented in
// the paper + 2
// FIXME: Find security paramter guaranteed by this. Hopefully 1^128.
const FISHLIN_ZERO_BITS: usize = 11;
const FISHLIN_REPETITIONS: usize = 12;
const FISHLIN_SAMPLES: usize = 0x8000; // 2^14
const FISHLIN_SUM: u32 = 12;

fn fischlin_bits(bytes: &[u8]) -> u32 {
    let mut word = 0;
    for i in 0..4 {
        word <<= 8;
        word |= bytes[i] as u32;
    }
    word >> (32 - FISHLIN_ZERO_BITS)
}

impl<T: SigmaProtocol> NIZK for FischlinTransform<T>
where
    Standard: Distribution<T::C>,
    T::X: Into<Vec<u8>>,
    T::T: Into<Vec<u8>>,
    T::C: Into<Vec<u8>>,
    T::R: Into<Vec<u8>>,
{
    type X = T::X;
    type W = T::W;
    type Proof = Vec<(T::T, usize, T::R)>;

    fn prove<R: Rng + ?Sized>(
        x: Self::X,
        w: Self::W,
        rng: &mut R,
    ) -> Self::Proof {
        // Safe as each point will be initialised before read.
        let mut pi = Vec::new();
        for i in 0..FISHLIN_REPETITIONS {
            let (z, t) = T::prove_step_1(x, w, rng);
            let mut min_idx: usize = 0;
            let mut min_r: Option<T::R> = None;
            let mut min_val: u32 = u32::max_value();
            for j in 0..FISHLIN_SAMPLES {
                let rnd = T::H::seq_query(
                    &[
                        &x.into()[..],
                        &t.into()[..],
                        &i.to_le_bytes()[..],
                        &j.to_le_bytes()[..],
                    ][..],
                );
                let mut rnd_rng = ChaCha20Rng::from_seed(
                    rnd[..32].try_into().expect("32 byte seed expected"),
                );
                let c = rnd_rng.gen();
                let r = T::prove_step_2(x, w, z, c);
                let rnd2 = T::H::seq_query(
                    &[&t.into()[..], &c.into()[..], &r.into()[..]][..],
                );
                let bits = fischlin_bits(&rnd2[..]);
                if bits < min_val || min_r.is_none() {
                    min_r = Some(r);
                    min_val = bits;
                    min_idx = j;
                    if bits == 0 {
                        break;
                    }
                };
            }
            pi.push((
                t,
                min_idx,
                min_r.expect("at least one sample is generated"),
            ));
        }
        pi
    }

    fn verify(x: Self::X, pi: &Self::Proof) -> bool {
        if pi.len() != FISHLIN_REPETITIONS {
            return false;
        }
        let mut n = 0;
        for (i, &(t, j, r)) in pi.iter().enumerate() {
            let rnd = T::H::seq_query(
                &[
                    &x.into()[..],
                    &t.into()[..],
                    &i.to_le_bytes()[..],
                    &j.to_le_bytes()[..],
                ][..],
            );
            let mut rnd_rng = ChaCha20Rng::from_seed(
                rnd[..32].try_into().expect("32 byte seed expected"),
            );
            let c = rnd_rng.gen();
            if !T::finish_verify(x, t, c, r) {
                return false;
            }
            let rnd2 = T::H::seq_query(
                &[&t.into()[..], &c.into()[..], &r.into()[..]][..],
            );
            let bits = fischlin_bits(&rnd2[..]);
            n += bits;
        }
        return n <= FISHLIN_SUM;
    }
}

pub trait SigmaProtocol {
    type X: Copy;
    type W: Copy;
    type Z: Copy;
    type T: Copy;
    type C: Copy;
    type R: Copy;
    type H: RO;

    /// Step 1: Create commitments.
    fn prove_step_1<R: Rng + ?Sized>(
        x: Self::X,
        w: Self::W,
        rng: &mut R,
    ) -> (Self::Z, Self::T);
    /// Step 2: Respond to challenge
    fn prove_step_2(x: Self::X, w: Self::W, z: Self::Z, c: Self::C) -> Self::R;
    /// Final verification.
    fn finish_verify(x: Self::X, t: Self::T, c: Self::C, r: Self::R) -> bool;
}

impl<T: SigmaProtocol> NIZK for T
where
    Standard: Distribution<T::C>,
    T::X: Into<Vec<u8>>,
    T::T: Into<Vec<u8>>,
{
    type X = T::X;
    type W = T::W;
    type Proof = (T::T, T::R);

    fn prove<R: Rng + ?Sized>(
        x: Self::X,
        w: Self::W,
        rng: &mut R,
    ) -> Self::Proof {
        let (z, t) = Self::prove_step_1(x, w, rng);
        let rnd = T::H::seq_query(&[&x.into()[..], &t.into()[..]][..]);
        let mut rnd_rng = ChaCha20Rng::from_seed(
            rnd[..32].try_into().expect("32 byte seed expected"),
        );
        let c = rnd_rng.gen();
        let r = Self::prove_step_2(x, w, z, c);
        (t, r)
    }

    fn verify(x: Self::X, &(t, r): &Self::Proof) -> bool {
        let rnd = T::H::seq_query(&[&x.into()[..], &t.into()[..]][..]);
        let mut rnd_rng = ChaCha20Rng::from_seed(
            rnd[..32].try_into().expect("32 byte seed expected"),
        );
        let c = rnd_rng.gen();
        Self::finish_verify(x, t, c, r)
    }
}

pub struct DualProofOfExponentSigmaProtocol<C: CurveAffine, H: RO> {
    phantom: PhantomData<(C, H)>,
}

#[derive(Copy, Clone)]
pub struct CurvePair<C: CurveAffine>(pub C, pub C);

#[derive(Copy, Clone)]
pub struct FieldPair<F: PrimeField>(pub F, pub F);

impl<C: CurveAffine> Into<Vec<u8>> for CurvePair<C> {
    fn into(self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend(self.0.into_uncompressed().as_ref().iter().cloned());
        vec.extend(self.1.into_uncompressed().as_ref().iter().cloned());
        vec
    }
}

impl<F: PrimeField> Into<Vec<u8>> for FieldPair<F> {
    fn into(self) -> Vec<u8> {
        let mut vec = Vec::new();
        for i in [self.0, self.1].iter() {
            for word in i.into_repr().as_ref() {
                vec.extend(word.to_le_bytes().iter())
            }
        }
        vec
    }
}

impl<F: PrimeField> Distribution<FieldPair<F>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> FieldPair<F> {
        FieldPair(F::random(rng), F::random(rng))
    }
}

impl<C: CurveAffine, H: RO> SigmaProtocol
    for DualProofOfExponentSigmaProtocol<C, H>
{
    type X = CurvePair<C>;
    type W = FieldPair<C::Scalar>;
    type Z = FieldPair<C::Scalar>;
    type T = CurvePair<C>;
    type C = FieldPair<C::Scalar>;
    type R = FieldPair<C::Scalar>;
    type H = H;

    fn prove_step_1<R: Rng + ?Sized>(
        _: Self::X,
        _: Self::W,
        rng: &mut R,
    ) -> (Self::Z, Self::T) {
        let z = FieldPair(C::Scalar::random(rng), C::Scalar::random(rng));
        let t = CurvePair(
            C::one().mul(z.0).into_affine(),
            C::one().mul(z.1).into_affine(),
        );
        (z, t)
    }

    fn prove_step_2(
        _: Self::X,
        FieldPair(a, b): Self::W,
        FieldPair(mut v, mut w): Self::Z,
        FieldPair(mut c, mut d): Self::C,
    ) -> Self::R {
        c.mul_assign(&a);
        d.mul_assign(&b);
        v.sub_assign(&c);
        w.sub_assign(&d);
        FieldPair(v, w)
    }

    fn finish_verify(
        CurvePair(a, b): Self::X,
        CurvePair(t, u): Self::T,
        FieldPair(c, d): Self::C,
        FieldPair(r, s): Self::R,
    ) -> bool {
        let mut t_prime = C::one().mul(r);
        t_prime.add_assign(&a.mul(c));
        let mut u_prime = C::one().mul(s);
        u_prime.add_assign(&b.mul(d));
        t_prime.into_affine() == t && u_prime.into_affine() == u
    }
}