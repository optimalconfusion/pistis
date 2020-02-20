use crate::poe::{CurvePair, FieldPair, NIZK};
use crate::ro::{ROOutput, RO};
use crate::util::multiexp;
use ff::{Field, ScalarEngine};
use group::{CurveAffine, CurveProjective};
use pairing::{Engine, PairingCurveAffine};
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use rand_core::block::BlockRng;
use rayon::prelude::*;
use std::io::{self, Write};
use std::iter::once;

macro_rules! check {
    ($x:expr) => {{ if !$x {
        return false;
    }}}
}

#[derive(Clone)]
pub struct USRS<E: Engine> {
    /// The dimension of the USRS.
    pub d: usize,
    /// g^{x^i} for i \in -d to d
    pub g_x: Vec<E::G1Affine>,
    /// h^{x^i} for i \in -d to d
    pub h_x: Vec<E::G2Affine>,
    /// g^{x^i \alpha} for i \in -d to d; At i=0, the value is undefined.
    pub g_ax: Vec<E::G1Affine>,
    /// h^{x^i \alpha} for i \in -d to d
    pub h_ax: Vec<E::G2Affine>,
}

pub struct Trapdoor<E: Engine> {
    pub x: E::Fr,
    pub alpha: E::Fr,
}

impl<E: Engine> Distribution<Trapdoor<E>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Trapdoor<E> {
        Trapdoor {
            x: E::Fr::random(rng),
            alpha: E::Fr::random(rng),
        }
    }
}

pub struct Update<
    E: Engine,
    N: NIZK<X = CurvePair<E::G1Affine>, W = FieldPair<E::Fr>>,
> {
    srs: USRS<E>,
    g_y: E::G1Affine,
    g_by: E::G1Affine,
    pi: N::Proof,
}

impl<E: Engine, N: NIZK<X = CurvePair<E::G1Affine>, W = FieldPair<E::Fr>>>
    Update<E, N>
{
    pub fn new<H: RO + ?Sized>(
        srs: &USRS<E>,
        rng: &mut BlockRng<ROOutput<H>>,
    ) -> Self
    where
        ROOutput<H>: Send,
    {
        let trapdoor: Trapdoor<E> = rng.gen();
        let mut tmp = E::G1Affine::one().mul(trapdoor.x);
        let g_y = tmp.into_affine();
        tmp.mul_assign(trapdoor.alpha);
        let g_by = tmp.into_affine();
        let by = {
            let mut tmp = trapdoor.x;
            tmp.mul_assign(&trapdoor.alpha);
            tmp
        };
        Update {
            srs: srs.permute(&trapdoor),
            g_y: g_y,
            g_by: g_by,
            pi: N::prove(CurvePair(g_y, g_by), FieldPair(trapdoor.x, by), rng),
        }
    }

    pub fn verify<R: Rng + ?Sized>(&self, srs: &USRS<E>, rng: &mut R) -> bool {
        let d = srs.d;
        let g = E::G1Affine::one();
        let e = E::pairing;
        check!(self.g_y != g && self.g_by != g);
        check!(self.srs.d == srs.d);
        check!(N::verify(CurvePair(self.g_y, self.g_by), &self.pi));
        check!(e(self.g_by, srs.h_ax[d + 1]) == e(g, self.srs.h_ax[d + 1]));
        check!(e(self.g_y, srs.h_x[d + 1]) == e(g, self.srs.h_x[d + 1]));
        check!(self.srs.verify_structure(rng));
        true
    }
}

impl<E: Engine, N: NIZK<X = CurvePair<E::G1Affine>, W = FieldPair<E::Fr>>>
    Into<USRS<E>> for Update<E, N>
{
    fn into(self) -> USRS<E> {
        self.srs
    }
}

struct UpdatePart<
    E: Engine,
    N: NIZK<X = CurvePair<E::G1Affine>, W = FieldPair<E::Fr>>,
> {
    h_x: E::G2Affine,
    h_ax: E::G2Affine,
    g_y: E::G1Affine,
    g_by: E::G1Affine,
    pi: N::Proof,
}

pub struct AggregateUpdate<
    E: Engine,
    N: NIZK<X = CurvePair<E::G1Affine>, W = FieldPair<E::Fr>>,
> {
    srs: USRS<E>,
    upds: Vec<UpdatePart<E, N>>
}

impl<E: Engine, N: NIZK<X = CurvePair<E::G1Affine>, W = FieldPair<E::Fr>>> AggregateUpdate<E, N> {
    pub fn new(d: usize) -> Self {
        AggregateUpdate {
            srs: USRS::new(d),
            upds: Vec::new(),
        }
    }

    pub fn append(&mut self, upd: Update<E, N>) {
        let nxt = UpdatePart {
            h_x: self.srs.h_x[self.srs.d + 1],
            h_ax: self.srs.h_ax[self.srs.d + 1],
            g_y: upd.g_y,
            g_by: upd.g_by,
            pi: upd.pi,
        };
        self.srs = upd.srs;
        self.upds.push(nxt);
    }

    pub fn verify<R: Rng + ?Sized>(&self, rng: &mut R) -> bool {
        let g = E::G1Affine::one();
        let h = E::G2Affine::one();
        let e = E::pairing;
        check!(self.upds.iter().all(|u| N::verify(CurvePair(u.g_y, u.g_by), &u.pi)));
        check!(self.upds.iter().all(|u| u.g_y != g && u.g_by != g));
        check!(self.upds[0].h_x == h);
        check!(self.upds[0].h_ax == h);
        let h_xs = self.upds.iter().map(|u| u.h_x).chain(self.upds.iter().map(|u| u.h_ax));
        let h_xys = self.upds[1..].iter().map(|u| u.h_x).chain(once(self.srs.h_x[self.srs.d + 1])).chain(self.upds[1..].iter().map(|u| u.h_ax)).chain(once(self.srs.h_ax[self.srs.d + 1]));
        let g_ys = self.upds.iter().map(|u| u.g_y).chain(self.upds.iter().map(|u| u.g_by));
        for ((h_x, h_xy), g_y) in h_xs.zip(h_xys).zip(g_ys) {
            check!(e(g_y, h_x) == e(g, h_xy));
        }
        check!(self.srs.verify_structure(rng));
        true
    }
}

impl<E: Engine, N: NIZK<X = CurvePair<E::G1Affine>, W = FieldPair<E::Fr>>>
    Into<USRS<E>> for AggregateUpdate<E, N>
{
    fn into(self) -> USRS<E> {
        self.srs
    }
}

impl<E: Engine, N: NIZK<X = CurvePair<E::G1Affine>, W = FieldPair<E::Fr>>> AsRef<USRS<E>> for AggregateUpdate<E, N> {
    fn as_ref(&self) -> &USRS<E> {
        &self.srs
    }
}

impl<E: Engine> USRS<E> {
    pub fn new(d: usize) -> Self {
        USRS {
            d: d,
            g_x: vec![E::G1Affine::one(); 2 * d + 1],
            h_x: vec![E::G2Affine::one(); 2 * d + 1],
            g_ax: vec![E::G1Affine::one(); 2 * d + 1],
            h_ax: vec![E::G2Affine::one(); 2 * d + 1],
        }
    }

    pub fn export<W: Write>(&self, mut out: W) -> io::Result<()> {
        out.write_all((self.d as u64).to_le_bytes().as_ref())?;
        for g in self.g_x.iter().chain(self.g_ax.iter()) {
            out.write_all(g.into_compressed().as_ref())?;
        }
        for h in self.h_x.iter().chain(self.h_ax.iter()) {
            out.write_all(h.into_compressed().as_ref())?;
        }
        Ok(())
    }

    pub fn verify_structure<R: Rng + ?Sized>(&self, rng: &mut R) -> bool {
        let g = E::G1Affine::one();
        let h = E::G2Affine::one();
        let e = E::pairing;
        check!(self.g_x[self.d] == g && self.h_x[self.d] == h);
        let t_ax = e(g, self.h_ax[self.d + 1]);
        check!(t_ax == e(self.g_ax[self.d + 1], h));
        check!(e(g, self.h_x[self.d + 1]) == e(self.g_x[self.d + 1], h));
        // constrain e(g, h)^{\alpha\beta (xy)^{-1}}
        check!(t_ax == e(self.g_ax[self.d - 1], self.h_x[self.d + 2]));
        let g0 = self.g_x[..2 * self.d]
            .iter()
            .chain(self.g_ax[..self.d - 1].iter())
            .chain(self.g_ax[self.d + 1..2 * self.d].iter())
            .collect::<Vec<_>>();
        let g1 = self.g_x[1..]
            .iter()
            .chain(self.g_ax[1..self.d].iter())
            .chain(self.g_ax[self.d + 2..].iter())
            .collect::<Vec<_>>();
        let h0 = self.h_x[..2 * self.d]
            .iter()
            .chain(self.h_ax[..2 * self.d].iter())
            .collect::<Vec<_>>();
        let h1 = self.h_x[1..]
            .iter()
            .chain(self.h_ax[1..].iter())
            .collect::<Vec<_>>();
        let rnd0 = vec![<E as ScalarEngine>::Fr::random(rng); 4 * self.d - 2];
        let rnd1 = vec![<E as ScalarEngine>::Fr::random(rng); 4 * self.d];
        let mut neg_hx = self.h_x[self.d + 1];
        neg_hx.negate();
        let mut neg_gx = self.g_x[self.d + 1];
        neg_gx.negate();
        let table = [
            (
                multiexp(g0.into_iter(), rnd0.iter())
                    .into_affine()
                    .prepare(),
                neg_hx.prepare(),
            ),
            (
                multiexp(g1.into_iter(), rnd0.iter())
                    .into_affine()
                    .prepare(),
                E::G2Affine::one().prepare(),
            ),
            (
                neg_gx.prepare(),
                multiexp(h0.into_iter(), rnd1.iter())
                    .into_affine()
                    .prepare(),
            ),
            (
                E::G1Affine::one().prepare(),
                multiexp(h1.into_iter(), rnd1.iter())
                    .into_affine()
                    .prepare(),
            ),
        ];
        let table_ref = table
            .iter()
            .map(|&(ref a, ref b)| (a, b))
            .collect::<Vec<_>>();
        let lp = E::miller_loop(&table_ref[..]);
        E::final_exponentiation(&lp).unwrap() == E::Fqk::one()
    }

    pub fn permute(&self, trapdoor: &Trapdoor<E>) -> Self {
        let mut srs = self.clone();
        // beta y^i
        let mut byi = vec![trapdoor.alpha];
        // beta y^{-i}
        let mut neg_byi = vec![trapdoor.alpha];
        // y^i
        let mut yi = vec![E::Fr::one()];
        // y^{-i}
        let mut neg_yi = vec![E::Fr::one()];
        let x_inv = trapdoor.x.inverse().expect("trapdoor may not be zero");
        // Create vectors of powers
        for _ in 1..=self.d {
            let mut tmp = *byi.last().unwrap();
            tmp.mul_assign(&trapdoor.x);
            byi.push(tmp);
            tmp = *neg_byi.last().unwrap();
            tmp.mul_assign(&x_inv);
            neg_byi.push(tmp);
            tmp = *yi.last().unwrap();
            tmp.mul_assign(&trapdoor.x);
            yi.push(tmp);
            tmp = *neg_yi.last().unwrap();
            tmp.mul_assign(&x_inv);
            neg_yi.push(tmp);
        }
        // Convert into one vector of negtive and positive powers
        neg_byi.reverse();
        neg_byi.pop();
        neg_byi.extend(byi);
        byi = neg_byi;
        neg_yi.reverse();
        neg_yi.pop();
        neg_yi.extend(yi);
        yi = neg_yi;
        // h^\alpha -> h^\alpha\beta
        srs.h_ax[self.d] = srs.h_ax[self.d].mul(byi[0]).into_affine();
        srs.g_x = self
            .g_x
            .par_iter()
            .zip(yi.par_iter())
            .map(|(gx, y)| gx.mul(*y).into_affine())
            .collect();
        srs.h_x = self
            .h_x
            .par_iter()
            .zip(yi.par_iter())
            .map(|(hx, y)| hx.mul(*y).into_affine())
            .collect();
        srs.g_ax = self
            .g_ax
            .par_iter()
            .zip(byi.par_iter())
            .map(|(gax, by)| gax.mul(*by).into_affine())
            .collect();
        srs.h_ax = self
            .h_ax
            .par_iter()
            .zip(byi.par_iter())
            .map(|(hax, by)| hax.mul(*by).into_affine())
            .collect();
        // Unset g^\alpha.
        srs.g_ax[self.d] = E::G1Affine::one();
        srs
    }
}
