use crate::poe::{CurvePair, FieldPair, NIZK};
use crate::util::multiexp;
use crate::ro::{RO, ROOutput};
use rand_core::block::BlockRng;
use ff::{Field, ScalarEngine};
use group::{CurveAffine, CurveProjective};
use pairing::{Engine, PairingCurveAffine};
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use rayon::prelude::*;

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
    N: NIZK<X = CurvePair<E::G2Affine>, W = FieldPair<E::Fr>>,
> {
    srs: USRS<E>,
    h_y: E::G2Affine,
    h_by: E::G2Affine,
    pi: N::Proof,
}

impl<E: Engine, N: NIZK<X = CurvePair<E::G2Affine>, W = FieldPair<E::Fr>>>
    Update<E, N>
{
    pub fn new<H: RO + ?Sized>(srs: &USRS<E>, rng: &mut BlockRng<ROOutput<H>>) -> Self where ROOutput<H>: Send {
        let trapdoor: Trapdoor<E> = rng.gen();
        let mut tmp = E::G2Affine::one().mul(trapdoor.x);
        let h_y = tmp.into_affine();
        tmp.mul_assign(trapdoor.alpha);
        let h_by = tmp.into_affine();
        let by = {
            let mut tmp = trapdoor.x;
            tmp.mul_assign(&trapdoor.alpha);
            tmp
        };
        Update {
            srs: srs.permute(&trapdoor),
            h_y: h_y,
            h_by: h_by,
            pi: N::prove(CurvePair(h_y, h_by), FieldPair(trapdoor.x, by), rng),
        }
    }

    pub fn verify<R: Rng + ?Sized>(&self, srs: &USRS<E>, rng: &mut R) -> bool {
        let d = srs.d;
        let g = E::G1Affine::one();
        let h = E::G2Affine::one();
        let e = E::pairing;
        if self.h_y == h || self.h_by == h {
            return false;
        }
        if self.srs.d != srs.d {
            return false;
        }
        if self.srs.g_x[d] != g || self.srs.h_x[d] != h {
            return false;
        }
        if !N::verify(CurvePair(self.h_y, self.h_by), &self.pi) {
            return false;
        }
        // e(g, h)^{\alpha\beta xy}
        let t_abxy = e(srs.g_ax[d + 1], self.h_by);
        if e(self.srs.g_ax[d + 1], h) != t_abxy {
            return false;
        }
        if e(g, self.srs.h_ax[d + 1]) != t_abxy {
            return false;
        }
        // constrain e(g, h)^{\alpha\beta (xy)^{-1}}
        if e(self.srs.g_ax[d - 1], self.srs.h_x[d + 2]) != t_abxy {
            return false;
        }
        // e(g, h)^{xy}
        let t_xy = e(srs.g_x[d + 1], self.h_y);
        if e(self.srs.g_x[d + 1], h) != t_xy {
            return false;
        }
        if e(g, self.srs.h_x[d + 1]) != t_xy {
            return false;
        }
        let g0 = self.srs.g_x[..2 * d]
            .iter()
            .chain(self.srs.g_ax[..d - 1].iter())
            .chain(self.srs.g_ax[d + 1..2 * d].iter())
            .collect::<Vec<_>>();
        let g1 = self.srs.g_x[1..]
            .iter()
            .chain(self.srs.g_ax[1..d].iter())
            .chain(self.srs.g_ax[d + 2..].iter())
            .collect::<Vec<_>>();
        let h0 = self.srs.h_x[..2 * d]
            .iter()
            .chain(self.srs.h_ax[..2 * d].iter())
            .collect::<Vec<_>>();
        let h1 = self.srs.h_x[1..]
            .iter()
            .chain(self.srs.h_ax[1..].iter())
            .collect::<Vec<_>>();
        let rnd0 = vec![<E as ScalarEngine>::Fr::random(rng); 4 * d - 2];
        let rnd1 = vec![<E as ScalarEngine>::Fr::random(rng); 4 * d];
        let mut neg_hx = self.srs.h_x[d + 1];
        neg_hx.negate();
        let mut neg_gx = self.srs.g_x[d + 1];
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
        E::final_exponentiation(&lp).unwrap()
            == E::Fqk::one()
    }
}

impl<E: Engine, N: NIZK<X = CurvePair<E::G2Affine>, W = FieldPair<E::Fr>>>
    Into<USRS<E>> for Update<E, N>
{
    fn into(self) -> USRS<E> {
        self.srs
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
