use crate::poe::{CurvePair, FieldPair, NIZK};
use ff::Field;
use group::{CurveAffine, CurveProjective};
use pairing::Engine;
use rand::distributions::{Distribution, Standard};
use rand::Rng;

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

pub struct Update<E: Engine, N: NIZK<X=CurvePair<E::G2Affine>,W=FieldPair<E::Fr>>> {
    srs: USRS<E>,
    h_y: E::G2Affine,
    h_by: E::G2Affine,
    pi: N::Proof,
}

impl<E: Engine, N: NIZK<X=CurvePair<E::G2Affine>,W=FieldPair<E::Fr>>> Update<E, N> {
    pub fn new<R: Rng + ?Sized>(srs: &USRS<E>, rng: &mut R) -> Self {
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
            pi: N::prove(
                CurvePair(h_y, h_by),
                FieldPair(trapdoor.x, by),
                rng,
            ),
        }
    }

    pub fn verify(&self, srs: &USRS<E>) -> bool {
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
        if !N::verify(
            CurvePair(self.h_y, self.h_by),
            &self.pi,
        ) {
            return false;
        }
        // TODO: optimise the number of pairing calls.
        // TODO: batch pairings -- figure out how that works.
        // e(g, h)^{\alpha\beta xy}
        let t_abxy = e(srs.g_ax[d + 1], self.h_by);
        if e(self.srs.g_ax[d + 1], h) != t_abxy {
            return false;
        }
        if e(g, self.srs.h_ax[d + 1]) != t_abxy {
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
        for i in 0..=(2 * d) {
            if i != 2 * d {
                let nxt = e(self.srs.g_x[i], self.srs.h_x[d + 1]);
                if nxt != e(self.srs.g_x[d + 1], self.srs.h_x[i])
                    || nxt != e(self.srs.g_x[i + 1], h)
                    || nxt != e(g, self.srs.h_x[i + 1])
                {
                    return false;
                }
            }
            if e(self.srs.g_x[i], self.srs.h_ax[d]) != e(g, self.srs.h_ax[i]) {
                return false;
            }
            if i != d
                && e(self.srs.g_x[i], self.srs.h_ax[d])
                    != e(self.srs.g_ax[i], h)
            {
                return false;
            }
        }
        return true;
    }
}

impl<E: Engine, N: NIZK<X=CurvePair<E::G2Affine>,W=FieldPair<E::Fr>>> Into<USRS<E>> for Update<E, N> {
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
        let mut byi = trapdoor.alpha;
        // beta y^{-i}
        let mut neg_byi = trapdoor.alpha;
        // y^i
        let mut yi = E::Fr::one();
        // y^{-i}
        let mut neg_yi = E::Fr::one();
        let x_inv = trapdoor.x.inverse().expect("trapdoor may not be zero");
        // h^\alpha -> h^\alpha\beta
        srs.h_ax[self.d] = srs.h_ax[self.d].mul(byi).into_affine();
        for i in 1..=self.d {
            byi.mul_assign(&trapdoor.x);
            yi.mul_assign(&trapdoor.x);
            neg_byi.mul_assign(&x_inv);
            neg_yi.mul_assign(&x_inv);
            srs.g_x[self.d + i] = srs.g_x[self.d + i].mul(yi).into_affine();
            srs.g_x[self.d - i] = srs.g_x[self.d - i].mul(neg_yi).into_affine();
            srs.h_x[self.d + i] = srs.h_x[self.d + i].mul(yi).into_affine();
            srs.h_x[self.d - i] = srs.h_x[self.d - i].mul(neg_yi).into_affine();
            srs.g_ax[self.d + i] = srs.g_ax[self.d + i].mul(byi).into_affine();
            srs.g_ax[self.d - i] =
                srs.g_ax[self.d - i].mul(neg_byi).into_affine();
            srs.h_ax[self.d + i] = srs.h_ax[self.d + i].mul(byi).into_affine();
            srs.h_ax[self.d - i] =
                srs.h_ax[self.d - i].mul(neg_byi).into_affine();
        }
        srs
    }
}
