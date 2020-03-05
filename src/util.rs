use ff::{PrimeField, PrimeFieldRepr, ScalarEngine};
use group::{CurveAffine, CurveProjective};
use rayon::prelude::*;

/// Split into independant copies. Differs from `Clone` in that the copies should act *not* be
/// equal.
pub trait Split {
    fn split(&mut self) -> Self;
}

// Sourced from https://github.com/ebfull/sonic. Licensed under MIT
// Adapted to introduce parallelism.
pub(crate) fn multiexp<
    'a,
    G: CurveAffine,
    IB: IntoIterator<Item = &'a G>,
    IS: IntoIterator<Item = &'a G::Scalar>,
>(
    g: IB,
    s: IS,
) -> G::Projective
where
    IB::IntoIter: ExactSizeIterator + Clone + Send,
    IS::IntoIter: ExactSizeIterator + Clone + Send,
{
    let g = g.into_iter();
    let s = s.into_iter();
    assert_eq!(g.len(), s.len());

    let c = if s.len() < 32 {
        3u32
    } else {
        (f64::from(s.len() as u32)).ln().ceil() as u32
    };

    // Convert all of the scalars into representations
    let s = s.map(|s| s.into_repr()).collect::<Vec<_>>();

    let mask = (1u64 << c) - 1u64;
    let max_iters = (<G::Engine as ScalarEngine>::Fr::NUM_BITS as f64
        / c as f64)
        .ceil() as usize;
    let windows = (0..max_iters)
        .map(|i| (i, g.clone(), s.clone()))
        .collect::<Vec<_>>()
        .into_par_iter()
        .map(|(cur, g, s)| {
            let mut acc = G::Projective::zero();
            let mut buckets = Vec::new();

            buckets.truncate(0);
            buckets.resize((1 << c) - 1, G::Projective::zero());

            for (&(mut s), g) in s.iter().zip(g) {
                s.shr(cur as u32 * c);
                let index = (s.as_ref()[0] & mask) as usize;

                if index != 0 {
                    buckets[index - 1].add_assign_mixed(g);
                }
            }

            let mut running_sum = G::Projective::zero();
            for exp in buckets.iter().rev() {
                running_sum.add_assign(exp);
                acc.add_assign(&running_sum);
            }
            acc
        })
        .collect::<Vec<_>>();

    let mut acc = G::Projective::zero();

    for window in windows.into_iter().rev() {
        for _ in 0..c {
            acc.double();
        }

        acc.add_assign(&window);
    }

    acc
}
