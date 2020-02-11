use ff::{PrimeField, PrimeFieldRepr, ScalarEngine};
use group::{CurveAffine, CurveProjective};
use pairing::Engine;

// Sourced from https://github.com/ebfull/sonic. Licensed under MIT
pub fn multiexp<
    'a,
    G: CurveAffine,
    IB: IntoIterator<Item = &'a G>,
    IS: IntoIterator<Item = &'a G::Scalar>,
>(
    g: IB,
    s: IS,
) -> G::Projective
where
    IB::IntoIter: ExactSizeIterator + Clone,
    IS::IntoIter: ExactSizeIterator,
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
    let mut s = s.map(|s| s.into_repr()).collect::<Vec<_>>();

    let mut windows = vec![];
    let mut buckets = vec![];

    let mask = (1u64 << c) - 1u64;
    let mut cur = 0;
    while cur <= <G::Engine as ScalarEngine>::Fr::NUM_BITS {
        let mut acc = G::Projective::zero();

        buckets.truncate(0);
        buckets.resize((1 << c) - 1, G::Projective::zero());

        let g = g.clone();

        for (s, g) in s.iter_mut().zip(g) {
            let index = (s.as_ref()[0] & mask) as usize;

            if index != 0 {
                buckets[index - 1].add_assign_mixed(g);
            }

            s.shr(c as u32);
        }

        let mut running_sum = G::Projective::zero();
        for exp in buckets.iter().rev() {
            running_sum.add_assign(exp);
            acc.add_assign(&running_sum);
        }

        windows.push(acc);

        cur += c;
    }

    let mut acc = G::Projective::zero();

    for window in windows.into_iter().rev() {
        for _ in 0..c {
            acc.double();
        }

        acc.add_assign(&window);
    }

    acc
}
