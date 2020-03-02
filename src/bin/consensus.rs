use rand::distributions::Distribution;
use rand::rngs::SmallRng;
use rand::{Rng, thread_rng, SeedableRng};
use rand_distr::Exp;
use rayon::prelude::*;
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::fs::{create_dir_all, File};
use std::io::{stdout, Write};

const BASE_ITER: usize = 1_000;

fn rng() -> SmallRng {
    SmallRng::from_seed(thread_rng().gen())
}

const PRESAMPLE_BITS: usize = 20;

struct ConsensusParameters {
    honest_presample: Vec<f64>,
    adv_presample: Vec<f64>,
}

impl ConsensusParameters {
    fn new<R: Rng + ?Sized>(network_delay: f64, mean_block_time: f64, fraction_honest: f64, rng: &mut R) -> Self {
        let mut honest_presample = Vec::with_capacity(1 << PRESAMPLE_BITS);
        let mut adv_presample = Vec::with_capacity(1 << PRESAMPLE_BITS);
        for _ in 0..(1 << PRESAMPLE_BITS) {
            honest_presample.push(Exp::new(fraction_honest / mean_block_time)
                .unwrap()
                .sample(rng)
                + network_delay);
            adv_presample.push(Exp::new((1f64 - fraction_honest) / mean_block_time)
                .unwrap()
                .sample(rng));
        }
        ConsensusParameters {
            honest_presample,
            adv_presample,
        }
    }

    fn honest_time<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        self.honest_presample[rng.next_u32() as usize & ((1 << PRESAMPLE_BITS) - 1)]
    }

    fn adversarial_time<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        self.adv_presample[rng.next_u32() as usize & ((1 << PRESAMPLE_BITS) - 1)]
    }
}

#[derive(Clone)]
struct ConsensusState {
    hon_chain_len: usize,
    adv_chain_len: usize,
    next_honest: f64,
    next_adv: f64,
}

impl ConsensusState {
    fn new<R: Rng + ?Sized>(p: &ConsensusParameters, rng: &mut R) -> Self {
        ConsensusState {
            hon_chain_len: 0,
            adv_chain_len: 0,
            next_honest: p.honest_time(rng),
            next_adv: p.adversarial_time(rng),
        }
    }

    /// Does the next thing. Returns the time of the newly created event
    fn step<R: Rng + ?Sized>(
        &mut self,
        rng: &mut R,
        p: &ConsensusParameters,
    ) -> f64 {
        if self.next_honest < self.next_adv {
            self.next_honest += p.honest_time(rng);
            self.hon_chain_len += 1;
            self.next_honest
        } else {
            self.next_adv += p.adversarial_time(rng);
            self.adv_chain_len += 1;
            self.next_adv
        }
    }
}

#[derive(PartialEq)]
struct TimeIndex(usize, f64);

impl Eq for TimeIndex {}

impl PartialOrd for TimeIndex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.1.partial_cmp(&other.1)
    }
}

impl Ord for TimeIndex {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).expect("times must be comparable")
    }
}

struct Experiment {
    states: Vec<ConsensusState>,
    data: Vec<(f64, f64)>,
    params: ConsensusParameters,
    nwinning: usize,
    queue: BinaryHeap<Reverse<TimeIndex>>,
    granularity: f64,
    next_recorded: f64,
}

impl Experiment {
    fn new<R: Rng + ?Sized>(
        p: ConsensusParameters,
        n: usize,
        granularity: f64,
        rng: &mut R,
    ) -> Self {
        let states: Vec<_> =
            (0..n).map(|_| ConsensusState::new(&p, rng)).collect();
        let queue = states
            .iter()
            .enumerate()
            .map(|(i, s)| TimeIndex(i, s.next_honest))
            .chain(
                states
                    .iter()
                    .enumerate()
                    .map(|(i, s)| TimeIndex(i, s.next_adv)),
            )
            .map(|i| Reverse(i))
            .collect();
        Experiment {
            states: states,
            data: vec![(0f64, 0f64)],
            params: p,
            nwinning: 0,
            queue: queue,
            granularity: granularity,
            next_recorded: granularity,
        }
    }

    fn record(&self, name: &str) {
        let mut f = File::create(format!("data/{}.csv", name)).unwrap();
        writeln!(&mut f, "#time,probability").unwrap();
        for (t, p) in self.data.iter() {
            writeln!(&mut f, "{},{}", t, p).unwrap();
        }
    }

    fn step<R: Rng + ?Sized>(&mut self, rng: &mut R) -> f64 {
        let Reverse(TimeIndex(idx, t)) =
            self.queue.pop().expect("there is always a next step");
        let was_winning =
            self.states[idx].hon_chain_len > self.states[idx].adv_chain_len;
        let nxt = self.states[idx].step(rng, &self.params);
        self.queue.push(Reverse(TimeIndex(idx, nxt)));
        let is_winning =
            self.states[idx].hon_chain_len > self.states[idx].adv_chain_len;
        while t > self.next_recorded {
            self.data.push((
                self.next_recorded,
                self.nwinning as f64 / self.states.len() as f64,
            ));
            self.next_recorded += self.granularity;
        }
        if !was_winning && is_winning {
            self.nwinning += 1;
        } else if was_winning && !is_winning {
            self.nwinning -= 1;
        }
        t
    }

    fn run_until_time<R: Rng + ?Sized>(
        &mut self,
        end: f64,
        rng: &mut R,
    ) -> &mut Self {
        while self.step(rng) < end {}
        self.data.retain(|(t, _)| *t <= end);
        self
    }

    /// Returns the first recorded point (if any) which satisfies the given confidence level.
    fn conf(&self, conf: f64) -> Option<f64> {
        let pos = match self.data.binary_search_by(|(_, y)| y.partial_cmp(&conf).expect("Probabilities must be comparable")) {
            Ok(p) => p,
            Err(p) => p,
        };
        if pos == self.data.len() {
            None
        } else {
            Some(self.data[pos].0)
        }
    }

    /// Runs until a confidence level is reached, or a time limit is hit.
    fn run_until_confidence<R: Rng + ?Sized>(
        &mut self,
        conf: f64,
        limit: f64,
        rng: &mut R,
    ) -> Option<f64> {
        let mut t = 0f64;
        while self.data.len() == 0 || self.data[self.data.len() - 1].1 < conf {
            t = self.step(rng);
            if t > limit {
                return None;
            }
        }
        Some(t)
    }
}

pub fn main() {
    create_dir_all("data").unwrap();
    // Network delays, ranging from 0 to 0.5 in 0.1 increments
    vec![
        (0.51, 10_000.0, 0.01),
        (0.55, 1_000.0, 0.05),
        (0.67, 500.0, 0.2),
        (0.9, 250.0, 1.0),
    ]
    .into_par_iter()
    .for_each(|(h, len, step)| {
        (0..=10).into_par_iter().map(|i| (i as f64 * step)).for_each(|d| {
            Experiment::new(
                ConsensusParameters::new(d, 1.0, h, &mut rng()),
                5 * BASE_ITER,
                2.0,
                &mut rng(),
            )
            .run_until_time(len, &mut rng())
            .record(&format!("network_delay_[h={:.2},d={:.2}]", h, d));
            print!(".");
            stdout().flush().unwrap();
        });
    });

    // For each inter-block time, how long a (phase 1) bootstrap is needed (with 55% honest, 99.9%
    // confidence)
    [0.55, 0.67, 0.9].par_iter().for_each(|h| {
        //for c in [0.999, 0.9999, 0.99999].iter() {
        let confs = [0.999, 0.9999, 0.99999];
        let data =
            (1..=250)
                .into_par_iter()
                .map(|i| {
                    let b = i as f64 * 0.1;
                    let mut exp = Experiment::new(
                        ConsensusParameters::new(1.0, b, *h, &mut rng()),
                        BASE_ITER,
                        1.0,
                        &mut rng(),
                    );
                    stdout().flush().unwrap();
                    exp.run_until_confidence(confs[confs.len() - 1], 15_000.0 * b, &mut rng());
                    print!(".");
                    stdout().flush().unwrap();
                    (b, confs.iter().map(|c| exp.conf(*c)).collect::<Vec<_>>())
                })
                    .collect::<Vec<_>>();
            let mut fs = confs.iter().map(|c| File::create(format!(
                "data/bootstrap_[h={:.2},c={:.5}].csv",
                h, c
            )).unwrap()).collect::<Vec<_>>();
            for f in fs.iter_mut() {
                writeln!(f, "#block-time,bootstrap-length").unwrap();
            }
            for (b, res) in data.into_iter() {
                for (res, f) in res.into_iter().zip(fs.iter_mut()) {
                if let Some(res) = res {
                    writeln!(f, "{},{}", b, res).unwrap();
                }
            }
        }
    });
}
