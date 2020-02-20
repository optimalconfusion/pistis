use pistis::ro::RO;
use rand::distributions::Distribution;
use rand::Rng;
use rand_distr::Exp;
use sha3::Sha3_256;
use std::fs::{create_dir_all, File};
use std::io::{Write, stdout};
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use rayon::prelude::*;

#[derive(Copy, Clone)]
pub struct ConsensusParameters {
    pub network_delay: f64,
    pub mean_block_time: f64,
    pub fraction_honest: f64,
}

impl ConsensusParameters {
    fn honest_time<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        Exp::new(self.fraction_honest / self.mean_block_time)
            .unwrap()
            .sample(rng)
            + self.network_delay
    }

    fn adversarial_time<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        Exp::new((1f64 - self.fraction_honest) / self.mean_block_time)
            .unwrap()
            .sample(rng)
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
    fn step<R: Rng + ?Sized>(&mut self, rng: &mut R, p: &ConsensusParameters) -> f64 {
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

impl Eq for TimeIndex { }

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
    fn new<R: Rng + ?Sized>(p: ConsensusParameters, n: usize, granularity: f64, rng: &mut R) -> Self {
        let states: Vec<_> = (0..n).map(|_| ConsensusState::new(&p, rng)).collect();
        let queue = states.iter().enumerate().map(|(i, s)| TimeIndex(i, s.next_honest)).chain(states.iter().enumerate().map(|(i, s)| TimeIndex(i, s.next_adv))).map(|i| Reverse(i)).collect();
        Experiment {
            states: states,
            data: Vec::new(),
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
        };
    }

    fn step<R: Rng + ?Sized>(&mut self, rng: &mut R) -> f64 {
        let Reverse(TimeIndex(idx, t)) = self.queue.pop().expect("there is always a next step");
        let was_winning = self.states[idx].hon_chain_len > self.states[idx].adv_chain_len;
        let nxt = self.states[idx].step(rng, &self.params);
        self.queue.push(Reverse(TimeIndex(idx, nxt)));
        let is_winning = self.states[idx].hon_chain_len > self.states[idx].adv_chain_len;
        while t > self.next_recorded {
            self.data.push((self.next_recorded, self.nwinning as f64 / self.states.len() as f64));
            self.next_recorded += self.granularity;
        }
        if !was_winning && is_winning {
            self.nwinning += 1;
        } else if was_winning && !is_winning {
            self.nwinning -= 1;
        }
        t
    }

    fn run_until_time<R: Rng + ?Sized>(&mut self, end: f64, rng: &mut R) -> &mut Self {
        while self.step(rng) < end { }
        self.data.retain(|(t, _)| *t <= end);
        self
    }

    /// Runs until a confidence level is reached, or a time limit is hit.
    fn run_until_confidence<R: Rng + ?Sized>(&mut self, conf: f64, limit: f64, rng: &mut R) -> Option<f64> {
        let mut t = 0f64;
        while self.data.len() == 0 || self.data[self.data.len() - 1].1 < conf { 
            t = self.step(rng);
            if t > limit {
                return None
            }
        }
        Some(t)
    }
}

pub fn main() {
    let mut rng = Sha3_256::query(&[
        0xa0, 0xc3, 0x5b, 0xa6, 0x8a, 0x0d, 0x98, 0x45, 0x61, 0x32, 0x70, 0xc3,
        0x6a, 0x0f, 0xa3, 0x50,
    ])
    .into_rng();
    create_dir_all("data").unwrap();
    // Network delays, ranging from 0 to 0.5 in 0.1 increments
    vec![
        (0.51, 10_000.0, 0.01, rng.core.split()),
        (0.55, 1_000.0, 0.05, rng.core.split()),
        (0.67, 500.0, 0.2, rng.core.split()),
        (0.9, 250.0, 1.0, rng.core.split()),
    ].into_par_iter().for_each(|(h, len, step, mut rng)| {
        let network_delays = (0..=10).map(|i| (i as f64 * step, rng.split())).collect::<Vec<_>>();
        network_delays.into_par_iter().for_each(|(d, rng)| {
            let mut rng = rng.into_rng();
            Experiment::new(
                ConsensusParameters {
                    network_delay: d,
                    mean_block_time: 1.0,
                    fraction_honest: h,
                },
                500_000,
                len / 10_000.0,
                &mut rng,
            ).run_until_time(len, &mut rng).record(
                &format!("network_delay_[h={:.2},d={:.2}]", h, d),
            );
            print!(".");
            stdout().flush().unwrap();
        });
    });

    // For each honest fraction, how long a (phase 1) bootstrap is needed to reach 99.9%
    // confidence.
    for d in (0..=4).map(|i| (i as f64 * 0.1)) {
        let data = (1..50).map(|i| (i, rng.core.split())).collect::<Vec<_>>().into_par_iter().map(|(i, rng)| {
            let h = 0.5 + (i as f64 * 0.01);
            let mut rng = rng.into_rng();
            let res = Experiment::new(
                 ConsensusParameters {
                     network_delay: d,
                     mean_block_time: 1.0,
                     fraction_honest: h,
                 },
                 100_000,
                 1.0,
                 &mut rng,
            ).run_until_confidence(0.999, 15_000.0, &mut rng);
            print!(".");
            stdout().flush().unwrap();
            (h, res)
        }).collect::<Vec<_>>();
        let mut f = File::create(format!("data/bootstrap_[c=0.999,d={:.1}].csv", d)).unwrap();
        for (h, res) in data.iter() {
            if let Some(res) = res {
                writeln!(&mut f, "{},{}", h, res).unwrap();
            }
        }
    }

    // For each confidence level, how long a (phase 1) bootstrap is needed (with 55% honest)
    for d in (0..=3).map(|i| (i as f64 * 0.1)) {
        let data = (0..200).map(|i| (i, rng.core.split())).collect::<Vec<_>>().into_par_iter().map(|(i, rng)| {
            let c = 0.8 + (i as f64 * 0.001);
            let mut rng = rng.into_rng();
            let res = Experiment::new(
                 ConsensusParameters {
                     network_delay: d,
                     mean_block_time: 1.0,
                     fraction_honest: 0.55,
                 },
                 100_000,
                 1.0,
                 &mut rng,
            ).run_until_confidence(c, 15_000.0, &mut rng);
            print!(".");
            stdout().flush().unwrap();
            (c, res)
        }).collect::<Vec<_>>();
        let mut f = File::create(format!("data/bootstrap_[h=0.55,d={:.1}].csv", d)).unwrap();
        for (h, res) in data.iter() {
            if let Some(res) = res {
                writeln!(&mut f, "{},{}", h, res).unwrap();
            }
        }
    }

    // For each inter-block time, how long a (phase 1) bootstrap is needed (with 55% honest, 99.9%
    // confidence)
    for h in [0.55, 0.67, 0.9].iter() {
        for c in [0.99, 0.999].iter() {
            let data = (1..=250).map(|i| (i, rng.core.split())).collect::<Vec<_>>().into_par_iter().map(|(i, rng)| {
                let b = i as f64 * 0.1;
                let mut rng = rng.into_rng();
                let res = Experiment::new(
                     ConsensusParameters {
                         network_delay: 1.0,
                         mean_block_time: b,
                         fraction_honest: *h,
                     },
                     100_000,
                     1.0,
                     &mut rng,
                ).run_until_confidence(*c, 15_000.0 * b, &mut rng);
                print!(".");
                stdout().flush().unwrap();
                (b, res)
            }).collect::<Vec<_>>();
            let mut f = File::create(format!("data/bootstrap_[h={:.2},c={:.3}].csv", h, c)).unwrap();
            for (h, res) in data.iter() {
                if let Some(res) = res {
                    writeln!(&mut f, "{},{}", h, res).unwrap();
                }
            }
        }
    }
}
