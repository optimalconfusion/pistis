use pistis::ro::RO;
use rand::distributions::Distribution;
use rand::Rng;
use rand_distr::Exp;
use sha3::Sha3_256;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::process::Command;

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

struct ConsensusState {
    hon_chain_len: usize,
    adv_chain_len: usize,
    next_honest: f64,
    next_adv: f64,
    winning: Vec<(f64, bool)>,
    parameters: ConsensusParameters,
}

impl ConsensusState {
    fn new<R: Rng + ?Sized>(p: ConsensusParameters, rng: &mut R) -> Self {
        ConsensusState {
            hon_chain_len: 0,
            adv_chain_len: 0,
            next_honest: p.honest_time(rng),
            next_adv: p.adversarial_time(rng),
            winning: vec![(0f64, false)],
            parameters: p,
        }
    }

    fn simulate<R: Rng + ?Sized>(&mut self, rng: &mut R, end: f64) {
        while self.next_honest < end || self.next_adv < end {
            if self.next_adv < self.next_honest {
                self.adv_chain_len += 1;
                self.winning.push((
                    self.next_adv,
                    self.hon_chain_len > self.adv_chain_len,
                ));
                self.next_adv += self.parameters.adversarial_time(rng);
            } else {
                self.hon_chain_len += 1;
                self.winning.push((
                    self.next_honest,
                    self.hon_chain_len > self.adv_chain_len,
                ));
                self.next_honest += self.parameters.honest_time(rng);
            }
        }
    }

    fn winning(&self, at: f64) -> bool {
        match self
            .winning
            .binary_search_by(|&(t, _)| t.partial_cmp(&at).unwrap())
        {
            Ok(idx) => self.winning[idx - 1].1,
            Err(idx) => self.winning[idx - 1].1,
        }
    }
}

pub fn record<R: Rng>(
    p: ConsensusParameters,
    end: f64,
    step: f64,
    name: &str,
    rng: &mut R,
) {
    let mut f = File::create(format!("data/{}.csv", name)).unwrap();
    writeln!(&mut f, "#time,probability").unwrap();
    const ITERS: usize = 1_000;
    let results = (0..ITERS)
        .map(|_| {
            let mut cs = ConsensusState::new(p, rng);
            cs.simulate(rng, end);
            cs
        })
        .collect::<Vec<_>>();
    println!("ran to time {} {} times", end, ITERS);
    for i in 1..((end / step) as usize) {
        let t = i as f64 * step;
        let p = results.iter().map(|r| r.winning(t)).filter(|b| *b).count()
            as f64
            / results.len() as f64;
        writeln!(&mut f, "{},{}", t, p).unwrap();
    }
    println!("combed through with {} time step", step);
}

fn plot<A: AsRef<str>, I: Iterator<Item = A>>(file: &str, inputs: I) {
    let plots = inputs
        .map(|i| format!("'data/{}.csv' with lines,", i.as_ref()))
        .fold(String::new(), |mut s, p| {
            s.push_str(&p);
            s
        });
    let cmd = format!("set terminal svg; set datafile separator ','; set output 'data/{}.svg'; set yrange [0:1]; plot {}", file, plots);
    Command::new("gnuplot").arg("-e").arg(cmd).spawn().unwrap();
}

pub fn main() {
    let mut rng = Sha3_256::query(&[
        0xa0, 0xc3, 0x5b, 0xa6, 0x8a, 0x0d, 0x98, 0x45, 0x61, 0x32, 0x70, 0xc3,
        0x6a, 0x0f, 0xa3, 0x50,
    ])
    .into_rng();
    create_dir_all("data").unwrap();
    // Network delays, ranging from 0 to 0.5 in 0.1 increments
    for (h, len, step) in [
        (0.55, 5_000.0, 0.05),
        (0.67, 500.0, 0.2),
        (0.9, 1_000.0, 1.0),
    ]
    .iter()
    {
        let network_delays = (0..=10).map(|i| i as f64 * step);
        for d in network_delays.clone() {
            record(
                ConsensusParameters {
                    network_delay: d,
                    mean_block_time: 1.0,
                    fraction_honest: *h,
                },
                *len,
                (*len / 1_000.0),
                &format!("network_delay_[h={:.2},d={:.2}]", h, d),
                &mut rng,
            );
        }
        plot(
            &format!("network_delay_[h={:.2}]", h),
            network_delays
                .map(|d| format!("network_delay_[h={:.2},d={:.2}]", h, d)),
        );
    }
    // Fraction honest, randing from 0.55 to 0.88 in 0.11 increments
    //let fraction_honest = (3..=8).map(|i| i as f64 * 0.11);
    //for h in fraction_honest.clone() {
    //    record(ConsensusParameters {
    //        network_delay: 0.0,
    //        mean_block_time: 1.0,
    //        fraction_honest: h,
    //    }, 100.0, 0.1, &format!("fraction_honest_{:.2}", h), &mut rng);
    //}
    //plot("fraction_honest", fraction_honest.map(|h| format!("fraction_honest_{:.2}", h)));
}
