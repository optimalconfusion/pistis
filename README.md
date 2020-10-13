# Implementations to accompany "Mining for Privacy"

This repository provides open source implementations of the Sonic uSRS update
procedure, modified to use a simple Fischlin-transformed sigma protocol as
proof-of-knowledge for exponents of updates. It contains the following
research-quality implementations:

* Sonic reference string updates and verification.
* Update and verification sequences
* An implementation of Fischlin-transformed dual-proof-of-exponents

Further, it provides a simulation of the optimal adversarial attack on the
update procedure; that of an independant adversarial fork, which is not subject
to network and processing delays as honest users are. This simulation draws
honest and adversarial block creation times from an exponential distribution,
which the honest generation times being delayed.

**This is a research project, and should not be relied apon for security**

## Running

This project primarily offers the endpoints:

1. A criterion benchmark for Fischlin vs Fiat-Shamir dual proofs of exponenents.
   This is run with `cargo bench`.
2. A program benchmarking full uSRS update generation and verification for
   various depths. This is run with `cargo run --bin timesrs --release`. The
   first numer of the output can be supplied as an argument to resume from this
   point.
3. A program simulating an adversarial attack in which the adversary maintains
   an independant chain, and it has negligible processing time, run for various
   settings. This is run with `cargo run --bin consensus --release`. Expect
   very long (days) executions times for the number of iterations set.
