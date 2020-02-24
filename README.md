# Implementations to accompany "Reference Strings from Chain Quality"

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
