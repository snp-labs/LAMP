# Local environment and interpretation

This is a new same-host development experiment on an Apple M1 Pro, macOS,
10 logical CPUs and 32 GiB physical memory, using Go 1.26.2 and a ten-thread
GOMAXPROCS budget. It is not a reproduction of the paper’s EPYC Linux timings.
The host remains a shared desktop: an unrelated `anvil` process was using
approximately one CPU and about 7 GiB RSS before the run. Other desktop activity
is uncontrolled. No unrelated user process was stopped. Treat timing variability
and any cross-scheme ratio as local evidence requiring a quiet common-host
confirmation before publication.

Both schemes use BN254 here. zkMatrix is an independent Go adaptation, not
the paper authors’ BLS12-381 implementation or an equal-security curve claim.
LAMP uses official e2d1cae with opt-in measurement/codec instrumentation. The
source snapshot is in /Users/hyunokoh/Develop/Projects/Lamp/tmp/comparison-frozen-20260929; exact
hashes are retained in manifest.json and every eligible raw record.

Each completed shape has ten proof repetitions. zkMatrix shares setup within
its ten-row process; LAMP performs fresh setup in each one-row process. Setup
and circuit compilation are excluded from the primary proving timer and
reported separately. Matrix multiplication is excluded. Peak RSS is measured
for each entire command, including setup and data generation; zkMatrix
commands contain ten repetitions whereas LAMP commands contain one.

Proof sizes are actual canonical compressed payload lengths after successful
verification of decoded proofs/statements. Statement bytes and public keys are
separate. Decoding/serialization and the extra re-verification are outside the
reported online proving and timed verification intervals. LAMP’s historical
uncompressed size and phase sum remain distinct fields, not substituted for
the normalized metrics. Missing, failed and interrupted commands do not yield
completed benchmark entries. zkMaP equation diagnostics are excluded.

Input-data provenance: both implementations use dense full-field BN254 matrices. zkMatrix uses deterministic seeded PRNG draws with canonical rejection sampling; LAMP preserves official cryptographic SetRandom generation. These are equal dimensions/counts, not byte-identical inputs. Input generation and AB preparation are excluded from normalized proving; proof blindings are cryptographic.
