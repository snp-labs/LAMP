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

This profile measures independent-claim batch q=1..10 at n=128. Each completed condition has ten proof repetitions. zkMatrix shares setup within
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

## Source-check interruption and continuation

The original batch run was interrupted for a user-requested GitHub revision check. Public HEAD/master still matched the measured official e2d1cae revision. This continuation preserves the original manifest/raw files, imports its 78 completed commands (168 verified proofs), and retries the interrupted command plus the remaining 31 commands in fresh directories. The interrupted attempt is excluded. Existing frozen binaries are reused; source, binary, host, Go version, thread budget, config and completed-record provenance were checked before continuation. The read-only original-manifest backup SHA-256 and full attempt history are recorded in this manifest. Keep both original and continuation directories when transferring results.

Input-data provenance: both implementations use dense full-field BN254 matrices. zkMatrix uses deterministic seeded PRNG draws with canonical rejection sampling; LAMP preserves official cryptographic SetRandom generation. These are equal dimensions/counts, not byte-identical inputs. Input generation and AB preparation are excluded from normalized proving; proof blindings are cryptographic.
