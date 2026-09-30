# Official LAMP revision recheck, 2026-09-29

## Revision found

A fresh git remote check found master at
e2d1cae15988779b0c65c7e492eb1dc4df2dd032 (2026-09-18).
The previous development tree was based on b1c7636a7fc660712eeb3908698b4bb753b353c9.
It is preserved in ../upstream; the latest official source is the detached
worktree ../upstream-current. No merge overwrote either tree.

The previous three-fold/two-vector source-gap finding applies to b1c7636,
not to the newer official circuit. Do not repeat it as a description of current
master.

## Independent compile evidence

Root executed official source before comparison instrumentation:

GOMAXPROCS=10 LAMP_OUTPUT_DIR=/Users/hyunokoh/Develop/Projects/Lamp/tmp/current-lamp-k7-compile
go run ./cmd/lamp --K 7 --rho 1/2 --L 309 --compile=true --all=false

Actual output: nbPublic=315, nbSecret=120735, nbConstraints=167065.
This exactly matches the supplied paper's smallest square constraint count.
The log is [current-lamp-k7-compile.log](../../benchmark/comparison/published_20260929/logs/current-lamp-k7-compile.log).
This was compilation, not a prover/verification performance run.

## Source differences now present

- Four sampled folds, including an independent challenge for the B fold.
- Native/encoded X, shared YZ and B-test vectors. Sharing YZ enforces the
  intended Y=Z identity through one vector representation.
- A third Groth16 witness commitment binds all three native/encoded RS vectors.
  Its returned challenge is the shared RS evaluation point.
- Official independent query draws allow duplicates; the default is L=309.
- Official rates 1/2, 1/4 and 1/8 are explicit.
- QA-link verification aggregates complete link equations using weights
  derived after the link proofs, statements, keys and context are absorbed.

## Details to disclose in an independent comparison

Matching the constraint count identifies the intended numerical artifact
configuration; it is not a formal security validation.

The written paper describes four separate vectors/code checks and pre-query
complete intermediate commitments. Current code shares YZ, derives query
indices from the intermediate Merkle root before Groth16 proving, and creates
the full RS witness commitment inside Groth16, before its RS challenge.
These are concrete implementation details to disclose, rather than a claim
that source and the interactive paper transcript are literally identical.

The implementation's encoder treats native vector entries as evaluations on
the size-k radix-2 domain: inverse FFT, zero-pad coefficients, then forward FFT
on the size-n domain. Its circuit interpolates both domains. Appendix D writes
the native entries as polynomial coefficients. Both describe linear RS maps,
but the basis conventions differ and must be identified.

Benchmark the official artifact without changing its relation or challenges.
The new comparison code should only add instrumentation, serialization and
independent baselines. Historical b1c7636 development timings must not enter a
current-artifact performance group.
