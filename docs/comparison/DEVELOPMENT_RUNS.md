# Historical and current development checks

> Earlier sections refer to the archived `../upstream` b1-based preliminary worktree. Do not treat those measurements or 124,842-constraint compile output as current official results. Current official decoded smokes are listed at the end.

These runs are local development checks on macOS arm64, not Section 7 reproduction
on the EPYC host. Do not put these numbers in the paper's comparison table.

## Public LAMP smoke, 2026-09-29

Command from this checkout:

```sh
GOMAXPROCS=10 LAMP_OUTPUT_DIR=benchmark/comparison/development_lamp_k7_l128 \
  go run ./cmd/lamp --K 7 --rho 1/2 --L 128 --merkle multi
```

The full prover and verifier completed successfully with 54,069 constraints.
The public CLI reported 22,724 bytes (260 Groth16 + 22,336 Merkle + 128 CP-Link).
The run uses the public snapshot's 128-query configuration. It does not use the
supplied paper's 309-query setting. Raw CSV and machine metadata are in
`benchmark/comparison/development_lamp_k7_l128/`.

Existing package checks `go test ./crypto ./matrix ./protocol` passed before
comparison implementation began. This is a baseline check of the existing tree,
not verification of any new comparison protocol.

## Public LAMP batch smoke, 2026-09-29

Command:

```sh
GOMAXPROCS=10 LAMP_BATCH_OUTPUT_DIR=benchmark/comparison/development_lamp_batch_k7_q2_l128 \
  go run ./cmd/lamp_batch --K 7 --rho 1/2 --L 128 --batch 2 --merkle multi
```

All proofs verified. The circuit contained 105,349 constraints; the public CLI
reported 22,788 bytes (260 Groth16 + 22,400 Merkle + 128 CP-Link).
Raw CSV and host metadata are preserved in the corresponding development
directory. The historical CSV timing formatter rounds values; these records are
smoke evidence, not precision timing data for a publication.

## Public LAMP 309-query compile check

The public circuit at k=128, rho=1/2, L=309 compiled to 124,842 constraints.
This is compile-only evidence; no proof or verification ran. The supplied paper
reports 167,065 constraints for that configuration, so changing the sampling mode
alone cannot recover its exact artifact. Raw compile record is preserved in
`benchmark/comparison/development_lamp_k7_l309_compile/`.
The Appendix on PDF page 16 specifies independent draws from [n]^t, supporting
an explicitly labelled reconstruction with repeated query indices.

## Conservative accelerated zkMatrix smoke

The independent conservative six-IPA variant passed honest/false-C and mutation
tests, factorized-polynomial checks, serialization roundtrips, and an explicit
test that a valid KZG evaluation equation cannot replace the shifted-SRS
knowledge condition. Root independently ran the package and CLI tests.

A local n=4 end-to-end CLI run verified, with 2,844 serialized proof bytes and
112 serialized statement bytes. Raw numeric data are in
`benchmark/comparison/development_zkmatrix_accelerated_k2.csv`.
This is a conservative implementation checkpoint, not the optimized paper
construction; extra output-knowledge IPAs and individual acceleration proofs
increase its constants. It is excluded from any paper SOTA timing claim.

## Optimized single-claim zkMatrix checkpoint

Root independently ran the optimized square/rectangular tests and a full n=4
CLI proof. Both accelerated and direct reference verification accepted honest
proofs and their decoded forms; false C and the tested mutations were rejected.
The full CLI run reported 1,856 proof bytes, matching 43 compressed BN254 G1
points, 14 field elements and 32 bytes of framing. Raw numeric run data are in
`benchmark/comparison/development_zkmatrix_optimized_k2.csv`.
This uses four IPAs and one aggregate accelerator with the Equation (22) SRS.
It remains a small development checkpoint, not a completed Section 7 experiment.

## Batch and parallel execution checks

Batch unit checks cover q=1,2,3 for square and rectangular dimensions, decoded
accelerated proofs, direct reference verification, false C at each claim
position, changed statement/intermediate/proof messages, reordered/removed/extra
claims, framing and the paper's point/scalar counts.

Root ran the batch and optimized unit checks with Go's race detector successfully.
A larger 32×32, q=2 CLI run with four workers exercised the parallel prover folds
and passed direct reference verification under the race detector. It serialized
3,912 proof bytes. The CSV at
`benchmark/comparison/development_zkmatrix_batch_k5_race.csv` is correctness
evidence only: race-instrumented timings must never be mixed into measurements.

## Full 309-query public-circuit check

Root ran the full public square circuit at k=128, rho=1/2, L=309 with the new
independent-query option. All Groth16, Merkle and QA-link verifications succeeded.
This draw contained 180 distinct positions among 309 ordered samples.
The circuit had 124,842 constraints and the original mixed-encoding size metric
was 44,100 bytes. Numeric JSONL and CSV are preserved in
`benchmark/comparison/development_lamp_k7_l309_independent/`.

This is a public-circuit development check with paper query parameters, not
reproduction of the paper's four-fold protocol. Its raw prove metric is still
the original phase sum; normalized full-online timing and compressed payload
measurement are separate tooling work. No speedup or superiority claim is made.

## Canonical decoded LAMP payload and online timer smoke, 2026-09-29

The post-instrumentation K=7, rho=1/2, L=309 independent-sampling command was
run with `GOMAXPROCS=10`, `LAMP_OUTPUT_DIR`, and
`LAMP_COMPARISON_RAW_JSONL` pointed into the fresh isolated directory
`benchmark/comparison/development_lamp_k7_l309_decoded_online_smoke_20260929/`.
The proof, Merkle openings, and both QA-link components verified, and the
comparison-only payload decoded and re-verified. This is one local smoke, not a
repetition set or comparison result. The JSONL records 124,842 constraints,
24,608 decoded canonical payload bytes, 1.836 seconds full-online proving,
0.155 seconds matrix commitment, and 1.681 seconds precommitted-online
proving. Its separate original reported byte metric is 44,420 bytes and uses
uncompressed point accounting, so it is not wire-equivalent to the canonical
payload size.

The full-online interval includes assignment construction and proof generation,
excludes domain/circuit compilation, Groth16 setup, protocol key binding and
CP-Link setup, and ends before verification. The historical phase-sum metric
remains present. These measurements are public-circuit development evidence;
they do not establish faithful paper protocol implementation or a performance
comparison.

## Current official decoded proof smokes, 2026-09-29

The clean `e2d1cae` worktree completed one square K7/rho=1/2/L=309 run and one LAMP batch q=2 run with GOMAXPROCS=10. Both Groth16, Merkle and QA-link proofs verified; each LCP1 payload was encoded, decoded, and reverified against decoded Groth16 commitments. The square compile reported 167,065 constraints. Raw records and unchanged CSV outputs are under `benchmark/comparison/current_official_square_k7_l309_decoded_smoke/` and `benchmark/comparison/current_official_batch_q2_k7_l309_decoded_smoke/`. They predate the final matrix-commit boundary and runner provenance fixes: decoded-proof verification is useful functional evidence, but their matrix-commit/precommitted fields are stale and they lack retained source/binary hashes. Do not aggregate them or use them as performance measurements. The final runner records corrected definitions and provenance for root's profiles.
