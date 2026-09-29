# Discussion notes to accompany verified measurements

This is an outline, not a measured superiority claim. Fill in performance
statements only after completing the implementation review and common-host runs.

## What the comparison must expose

| Dimension | LAMP | zkMatrix | zkMaP |
| --- | --- | --- | --- |
| Main strategy | Encoded matrix folds checked through proximity sampling, CP-SNARK and linking proofs | Four projection/inner-product arguments, with hiding commitments and optional paired verification acceleration | Published polynomial commitments and pairing checks; specification discrepancies need resolution |
| Prover work to measure | Encoding, matrix/intermediate commitments, sampled openings, Groth16 and CP-Link | Input commitments, projections, all masks, IPAs and acceleration proofs | Complete faithful author-confirmed prover needed before comparable timing |
| Verifier work to measure | Groth16, sampled commitment openings and CP-Link | All commitment knowledge checks, IPAs, and both paired acceleration checks | Projection binding and the correct complete pairing check must first be specified |
| Communication | Public roots/commitments, sampled openings and all auxiliary proofs | Input and intermediate commitments, mask messages, folded scalar/point messages and acceleration proofs | Reported constant size cannot be independently reproduced as a sound matrix argument from the disputed checks alone |
| Setup | Groth16 and CP-Link; report circuit/setup sizes and amortization | Structured/shifted SRS for logarithmic verification; this implementation retains those parameters for direct debug verification too | KZG SRS and any compression/preprocessing; obtain exact artifact settings |

For zkMatrix, distinguish input commitment cost from proving against precommitted
matrices. Algorithm 6 reduces the group work of additional claims inside the
proof; newly committing every input matrix still costs quadratic work per claim.
Compare both commitment-inclusive prover totals and precommitted online costs
if they are useful, with clear definitions.

Do not substitute a cubic implementation of whole-product zero-knowledge
masking for zkMatrix's final quadratic construction. Do not present a direct IPA
verifier's quadratic time as the paper's logarithmic verifier. Any changed SRS
layout, separate verification of subarguments, curve/backend, fixed-base
preprocessing, batching or transcript serialization must be disclosed.

For LAMP, query count and sampling convention affect soundness, constraint count,
prover time and communication. An L=128 public-artifact smoke result cannot stand
in for the supplied paper's t=309 experiment. Rates 1/2, 1/4 and 1/8 are LAMP
configuration knobs; the comparison protocols do not acquire equivalent code
rates simply by sharing the matrix dimensions.

## Suggested measured discussion structure

1. Same-host prover crossover, including commitments and all auxiliary work.
2. Verification latency and bandwidth, including complete transcripts.
3. Trusted setup, SRS size, preprocessing and amortization.
4. Peak process memory at the largest completed common dimensions; failed/OOM
   runs explicitly marked, without extrapolated entries.
5. Independent-claim batching at k=128 and q=1..10, separately from heterogeneous
   GPT-2 claims. Use exact rectangular shapes and count input/commitment reuse.
6. Security, curve and implementation differences, and unresolved zkMaP
   reproduction limits supported by executable diagnostics.

## zkMatrix's published timing evidence

Section 7 of the supplied zkMatrix paper says its table was estimated from
BLS12-381 primitive timings with assumed parallelism across 16 threads. Those
table entries are not measurements of our independent end-to-end implementation.
Keep published estimates, our BN254 development measurements, and eventual
same-host experimental results in distinct categories. Fixed-base acceleration
and parallelism can change implementation constants even when asymptotic work
matches; record what was actually used.
