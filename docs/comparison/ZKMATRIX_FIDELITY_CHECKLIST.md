# zkMatrix fidelity targets

This is a review target, not a claim of formal security validation or exact
reproduction of the paper's implementation.

## Variants

`ProveOptimized` / `VerifyOptimized` implement the paper composition: three
relaxed linear projection IPAs, one masked final dot product IPA, Eq. 21
aggregation, and a single Eq. 14 pairing accelerator proof. The relaxed scalar
SIP omits its separate Schnorr knowledge check; the high dimensional A/B
subprotocols omit the output-vector Rcom checks. The final dot argument bridges
`Cd`, `Cay`, and `Cby` under the disjoint projected bases, as in Section 5.1.
These omissions are specific to that composition.

`ProveConservative` / `VerifyConservative` preserve the six-IPA reference path
with the separate scalar and output-vector knowledge proofs. `VerifyOptimizedDirect`
checks the optimized four IPAs with direct group equations and consumes the
same aggregate transcript messages. It provides an independent correctness
cross-check, but has linear work in the matrix dimensions.

## Structured SRS and setup

For `m×l` and `l×n` matrices, `D=max(mn,ml,ln)`. Matrix bases A, B, and C
share `SRS[1:D]`. The projected scalar is at exponent `D+1`; projected A and B
bases use exponents `D+2+2k` and `D+3+2k`. The SRS ends at `D+2l+1`.
The hiding base is independent hash-to-curve output outside the SRS.

Setup is a single-party experiment. `tau` and `nu` are local setup values and
are not retained in `PublicParams`; this does not claim secure memory erasure
or a multiparty ceremony. The implementation uses BN254 while the paper's
reported curve is BLS12-381. No equal-security claim follows from the shared
protocol structure.

## Acceleration and complexity

The verifier computes the four IPA residuals and combines them with Eq. 21
weights `rho`, `rho²`, `rho³`, and `1`. The prover supplies one shifted-SRS
commitment and one quotient commitment for the aggregate polynomial. The
verifier recomputes the aggregate residual from all L/R points and checks both
Eq. 14 pairing conditions through the post-message random pairing challenge.
The polynomial evaluator uses the paper's distinct matrix stride 1 and
projected-vector stride 2. It does not expand the O(n²) coefficient vector.

The optimized verifier has logarithmic IPA point work plus a constant number
of pairing terms. The conservative `VerifyDirect` and optimized
`VerifyOptimizedDirect` references perform matrix-sized work. The optimized
prover still performs quadratic masking and MSM work. SRS length is
`D+2l+2` G1 points in each of the unshifted and shifted lists.

## Communication

For square dimension `n=2^K`, the optimized proof serializes
`14 log2(n)+15` G1 points and 14 field scalars, plus fixed headers, IPA round
framing, and the separately serialized three-point statement. Folded public
scalars are omitted from serialization and derived by the verifier; prover and
verifier absorb the same derived scalar in the transcript. The benchmark records
actual serialized proof and statement bytes, including framing.

`ProveBatch` / `VerifyBatch` implement Algorithm 6: all statements bind before
the common y challenge; the 3q intermediate commitments bind before the matrix
batching challenge; three masked projection IPAs prove the rho-aggregated
relations; and each claim has its own masked final dot IPA. Fresh residual
aggregation challenges are sampled after every IPA message and scalar. One
aggregate pairing accelerator covers all q+3 residuals. The direct verifier
folds each IPA independently and consumes the aggregate transcript without
using the accelerated pairing equation.

The square proof message count is `(2q+12)log2(n)+7q+8` G1 points and `5q+9`
field scalars, before the 20-byte dimension/count header and IPA round frames.
The codec checks exact dimensions, claim limits, point subgroup membership,
scalar canonicality, and trailing data. K2 q=2 CLI and q=1/2/3 square and
rectangular proofs have been checked. Matrix multiplication happens before
`ProveBatch`; the prover consumes the supplied C witness.

`VerifyBatch` uses factorized SRS polynomial evaluations and logarithmic IPA
folding. The direct reference deliberately has matrix-sized basis work. The
batch codec currently reports its actual zkMatrix proof bytes, but the LAMP
batch and GPT-2 comparison records have no normalized compressed payload yet.
