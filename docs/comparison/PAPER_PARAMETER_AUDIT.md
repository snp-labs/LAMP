# Parameters and evidence needed for the shepherd comparison

> Historical audit: the source-gap and compile findings below describe archived commit `b1c7636a7fc660712eeb3908698b4bb753b353c9`. The current official worktree is `e2d1cae15988779b0c65c7e492eb1dc4df2dd032`; see [OFFICIAL_REVISION_RECHECK.md](OFFICIAL_REVISION_RECHECK.md) and [LAMP_PROTOCOL_REVISION_GAP.md](LAMP_PROTOCOL_REVISION_GAP.md) before applying any source-specific statement. Current K7/rho=1/2/L=309 compile: 167,065 constraints.

Inspected 2026-09-29. Archived LAMP checkout inspected here: `b1c7636a7fc660712eeb3908698b4bb753b353c9`.
This document records inspection findings, not benchmark results.

## Requested comparison

The shepherd requests measurements of zkMatrix and zkMaP with the same parameters
as LAMP Section 7, plus a discussion of the trade-offs. Independent implementations
must be identified as such; neither paper's published timing can be presented as a
measurement on the LAMP machine.

## Section 7 and the public artifact differ

| Item | Supplied LAMP PDF | Archived b1 public checkout |
| --- | --- | --- |
| Curve | BN254 | BN254 |
| Square sizes | k=2^7 through 2^13 | CLI supports those sizes |
| Code rate | rho=1/2 | default rho=1/2 |
| Query count | t=309 | default L=128 |
| Sampling | Appendix specifies independent draws from [n]^t, allowing repeats | `GenerateUniqueIndices` samples without replacement |
| Repetitions | Ten, arithmetic mean | One invocation runs one experiment per size |
| Machine | Linux, EPYC 7B13, 32 cores, 256GB | Historical `benchmark/lamp/system_info.json`: Linux arm64, 10 logical cores, 23.43GiB |
| Batch | k=128, q=1..10 | `lamp_batch` supports q ranges; validate exact batching semantics |
| GPT-2 | sequence length 1024, 36 claims | GPT-2 medium: D=1024, 16 heads, Dh=64, M=4096 |

At k=128 and rho=1/2 the codeword domain has N=256 positions. Calling
`GenerateUniqueIndices(..., 256, 309)` returns an error. The square CLI currently
ignores that error at `cmd/lamp/main.go:225` and `:436`. Consequently simply passing
`--L 309` is not a valid reproduction of the PDF's smallest-size experiment. The Appendix's soundness analysis explicitly samples independent queries from
[n]^t, which allows repeats. An opt-in reconstruction using independent draws can
therefore match the stated dimension/rate/query count, provided all 309 ordered
queries remain in the circuit and duplicate openings are handled consistently.
This must be identified as a reconstructed profile. The original experiment
revision is still needed to reproduce its circuit and exact table entries.

Historical CSVs are preserved but must not be mixed with fresh measurements. The
public CSV at k=128 reports 54,069 constraints and 22,660 bytes, whereas PDF Table 3
reports 167,065 constraints and 44,324 bytes. A compile-only public-artifact run with L=309 at k=128 produced 124,842
constraints, still different from the paper's 167,065. This demonstrates a
remaining circuit revision difference even after matching the query count.

## Timing and size accounting

Report separately: computing C=AB, setup, matrix commitments, remaining prover
work, full prover time including commitments, verification, proof bytes,
statement commitment bytes, and total serialized communication. Exclude C=AB and
setup from the main prover metric for every scheme. Include every auxiliary proof,
projection, masking operation and commitment in its corresponding measured phase.
Record setup/SRS size and peak process RSS separately from prover-only allocation.
Use real serialization, preserve raw run records, and report mean and spread.

The LAMP CLI's `TotalProveTime` adds matrix/vector commitment, Merkle proof,
Groth16 proof and CP-Link proof phases. Its `TotalProofSize` adds Groth16, Merkle
opening and CP-Link sizes; audit public roots, challenges and commitment data
before equating this number with an independently serialized total transcript.

## Protocol fidelity

zkMatrix's O(n^2) version introduces zero knowledge within the four projection/
inner-product subprotocols (Section 5.2, p.24). Applying Algorithm 5 to the entire
matrix product computes masking matrix products with cubic cost and would bias
the comparison. The O(log n) verifier also requires the paper's structured SRS,
additional commitment knowledge check and pairing acceleration. A plain IPA
verifier with linear work must be labelled as a variant.

zkMaP Section 8.1 names
<https://github.com/20code-submission-review25/anonzkp-harbor-6092>.
`git ls-remote` returned "Repository not found" on the inspection date. This
establishes failed public access, not that no implementation exists anywhere.
Its specified polynomial and pairing operations require clarification before a
faithful, sound baseline can be reported. Executable diagnostic checks must stay
outside performance comparison tables until the protocol is resolved.

The supplied zkMaP PDF is byte-for-byte identical to the publisher's current PDF
at <https://cic.iacr.org/p/2/3/23/pdf>. Both SHA-256 hashes are
`43e9631792b3c6124e58f081c11073113d779794e1fb0d4ab97aa5cac99ceaec`.
Appendix E, Algorithm 2 on page 37 specifies an additive pairing equation distinct
from the main text's multiplication expression. A diagnostic should test both
readings independently and identify the exact equation being evaluated.

## Execution environment

Current development machine: macOS arm64, 10 logical CPUs, 32GiB RAM, Go 1.26.2.
Local measurements are smoke checks. An exact Section 7 artifact reproduction requires the original revision and a
common adequately provisioned Linux host. A clearly labelled paper reconstruction
can use the stated independent-query convention on the public circuit.
Matching BN254 controls the backend but does not establish equal security with the
papers' BLS12-381 instantiations. Discuss curve/security and implementation differences.

## Sources

- Supplied `docs/LAMP.pdf`, Section 7 and Tables 3--6 (outside this checkout).
- Supplied `docs/zkMatrix.pdf`, Algorithms 1--6 and Sections 3--6;
  <https://eprint.iacr.org/2024/161>.
- Supplied `docs/zkMaP.pdf`, Sections 4 and 8;
  <https://cic.iacr.org/p/2/3/23>.
- Public repository: <https://github.com/snp-labs/LAMP>.

## Communication encoding mismatch found during review

The public LAMP constants count G1 points at 64 bytes for Merkle leaves and
QA-link proofs (`crypto/cpLink.go`), while the independent zkMatrix codec uses
32-byte compressed BN254 G1 encodings. LAMP's Groth16 `WriteTo` is already
compressed. Therefore the original `TotalProofSize` mixes these encodings and
must remain labelled as the original reported metric. It cannot be treated as
a standardized compressed transcript size alongside zkMatrix.

A comparison codec should count actual compressed component encodings, framing,
and separate public statements. Groth16's embedded commitments must not be counted
twice. Derived query indices and challenges need not be transmitted when the
verifier can reconstruct them. A public-witness replay archive that transmits
those derived values must be labelled separately from a minimal transcript.
Private matrices, opening blindings and the backend's `HackBlindings` must
never appear in serialized benchmark proof artifacts.

## Protocol revision difference

Further source inspection confirmed that the public artifact and supplied PDF
differ in the checked relation, beyond sampling and circuit counts. See
[LAMP_PROTOCOL_REVISION_GAP.md](LAMP_PROTOCOL_REVISION_GAP.md): the public square
circuit has three folds and two intermediate vector views, while the PDF has
four folds, four views and a pre-query complete-intermediate-witness commitment.

This conclusion applies to the archived b1 implementation only. The current official revision has a separate source audit in `OFFICIAL_REVISION_RECHECK.md`; its instrumentation must preserve that revision unchanged.
