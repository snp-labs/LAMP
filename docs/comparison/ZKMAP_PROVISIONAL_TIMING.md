# zkMaP provisional operation timing

Implementation: Claude Haiku 4.5 (`claude-haiku-4-5-20251001`) with root review and corrections. This measures an uncompressed Appendix E Algorithm 2 operation workload. It is **not a valid zkMaP prover**. See [specification gaps](ZKMAP_SPEC_GAPS.md).

## Scope and assumptions

Fresh random BN254 field matrices A and B are generated for every attempt; C=A·B is computed with the existing parallel matrix helper. Three row-major n²-coefficient KZG commitments precede a challenge derived from domain, dimension, serialized-SRS fingerprint, node assumption and commitments. The challenge uses SHA256 reduced into the scalar field; this is an explicit reference choice.

Projections use yL[i]=y^(i*n), yR[j]=y^j, ay=yLᵀA, by=ByR and μ=yLᵀCyR. Two separate interpolation assumptions are measured because the published algorithm does not specify its nodes:

- `integers`: nodes 0..n−1; cached Lagrange basis built from one common product plus synthetic division in O(n²), then O(n²) linear combination online.
- `fft`: actual gnark-crypto BN254 FFT domain; inverse FFT followed by bit reversal yields natural coefficient order in O(n log n). Requires power-of-two n. No n² basis is cached.

Neither node choice is asserted to be the authors’ intended construction. Polynomial multiplication currently uses O(n²) convolution in both modes.

The workload divides μ−Pay·Pby by x−y and **preserves the remainder**. Even when it is nonzero, it commits the quotient, Pay and Pby, and computes μG1, to measure all auxiliary operations. This discards the remainder only for the commitment workload: `witness_polynomial_exists` remains false. The literal Appendix pairing diagnostic executes afterward using these cached commitments. Acceptance does not establish soundness or correct matrix binding.

Every output has `provisional_operation_only=true`, `security_certified=false`, and `comparison_eligible_as_valid_proof=false`. There is no `verified=true` field. Compression, projection binding proofs, zero-knowledge masks and a complete sound verifier are absent.

## Timing boundaries

`online_seconds` includes input commitments, challenge, powers/projections, interpolation, polynomial product/division and auxiliary commitments. Input generation, honest C computation, setup, preprocessing, consistency checks, literal pairing and point sizing are outside that timer.

Setup runs once per command. `setup_seconds` times random-trapdoor KZG SRS construction; `preprocessing_seconds` times SRS serialization/fingerprinting and interpolation preparation. These same one-time values repeat in each row and must not be treated as independent setup samples. `input_generation_seconds` and `matmul_seconds` are separate per-attempt values. `total_seconds` includes all per-attempt work through diagnostics and point sizing, excludes prepared setup and CLI JSON serialization.

`srs_compressed_bytes` is the actual gnark SRS `WriteTo` serialization length, including library metadata and precomputed data; it is not a minimal theoretical SRS size. `g1_proof_attempt_bytes` sums `Bytes()` lengths of the seven attempted G1 points (224 bytes on BN254). It excludes metadata and missing protocol components and **is not a valid proof size**. The exact remainder is a canonical 32-byte field hex value. The challenge hex stores the unreduced SHA256 digest.

## Run

```bash
go test ./crypto/zkmap_provisional ./cmd/zkmap_provisional
go run ./cmd/zkmap_provisional -n 128 -mode fft -threads 10 -repetitions 10 -output new-results.jsonl
```

Output paths must be new. Configuration is checked before output creation; failed operations terminate with nonzero exit code. `-max-matrix-elements` bounds each n² matrix (default 1048576, supporting n≤1024); the dimension limit is 32768. Dense storage totals 3n² elements, with additional helper memory. SRS setup is for development, with a locally generated trapdoor; it is not a ceremony.

Tests check integer and FFT recovery at all eight nodes, full FFT generator order, polynomial arithmetic, honest μ consistency, remainder retention, n1024 cap validation and reuse of one prepared setup. These tests do not establish protocol security.

## Local measurements, 2026-09-30 (KST)

Apple M1 Pro, 10 configured/runtime threads, BN254, Go 1.26.2. Eight sequential commands with ten fresh-input attempts each. Values are mean ± sample SD in seconds. Setup/preprocessing is one invocation per group, excluded from online time. Shared desktop load was not controlled.

| n | Integer-node operation time | FFT-node operation time | Earlier LAMP valid online proof | Earlier zkMatrix valid online proof |
|---:|---:|---:|---:|---:|
| 128 | 0.0470 ± 0.0019 | 0.0495 ± 0.0045 | 2.0662 | 1.3470 |
| 256 | 0.1623 ± 0.0127 | 0.1504 ± 0.0053 | 4.1358 | 4.6207 |
| 512 | 0.5624 ± 0.0252 | 0.5934 ± 0.0349 | 9.0708 | 16.9261 |
| 1024 | 2.0330 ± 0.1410 | 1.8862 ± 0.0330 | 22.0986 | 66.5999 |

**All 80 operation attempts had nonzero remainder and zero valid witnesses; all literal pairing diagnostics rejected.** Honest μ consistency held in all attempts. The operation times are lower than the earlier valid-proof times, but do not support a claim that a sound zkMaP prover is faster, or that LAMP loses to zkMaP. Missing binding, compression and zero-knowledge work could change cost. This does not fulfill the shepherd’s request for a sound zkMaP benchmark.

The earlier LAMP/zkMatrix rows were measured from a different frozen source, at an earlier time on the same desktop. Their complete mean/SD and conditions are in [local results](LOCAL_RESULTS.md). No old row was relabeled with this new source hash.

[Raw results, component timings, command logs, source archive and manifest](../../benchmark/comparison/published_zkmap_operations_20260930/manifest.json); [summary](../../benchmark/comparison/published_zkmap_operations_20260930/summary.json). Measured source SHA256: `fa8a36c384f260c4c7a799ee708fea8badc8d4e663b62defe6d06240a095b793`; binary SHA256: `2b9584bfdd6a58c0d728d8766425c4d5d2d545b627adc1a6ce1cfaf829d9d622`. This source includes uncommitted new Haiku implementation atop 23dac21c1d504a70400e3379497fc47891445f7e; archive content is the authority for the measured implementation.
