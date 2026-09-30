# Comparison implementation status

Updated 2026-09-29 for official commit `e2d1cae15988779b0c65c7e492eb1dc4df2dd032`.
This describes tooling and 300 completed local proof checks, not a completed
common-host three-protocol paper comparison.

## Independent packages

- `crypto/zkmatrix` contains the independent BN254 optimized proof, direct
  verifier, batched Algorithm 6 implementation, and canonical codecs.
- `cmd/zkmatrix` records numeric timings, shared setup, seeds, SRS, statement
  and proof sizes, resource limits, runtime and binary-relevant metadata. It
  decodes and re-verifies the canonical proof and statement payloads outside
  the timed verification interval before a CSV row can be marked verified.
- `crypto/zkmap_audit` and `cmd/zkmap_audit` remain diagnostic. No supported
  zkMaP proof construction is claimed or included in performance comparisons.

## LAMP instrumentation

- Instrumentation is opt-in through `LAMP_COMPARISON_RAW_JSONL`; existing CSV
  fields and official circuit, crypto, sampler, challenge order, and QA-link
  verification remain unchanged.
- Square and batch proof paths emit separate records. Their online prove time
  starts at matrix commitment and excludes domain/circuit compilation,
  Groth16 setup, key binding, and QA-link setup. It includes witness creation,
  commitments, proving, Merkle openings, and QA-link proving. Historical
  `TotalProveTime` remains recorded as `original_reported_totalprove`.
- Matrix commitment includes matrix encoding and root/commitment construction;
  raw records also keep the prior encoding and commit-only durations.
- LCP1 payload counts are available for square and batch only after codec
  round-trip and verification of decoded Groth16 proofs, Merkle openings, and
  QA-link proofs against decoded Groth16 commitments. Groth16 commitments are
  embedded in the Groth16 proof and are not counted twice. Public roots, keys,
  and witnesses are excluded. Existing reported proof bytes retain their
  uncompressed G1 accounting.
- The current public circuit has a four-fold construction, shared Y/Z witness,
  and a complete RS witness commitment. The K7, rho=1/2, L=309 compile is
  recorded at 167,065 constraints, matching the paper's constraint count.
  This count alone does not establish complete protocol or benchmark-table
  reproduction; see the revision audit.

## Runner and reporting

- `scripts/comparison/run.py` builds isolated binaries and run directories,
  applies scheme filters to the actual command list, sets explicit CLI gates,
  records source and binary hashes, host/CPU/memory/thread budget, and saves
  logs and manifests.
- zkMatrix CSV rows are adapted from actual numeric values. Setup is represented
  once per shared invocation; q=1 batch and square runs carry separate path
  identity. `query_count=0` is marked not applicable for zkMatrix.
- Aggregation rejects malformed, absent, boolean, NaN, negative, unverified, or
  provenance-incomplete values. It groups by source, host, protocol path and
  fidelity, proof-size definition, timing-accounting profile, and config.
  Missing raw records, failed commands, build errors, and postprocessing errors
  leave a persisted incomplete manifest and a nonzero result.
- Final aggregation includes only raw outputs linked to manifest commands with
  `status=completed` and matching verified row counts. A valid-looking row left
  by a command that later exits nonzero is excluded.
- The runner atomically checkpoints an incomplete manifest before building,
  when each command starts, and after it completes or postprocessing finishes.
  An interrupt records the active build or command and leaves the experiment
  incomplete for inspection.
- Server plan configurations document K=7..13 square runs and LAMP batch q=1..10,
  each at ten repetitions and 32 threads. `--plan` prints commands without
  executing them; actual commands expand over the same full grid and are
  guarded by host CPU and memory requirements. Quick local profiles are K7
  square and zkMatrix q=1..10 plus LAMP q=2. Extended local profiles cover
  square K7..K10 and both schemes' batch q=1..10. Optional square-rate profiles
  cover rho=1/4, L=189 and rho=1/8, L=155. All use ten repetitions and the
  1<<20 local matrix-element limit.

## GPT-2 zkMatrix claims-only baseline

- `go run ./cmd/lamp_gpt2 --baseline-plan --seq 10` uses the official shape-only
  graph builder to list all 36 claim IDs/tags and groups them by exact
  rectangular `(m, inner, n)` layout. It generates no tensor values and does
  no SRS setup.
- Execution uses
  `--baseline zkmatrix_grouped_matmul_claims_only`, defaults to ten repetitions,
  and accepts an explicit thread budget. Public parameters are set up once per
  unique shape and reused across repetitions. Its JSON manifest records graph
  generation/matmul time, setup, commitments, precommitted proving, full online
  time, decoded verification, payload sizes, source/binary hashes, host details,
  and the official generator's non-deterministic field-data provenance.
- Execution requires at least 32 logical CPUs and 240 GiB usable memory, the
  practical available-memory floor for a nominal 256 GiB host. Collect peak
  RSS with `/usr/bin/time` or a supported external wrapper; the baseline does
  not report an estimated RSS value.
- The certificate is explicitly
  `official_gpt2_graph_matmul_claims_only`. Both
  `graph_wiring_certified=false` and
  `public_input_output_binding_certified=false`: it proves the official
  generator's 36 supplied products, but does not prove LAMP's cross-claim
  equality/transpose/concat wiring or designated public input/output binding.
  This is not a full linked GPT-2 certificate.
- Its compressed SRS byte metric sums two G1 power arrays and three G2 anchors;
  it excludes the fixed hiding point and framing bytes.

## Remaining scope

- The two decoded K7/L309 smokes passed before the final matrix-commit metric
  boundary correction. Their proof verification remains valid; do not use their
  earlier matrix-commit/precommitted timing fields for summaries. Final local profiles have now completed: 80 square, 200 batch and 20
  additional-rate proofs. See LOCAL_RESULTS.md for actual means, sample SD,
  complete raw manifests and accounting. Smokes provide functional evidence only.
- zkMaP scheme details and full paper workload/reproduction remain unresolved.
  Do not present this status as a completed SOTA comparison or paper-ready
  results table.

## Future server input preparation

After all frozen-source measurements completed, a bounded gpt-6-luna change
replaced only the zkMatrix CLI's honest C=AB preparation with the existing
`matrix.MatMulRect`, with row-shape validation. The protocol, matrix generator,
flags, timers and original helper are unchanged. Root compared all source files
against the frozen archive: only `cmd/zkmatrix/main.go` differs, and the narrow
`cmd/zkmatrix/multiply_test.go` is added. Rectangular/square/full-field results,
invalid shapes and input preservation were tested; small decoded-proof CLI
checks passed. This is not an n=8192 performance measurement.

Future source hash:
`0c004f987e5b6e3dfb08242edbd3ed7f1bf0c19d815ecf0f779e4695d034aa83`.
All 300 reported measurements retain the older c34 frozen-source identity.
