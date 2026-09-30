# Sparse FRI + Groth16 research pilot raw data

Research-only branch: `research/sparse-column-openings`. Source: `cmd/lamp_sparse_fri_probe`, `cmd/lamp_fri_column_cost`, `circuit/lamp_sparse_fri.go`, `crypto/fri_column.go`. Host: Apple M1 Pro, macOS arm64, Go 1.26.2. `workers=10`. Each row is one run, with no warmup or confidence interval. No original LAMP implementation files were changed.

Build with default optimized Go settings from repository root:

```sh
go build -o /tmp/lamp_sparse_fri_probe ./cmd/lamp_sparse_fri_probe
go build -o /tmp/lamp_fri_column_cost ./cmd/lamp_fri_column_cost
```

`hybrid_runs.jsonl` is extracted from the last JSON line of each corresponding `.log` file. Reproduce the five runs:

```sh
/tmp/lamp_sparse_fri_probe -logK 2 -repetitions 43 -queries 1 -workers 10
/tmp/lamp_sparse_fri_probe -logK 3 -repetitions 43 -queries 2 -workers 10
/tmp/lamp_sparse_fri_probe -logK 8 -repetitions 1 -queries 1 -workers 10
/tmp/lamp_sparse_fri_probe -logK 10 -repetitions 1 -queries 1 -workers 10
/tmp/lamp_sparse_fri_probe -logK 2 -repetitions 3 -queries 1 -workers 10 -tamper-c
```

The three `single_column.jsonl` records are from `/tmp/lamp_fri_column_cost -logK 8`, `-logK 10`, and `-logK 12`. The online pilot field excludes deterministic input generation, dense `C=AB`, native FRI checks, circuit compilation and Groth16 setup. It includes horizontal encoding, all A/C FRI commitments, B/XYZ hashes, opening creation, witness construction and Groth16 proving. FRI payload bytes are component sums, not a serialized proof. Statement bytes are separate.

Large-matrix runs use `T=L=1` solely for integration and profiling; they do not meet the paper's security parameters. See [analysis](../../../docs/comparison/SPARSE_FRI_GROTH16_PILOT_KO.md).
