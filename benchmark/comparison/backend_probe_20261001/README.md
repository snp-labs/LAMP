# Research-only direct hash and KZG fold probe

Branch: `research/sparse-column-openings`. Source: `cmd/lamp_backend_probe/main.go`. Host: Apple M1 Pro, macOS arm64, Go 1.26.2. Each condition ran once using default optimized `go build`; no warmup or controlled system isolation. The direct scheme is not zero knowledge. The KZG scheme uses a benchmark-local SRS; deployment requires trusted MPC setup and a security analysis. Neither has an outer SNARK.

The six `.log` files each contain two JSON records from one process, using the same deterministic full-field A/B and their honest product C. `results.jsonl` adds `source_log` to these records. Input creation and dense C=AB are excluded from the online timers. The direct path has 309 sampled encoded columns with replacement and rate 1/2. KZG proves folded polynomial evaluations and does not use those sampled columns.

Reproduce from the repository root:

```sh
go build -o /tmp/lamp_backend_probe ./cmd/lamp_backend_probe
/tmp/lamp_backend_probe -logK 7 -queries 309 -seed 7 -mode both
/tmp/lamp_backend_probe -logK 8 -queries 309 -seed 7 -mode both
/tmp/lamp_backend_probe -logK 9 -queries 309 -seed 7 -mode both
/tmp/lamp_backend_probe -logK 10 -queries 309 -seed 7 -mode both
/tmp/lamp_backend_probe -logK 11 -queries 309 -seed 7 -mode both
/tmp/lamp_backend_probe -logK 12 -queries 309 -seed 7 -mode both
```

The direct payload is an estimate from field values, salts, Merkle siblings and indices. The KZG batch proof size comes from `WriteTo` plus vector values, with row commitments counted as separate public statement. No network, SRS or outer proof size is included. See [analysis](../../../docs/comparison/LAMP_BACKEND_REDESIGN_PILOT_KO.md).
