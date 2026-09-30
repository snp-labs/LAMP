# LAMP column RS / sparse opening probe

This is a component experiment, **not** a complete LAMP proof or a sound replacement for the current Groth16 circuit. In particular it has no intermediate-value commitment or LAMP challenge-order binding. The JSONL results were measured once per size on Apple M1 Pro, Go 1.26.2, macOS arm64, with ten parallel workers on 2026-09-30. All durations are wall-clock seconds.

Reproduce from the repository root:

```sh
go build -o /tmp/lamp_column_probe ./cmd/lamp_column_probe
for logk in 8 10 11 12; do /tmp/lamp_column_probe --logK "$logk" --queries 309 --seed 20260930 --workers 10; done
go test ./crypto ./cmd/lamp_column_probe
```

Each input matrix is horizontally RS encoded from K × K to K × N with N=2K. Then every resulting length-K column is *coefficient* RS encoded to M=2K vertical evaluations. A nested SHA-256 Merkle tree commits to A/B/C triples at each vertical row and horizontal column. After the root is fixed, the probe derives two vertical rows and 309 horizontal queries, deduplicates repeated columns, opens two cells per queried column, checks Merkle paths, and compares three folded values to direct Horner evaluation. It also times one representative length-K `x·B_j` computation per distinct queried column, without proving that relation. During opening, it recomputes only the queried column trees from retained source columns; the rebuild is included in `sparse_open_seconds`.

| K | N=M | Distinct columns | Horizontal RS | Vertical RS | Grid hash | Sparse open | Opening bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 256 | 512 | 232 | 0.062 | 0.013 | 0.013 | 0.062 | 250,560 |
| 1024 | 2048 | 286 | 0.712 | 0.200 | 0.166 | 0.238 | 363,792 |
| 2048 | 4096 | 292 | 2.376 | 0.899 | 0.678 | 0.512 | 399,456 |
| 4096 | 8192 | 306 | 9.576 | 4.286 | 2.882 | 0.918 | 447,984 |

The sparse opening byte count is a raw layout sum, not a measured serialized payload. It contains six BN254 field elements and two inner Merkle paths plus one outer path for each distinct column; it is not the size of a complete proof. The current component uses SHA-256, whose cost *inside an outer Groth16 circuit* was not measured. The root does not prove that committed columns are low-degree codewords: a malicious prover could commit arbitrary vertical values. An FRI/DEEP-FRI style proximity argument or another sound polynomial commitment is required. The `xᵀB` contraction still needs an inner-product/sumcheck proof.

There is also a soundness loss if the Freivalds challenge is restricted to one of only M=2K vertical code positions. A nonzero degree-(K−1) error polynomial can vanish at K−1 of those M points, so one row query misses a fixed bad statement with probability as high as `(K−1)/M`, nearly 1/2. Additional horizontal column queries cannot repair a shared bad row challenge. `TestSingleVerticalRowChallengeCanMissAlmostHalfTheDomain` constructs this error polynomial. Repeating independent row challenges, raising M substantially, or opening at a random full-field point are possible responses; all have proving-cost consequences. For 128-bit soundness at rate 1/2, approximately 128 independent row challenges are needed even before accounting for other soundness terms.

The experiment therefore establishes the *byte reduction of authenticated sampled values* and the *cost of building that honest commitment*. It does not establish a faster or sound LAMP prover. The next candidate must be assessed with its low-degree proof, the `xᵀB` proof, and the outer SNARK verifier circuit in the measured online time.
