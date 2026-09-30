# LAMP Quick Start
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.22787398-blue.svg)](https://doi.org/10.5281/zenodo.22787398)

This repository contains Go implementations for `LAMP: Linear Verification of
Matrix Multiplication via Proximity Testing`, along with Freivalds baselines over
gnark/Groth16.
It is intended as a lightweight artifact for reproducing comparison
experiments.

Implemented experiments:

- `lamp`: square matrix multiplication with the LAMP protocol.
- `lamp_batch`: random-linear-combination batch LAMP for multiple square
  matrix multiplications.
- `freivalds`: square matrix multiplication Freivalds baseline.
- `freivalds_batch`: batched Freivalds baseline for multiple square matrix
  multiplications in one Groth16 proof.
- `lamp_gpt2`: LAMP benchmark for one GPT-2 medium matmul-only layer.
- `freivalds_gpt2`: Freivalds baseline for the same GPT-2 matmul-only layer.

The GPT-2 experiments only include matrix multiplications. LayerNorm,
activation functions, softmax, tokenization, and language-model inference are
outside the benchmark scope.

## Requirements

Recommended:

- Docker

Optional local execution:

- Go `1.25.6`

The scripts build the Docker image from the included `Dockerfile` and mount the
`benchmark/` directory back into this repository.

## Setup

Create a local environment file:

```sh
cp .env.example .env
```

The default values in `.env.example` can be changed, but command-line flags
override them for ad-hoc runs. LAMP runs use the QA-batch CP-link backend and
Merkle multiproofs; these are fixed and are not configured through `.env` or
command-line flags. The default number of sampled queries is `L=309`.

To run a one-off experiment with different parameters, pass flags after the
target name:

```sh
sh scripts/run_bench.sh lamp --K 10 --rho 1/2 --L 309
sh scripts/run_bench.sh lamp_batch --K 10 --rho 1/2 --L 309 --batch 5
sh scripts/run_bench.sh lamp --range --from 7 --to 13
sh scripts/run_bench.sh lamp_batch --batch-range --batch-from 1 --batch-to 10
sh scripts/run_gpt2_bench.sh lamp --seq 7 --rho 1/2 --L 309
sh scripts/run_gpt2_bench.sh lamp --range --from 7 --to 10
```

Here `--K 10` means square matrix dimension `K=2^10`, and `--seq 7` means GPT-2
sequence length `2^7`.

Range scripts run one configuration per fresh container, sequentially. No CPU
or memory limit is applied, so each benchmark process can use all resources
available to Docker, and each CSV `PeakMemory(B)` value is an independent peak
RSS measurement.


## Running Benchmarks

Square LAMP:

```sh
sh scripts/run_bench.sh lamp
```

Square LAMP batch:

```sh
sh scripts/run_bench.sh lamp_batch
```

Square Freivalds:

```sh
sh scripts/run_bench.sh freivalds
sh scripts/run_bench.sh freivalds_batch
```

GPT-2 LAMP:

```sh
sh scripts/run_gpt2_bench.sh lamp
```

GPT-2 Freivalds:

```sh
sh scripts/run_gpt2_bench.sh freivalds
```

The GPT-2 dimensions are fixed to GPT-2 medium:

```text
embedding dimension D = 1024
number of heads       = 16
head dimension Dh     = 64
MLP dimension M       = 4096
```

## Range Runs

Square LAMP and Freivalds:

Set `LAMP_ALL=true`, `LAMP_BATCH_RANGE=true`, `FREIVALDS_ALL=true`, or
`FREIVALDS_BATCH_RANGE=true` in `.env` for range runs.

```sh
sh scripts/run_bench.sh lamp
sh scripts/run_bench.sh lamp_batch
sh scripts/run_bench.sh freivalds
sh scripts/run_bench.sh freivalds_batch
sh scripts/run_bench.sh all
```

GPT-2 LAMP and Freivalds:

Set `LAMP_GPT2_ALL=true` or `FREIVALDS_GPT2_ALL=true` in `.env`.

```sh
sh scripts/run_gpt2_bench.sh lamp
sh scripts/run_gpt2_bench.sh freivalds
sh scripts/run_gpt2_bench.sh all
```

Set the range bounds and batch-size ranges in `.env` before running these
commands.

## Output

Benchmark CSV files are written under:

```text
benchmark/lamp/
benchmark/lamp_batch/
benchmark/freivalds/
benchmark/freivalds_batch/
benchmark/lamp_gpt2/
benchmark/freivalds_gpt2/
```

The main timing columns include matrix computation, setup, proving, and
verification times.

Each CSV output directory also contains `system_info.json`, which records the
CPU model, logical core count, RAM, OS, architecture, Go version, and timestamp
for the benchmark run.

## Reproducible comparison tooling

The independent zkMatrix implementation, diagnostic-only zkMaP audit, numeric
comparison runner, and current source-fidelity notes are under
[`docs/comparison/IMPLEMENTATION_STATUS.md`](docs/comparison/IMPLEMENTATION_STATUS.md).
The current comparison target is the official revision `e2d1cae`; historical
measurements in the archived `../upstream` checkout are preliminary and are not
current-worktree benchmark results.

A one-command local smoke/runner invocation uses the K7 development profile:

```sh
python3 scripts/comparison/run.py --config development --scheme both
```

The reviewed local measurement profiles are `official_squares_local` (K7
square, ten repetitions for both implementations) and `official_batch_local`
(zkMatrix batch q=1..10 plus LAMP batch q=2, ten repetitions). They use ten
threads and retain the local matrix element cap:

```sh
python3 scripts/comparison/run.py --config official_squares_local --scheme both
python3 scripts/comparison/run.py --config official_batch_local --scheme both
```

For the full local square grid through K=10 and the matching LAMP/zkMatrix
batch q=1..10 grid, use `official_squares_k7_k10_local` and
`official_batch_q1_q10_local`. Optional square rate profiles use rho=1/4,
L=189 and rho=1/8, L=155, with ten repetitions each:

```sh
python3 scripts/comparison/run.py --config official_squares_k7_k10_local --scheme both
python3 scripts/comparison/run.py --config official_batch_q1_q10_local --scheme both
python3 scripts/comparison/run.py --config official_square_rho_1_4_local --scheme both
python3 scripts/comparison/run.py --config official_square_rho_1_8_local --scheme both
```

The shape-only GPT-2 plan lists the official graph's 36 matmul claims without
allocating matrices or setting up an SRS:

```sh
go run ./cmd/lamp_gpt2 --baseline-plan --seq 10
```

The optional zkMatrix execution path is
`--baseline zkmatrix_grouped_matmul_claims_only`; it has a 32 CPU and 240 GiB
usable-memory guard (for a nominal 256 GiB host), defaults to ten repetitions,
and accepts `--threads`. Its certificate covers the actual matrix products
only. Both `graph_wiring_certified` and
`public_input_output_binding_certified` are false, so it is not a full linked
GPT-2 certificate. Do not run it on a laptop; use plan mode there.

The runner records isolated output, source and binary hashes, host details,
verified numeric JSONL records, and a manifest. To inspect a non-executing
server plan, use:

```sh
python3 scripts/comparison/run.py --config server_square_k7_k13 --scheme both --plan
python3 scripts/comparison/run.py --config server_batch_q1_q10 --scheme lamp --plan
```

The server plans specify K=7..13 square runs and LAMP batch q=1..10 with ten
repetitions and a 32-thread budget. They are plans only; use an adequately
provisioned host before running them. The paper-parameter profile is named
`official_paper_parameters`. It checks the latest official K7/rho=1/2/L=309
constraint count and does not assert a complete paper reproduction. See
[`docs/comparison/LAMP_PROTOCOL_REVISION_GAP.md`](docs/comparison/LAMP_PROTOCOL_REVISION_GAP.md)
for the revision-specific audit.

On a host that passes the resource guard, execute the server grids with:

```sh
python3 scripts/comparison/run.py --config server_square_k7_k13 --scheme both
python3 scripts/comparison/run.py --config server_batch_q1_q10 --scheme both
```

Completed shared-desktop measurements (300 verified proofs) and limits are in
[LOCAL_RESULTS.md](docs/comparison/LOCAL_RESULTS.md). Portable numerical records
and the distinct measured/future source overlays are in
[published evidence](benchmark/comparison/published_20260929/README.md).
