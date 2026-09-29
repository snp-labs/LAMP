# LAMP source fidelity and historical audit

This document preserves the source-gap review made against the archived public
snapshot at commit `b1c7636a7fc660712eeb3908698b4bb753b353c9`. That review is
historical and does not describe the current official worktree at
`e2d1cae15988779b0c65c7e492eb1dc4df2dd032`.

## Historical b1 snapshot finding

The supplied paper describes four sampled folds and a complete intermediate
witness commitment before query and code-check challenges. The archived `b1`
circuit exposed three folds, and its CLI made sampled openings before Groth16
proving. Its K7/rho=1/2/L=309 compile had 124,842 constraints, below the
paper's 167,065. See the source notes in `PAPER_PARAMETER_AUDIT.md` and the
archived worktree for that revision.

## Current official revision

The current comparison worktree is the clean official revision above. It uses
its own `GenerateIndices` and challenge order, has four folds, shared Y/Z
witness data, and a third commitment for the RS witness. Its K7/rho=1/2/L=309
compile is recorded at exactly 167,065 constraints. That constraint match is a
useful parameter check, not proof that every paper protocol detail, workload,
source revision, or benchmark-table condition has been reproduced. All current
records identify the official revision and preserve its implementation.

The comparison instrumentation does not modify the circuit, crypto, protocol,
sampler, or vendored gnark. Square and batch records keep their distinct
protocol paths, report the official query count, preserve the historical CSV
phase sum, and add a separate full-online timing boundary. Canonical compressed
LCP1 payload sizes are recorded only after decoding and verifying Groth16,
Merkle, and QA-link components. Batch q=1 is distinct from the square path.

No zkMaP paper scheme has been established from the available materials. The
`zkmap_audit` package is diagnostic only and is not included as a comparison
result. No full SOTA comparison or paper-ready claim should be inferred from
the tooling or smoke runs.
