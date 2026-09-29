# Common-host execution recipe

These commands run new experiments. They do not reproduce the publication’s
archival table or provide the missing zkMaP author specification.

## Transfer a source snapshot

Use a fresh Git clone at official e2d1cae, then overlay one source archive.
The archives contain Go/module/comparison sources, not Git metadata or all
original non-Go assets; the clone supplies those unchanged upstream files.
Use Go 1.26.2. Server binaries will be rebuilt and get their own hashes.

- Recommended for future large runs: [server source archive](../../benchmark/comparison/published_20260929/source/future-server/comparison-server-source.tar.gz).
  Source hash `0c004f987e5b6e3dfb08242edbd3ed7f1bf0c19d815ecf0f779e4695d034aa83`.
  Only the CLI's untimed honest C calculation uses the existing official
  parallel matrix helper, with shape validation; a narrow test is added.
- Exact snapshot used by the 300 local proofs: [measured archive](../../benchmark/comparison/published_20260929/source/measured/comparison-source.tar.gz).
  Source hash `c34bd62bee6f07a879d7e4b48d8b9c17e0ca48c34e796425e2bec93ed74e6f93`.
  Its serial C preparation can exceed the command timeout for ten n=8192
  preparations. This untimed work is reported separately.

Transfer the selected archive, its adjacent SHA-256 file and source manifest.
For the recommended future snapshot:

```sh
git clone https://github.com/snp-labs/LAMP.git LAMP-comparison
cd LAMP-comparison
git checkout --detach e2d1cae15988779b0c65c7e492eb1dc4df2dd032
# Transfer the selected archive, checksum and source-manifest.json here.
sha256sum -c comparison-server-source.tar.gz.sha256
tar -xzf comparison-server-source.tar.gz
```

Before execution, import `scripts/comparison/run.py` and call
`source_manifest()` to compare its source-tree hash and HEAD with the selected
source manifest. The 300 local measurements retain their measured-snapshot
identity. No future-source timing has been substituted into them. Keep results
from different source fingerprints separate.

## Square and independent-claim batch

Use the official `e2d1cae` comparison worktree and a nominal 256 GiB Linux host
with at least 32 logical CPUs. Record actual usable RAM; the runner allows the
240 GiB usable-memory floor to account for operating-system reservations.
Run in a quiet session, with the same CPU/thread budget for both schemes.

```sh
python3 scripts/comparison/run.py --config server_square_k7_k13 --scheme both --plan
python3 scripts/comparison/run.py --config server_batch_q1_q10 --scheme both --plan
python3 scripts/comparison/run.py --config server_square_k7_k13 --scheme both
python3 scripts/comparison/run.py --config server_batch_q1_q10 --scheme both
```

Each profile creates a new experiment directory, isolated binaries, per-command
logs, verified numeric records, source/binary identities and summaries. Never
merge rows from another source, machine, binary, protocol path or parameter
profile. Keep failed/OOM/interrupted configurations as explicit missing entries.

## Actual GPT-2 matrix products

The optional zkMatrix path uses the official tensor generator’s products and
batches equal rectangular shapes. It proves **matrix-product claims only**:
LAMP’s graph wiring and designated public input/output binding are additional
claims absent from this certificate. Present these as different proof scopes
in the discussion, not equivalent complete GPT-2 proofs.

```sh
go build -o /tmp/lamp_gpt2_comparison ./cmd/lamp_gpt2
/tmp/lamp_gpt2_comparison -seq 10 -baseline-plan
/usr/bin/time -v /tmp/lamp_gpt2_comparison -seq 10 -baseline zkmatrix_grouped_matmul_claims_only -repetitions 10 -threads 32 -baseline-output /tmp/zkMatrix_gpt2_claims.json
```

Choose fresh output paths for each experiment. Retain the `/usr/bin/time`
standard-error log alongside the manifest for actual peak process RSS. Setup is
shared once per shape; one graph is reused with fresh commitment blindings.
No full sequence-1024 run has yet been completed locally. The original LAMP
GPT-2 CLI remains available, but its historical CSV totals require the same
care about timer and communication definitions as the publication’s table.
Do not combine historical GPT-2 totals with square/batch normalized rows.

## zkMaP

No faithful benchmark command is provided while the encoding and complete
binding checks remain unresolved. `cmd/zkmap_audit` produces equation
diagnostics, not zkMaP performance measurements. Author clarification questions
are in `AUTHOR_CLARIFICATION_DRAFTS.md`; no correspondence has been sent.
