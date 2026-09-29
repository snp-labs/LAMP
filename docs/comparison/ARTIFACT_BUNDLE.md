# Comparison artifacts — 2026-09-29

[Public numeric records and source overlays](../../benchmark/comparison/published_20260929/README.md). The complete local archive, including arm64 binaries and full logs, is retained as `lamp-comparison-20260929.tar.gz` with its adjacent checksum; it is not committed to Git.

## Completed local evidence

- 300 verified proofs across 30 conditions, ten repetitions each.
- Square n=128,256,512,1024: 80 proofs.
- Independent-claim batch n=128, q=1..10: 200 proofs.
- LAMP square n=128, rho=1/4 and 1/8: 20 proofs.
- 174 completed effective commands. An interrupted batch attempt is retained
  for audit and excluded from the effective-result index.

[Readable results](LOCAL_RESULTS.md) · [full metric tables](results_20260929/MEASUREMENT_TABLES.md) · [numeric CSV](results_20260929/compact_summary.csv) · [server instructions](SERVER_EXECUTION.md) · [shepherd response draft](SHEPHERD_RESPONSE_DRAFT.md)

## Two source identities

All local benchmark rows belong to official LAMP e2d1cae plus comparison
instrumentation and independent zkMatrix, measured source hash:
`c34bd62bee6f07a879d7e4b48d8b9c17e0ca48c34e796425e2bec93ed74e6f93`.

The separately supplied future-server snapshot has hash:
`0c004f987e5b6e3dfb08242edbd3ed7f1bf0c19d815ecf0f779e4695d034aa83`.
It changes only the CLI's untimed C preparation to the official parallel helper
and adds a multiplication test. Its tests and tiny decoded-proof checks passed.
No paper-size future-source result is claimed or inserted into the tables.

Both source archives are overlays for a fresh Git clone at exact official
`e2d1cae15988779b0c65c7e492eb1dc4df2dd032`. The clone provides Git metadata,
licenses and unchanged non-Go build assets. See the server recipe.

## Bundle layout and integrity

`source/measured/` and `source/future-server/` contain distinct archives,
checksums and source manifests. `experiments/` preserves original and continued
experiment folders, including logs, raw numeric records, source/binary/host
manifests and local arm64 binaries. Linux runs rebuild their own binaries.
`docs/` contains the report, CSV, PNG/PDF figures and fidelity/scope notes.
`analysis/` contains the report generator and continuation helper/fixtures.
`functional/` contains the future-source tiny CLI check, outside benchmark rows.

`eligible_raw_records.json` maps the 174 effective commands to portable
relative raw-file paths and SHA-256 values (300 verified rows). It excludes the
interrupted attempt. Historical manifest paths remain the original absolute
paths for provenance; use this index when reading relocated data. Keep the
original and continued batch folders together.
`file_checksums.json` records the included files' paths, lengths and SHA-256.
The bundle's separate `.sha256` file checks the tar archive itself.

Proof payloads were serialized, decoded and reverified during execution; the
retained records are numerical/log evidence, not a collection of exported
proof payload files. The bundled sources support rerunning the checks.

## Remaining comparison requirements

These are shared M1 Pro desktop, BN254 development measurements. A quiet common
Linux host is still needed for the full Section 7 grid. zkMaP encoding and full
projection-binding checks still need a usable artifact or author clarification.
The GPT-2 zkMatrix baseline proves the generator's 36 matrix products only;
graph wiring and designated public input/output binding are outside that scope.
This bundle does not complete the requested three-protocol paper comparison.
