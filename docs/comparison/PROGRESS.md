# Comparison progress

Updated 2026-09-29 for official commit `e2d1cae`.

## Completed

- Migrated the independently reviewed zkMatrix implementation, batch proof and
  CLI, and zkMaP diagnostics into this latest official worktree. Imports use
  `example.com/lamp`.
- Added decoded direct verification to the zkMatrix batch codec test.
- Added opt-in LAMP full-online timing and canonical compressed LCP1 payload
  round-trip/reverification for square and batch paths. Official protocol and
  baseline CSV output are preserved.
- Added a source/binary/host-aware runner, strict raw-record aggregation,
  numeric zkMatrix CSV adapter, scheme filtering, q=1 path identity, and
  non-executing server plans.
- Targeted Go and Python fixtures pass.
- Two isolated decoded full-proof smokes passed before freezing the measured source:
  square K7/L309 and batch q=2/K7/L309, GOMAXPROCS=10. See
  `DEVELOPMENT_RUNS.md` for raw artifact paths.

## Local measurements completed

All 300 planned local proofs passed verification: square n=128,256,512,1024
(80), independent-claim batch q=1..10 at n=128 (200), and two additional LAMP
code-rate profiles (20). All 30 conditions have ten repetitions. The 174
completed effective commands, raw records, numeric summaries and three figures
are documented in [LOCAL_RESULTS.md](LOCAL_RESULTS.md).

Measured source hash:
`c34bd62bee6f07a879d7e4b48d8b9c17e0ca48c34e796425e2bec93ed74e6f93`.
The frozen source archive is preserved. Public GitHub HEAD/master was rechecked
on 2026-09-29 and still matched official e2d1cae, already reflected here.

A user-requested source check interrupted the original batch run. Its completed
78-command prefix (168 proofs) was checked and preserved; the remaining 32
commands completed in `batch_q1_q10_m1pro_20260929_resume1`, reusing the same
binaries and source. The interrupted attempt is excluded from aggregation.

## Still required

- Adequate common server for the K7..13 square and q=1..10 batch grids.
- A fully specified and executable zkMaP protocol; diagnostics are excluded
  from performance comparison.
- A complete GPT-2 linked workload comparison and confirmed Section 7 setup
  provenance before claiming a full paper reproduction.

No full SOTA comparison, universal performance conclusion, or paper-ready
common-host table is claimed.

## Server preparation reviewed

The future zkMatrix CLI uses the official parallel rectangular matrix multiply
for honest C generation before the proving timer. Narrow multiplication tests
and tiny decoded-proof checks passed. Its source hash is
`0c004f987e5b6e3dfb08242edbd3ed7f1bf0c19d815ecf0f779e4695d034aa83`;
it is distinct from the measured c34 archive. No future-source paper-size run
has been substituted into the local result tables.
