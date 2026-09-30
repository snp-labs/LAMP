# Comparison progress

Baseline updated 2026-09-29 for official commit `e2d1cae`; prototype update 2026-09-30.

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

## 2026-09-30 provisional operation estimate

Claude Haiku 4.5 implemented a separate zkMaP Appendix E operation workload, followed by root review/corrections. [80 measured operation attempts and limitations](ZKMAP_PROVISIONAL_TIMING.md) are published. Both node assumptions have nonzero remainders in all attempts; zero valid witnesses. This completes the requested provisional estimate, not the sound zkMaP baseline or full Linux Section 7 reproduction.

## 2026-09-30 proof-system exploration

[Vertical RS sparse-opening pilot](COLUMN_RS_SAMPLING_PILOT_KO.md) shows the full-column data reduction but also a concrete soundness gap: a single vertical grid challenge at rate 1/2 can miss an invalid relation with probability about 1/2, and the `xᵀB` inner product remains unproved. It is not a complete LAMP replacement.

[Full-field row-KZG/Freivalds pilot](ROW_KZG_FULL_FIELD_PILOT_KO.md) implements and checks two complete non-ZK matrix-product arguments for a different row-commitment statement. The direct commitment variant takes 51.462 seconds to commit and prove a 4096×4096 case and has a 131,080-byte inner proof; the 393,224-byte statement and SRS are separate. An outer Groth16 wrapper and its proof time remain unmeasured. These results are exploratory and are not inserted into the Shepherd comparison table.

[Original LAMP Groth16 KZG-link pilot](LAMP_KZG_GROTH16_LINK_PILOT_KO.md) embeds the unchanged ECC and sampled-column LAMP circuit and checks KZG links to the sampled commitments inside Groth16. This research path is opt-in, remains on `prototype/fast-pcs`, and must not be merged into main LAMP or reported as a production or paper result. The K=4, L=1 circuit compiles to 686,813 constraints versus 1,822 for the existing LAMP circuit.
