# Published local evidence, 2026-09-29

300 verified proof repetitions, 30 conditions, 174 effective commands.
Four JSONL files retain the original numeric rows. index.json records their
checksums, source/config/host metadata, command binary identities, elapsed time
and whole-process RSS. The interrupted batch attempt is excluded.

This is shared M1 Pro, BN254 development evidence, not the complete Section 7
three-protocol common-host comparison. Serialized payloads were decoded and
reverified during execution; exported proof files are not included.

source/measured contains the exact source overlay used by all 300 rows.
source/future-server contains the separate preparation-only CLI revision.
Clone official e2d1cae before applying an overlay; this supplies Git metadata,
licenses and unchanged upstream non-Go build assets. Do not relabel old results
with the future hash. Local arm64 binaries and full logs are retained in the
local artifact bundle; they are not committed to Git.

See ../../../docs/comparison/LOCAL_RESULTS.md for means, sample SD and figures,
and ../../../docs/comparison/SERVER_EXECUTION.md for new server experiments.
