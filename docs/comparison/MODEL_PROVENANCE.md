# Implementation provenance

This bounded migration and harness completion used Codex with `gpt-6-luna`, as
requested. No native agents were used.

The zkMatrix and zkMaP diagnostic packages were copied from the archived
preliminary checkout after review, then adapted to module path
`example.com/lamp`. The LAMP instrumentation was implemented against the
latest official source. Existing official circuit, crypto, protocol, sampler,
challenge order, QA-link algorithm, vendored gnark, and historical CSV schema
were preserved.

The older `../upstream` checkout and its measurements remain archived
preliminary work. Current smoke outputs, source audit, and comparison tooling
belong to this official `e2d1cae` worktree under `benchmark/comparison/`.
Tooling tests and local smokes establish implementation behavior only; they do
not imply author validation, security review, a faithful zkMaP baseline, or a
complete paper comparison.

The external interruption-resume helper and isolated filesystem fixtures were
also implemented with `gpt-6-luna` and reviewed by root. They live under the
parent `tmp/` directory and do not change the frozen measured source. Root
performed independent read-only checks of all 168 reused rows against the full
config, per-command binary SHA, host metadata, protocol path, dimensions and
query count before launching the continuation.

The preparation-only future-server CLI change used a fresh gpt-6-luna coding
session after the measurement controller reported complete. Root reviewed its
diff against the measured archive and audited all 300 rows' complete configs,
binary identities and host metadata. The original matrix/protocol/crypto code
was preserved; the updated CLI and new multiplication test receive a separate
source fingerprint. The tiny CLI checks are functional evidence only.
