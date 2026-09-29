# Inputs required to finish the requested paper comparison

The local tools and independent implementations can be developed without these
inputs. A faithful, same-host Section 7 comparison cannot be certified until they
are resolved.

## LAMP source is available

The latest official revision is available at
e2d1cae15988779b0c65c7e492eb1dc4df2dd032. Its smallest paper configuration
compiles to the stated 167,065 constraints, and full square and batch proof
checks succeeded. This revision is the basis for the comparison tooling.
See `OFFICIAL_REVISION_RECHECK.md` for its concrete implementation details.

An exact replay of the publication's original table would additionally require
its original raw measurements and machine configuration. That archival
confirmation does not prevent new same-host experiments on the official code.
The historical b1 source-gap note applies only to the archived earlier checkout.

## zkMaP specification or artifact

Provide an accessible author implementation or clarification of the matrix
encoding, projection relation and binding checks listed in
AUTHOR_CLARIFICATION_DRAFTS.md. The executable isolated-equation diagnostics are
not a sound matrix verification scheme and must not receive benchmark rows
presented as zkMaP performance.

## Common experiment machine

Provide access/instructions for the common Linux host, ideally the paper's
EPYC 7B13 with 32 cores and 256 GiB. Record its actual processor, OS, memory,
thread count and software versions. The local M1 Pro development checks establish
execution correctness for the tested cases; they are not the paper's hardware
measurements. Run all comparison implementations on the same host.

## Results that remain required

- Square n=128 through 8192, ten repetitions per completed configuration.
- Batch q=1 through 10 at n=128, ten repetitions.
- The Section 7 linked GPT-2 workload, with its tensor relations accounted for;
  independent products of the same shapes alone are not an equivalent workload.
- Separate setup, input/output commitment, full online proving, full verification,
  actual serialized proof and statement bytes, and memory measurements.
- Source/binary identities and failed/partial run records alongside raw values.

No correspondence has been sent. Drafts can be reviewed and sent by the authors.
