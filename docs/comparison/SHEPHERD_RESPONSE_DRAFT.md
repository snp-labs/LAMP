# Shepherd response draft — incomplete experiments

Do not submit this as a completed comparison. No results have been invented.
Replace the bracketed sections only after the specified runs and fidelity review.

Dear shepherd,

Thank you for specifying the comparison needed to address this concern. We are
reconstructing zkMatrix independently from its published algorithms, including
the quadratic zero-knowledge construction and pairing-based verification
acceleration. We will identify the implementation and any differences in its
curve, SRS layout, batching and preprocessing.

The comparison will use the matrix dimensions and workloads of Section 7 on a
common machine. We will report setup separately, both commitment-inclusive and
precommitted proving costs, full verification costs, serialized communication,
and memory. Each completed configuration will have ten repetitions with raw
records and summary statistics.

Our initial square measurements are complete on a shared Apple M1 Pro desktop
(macOS, 32 GiB, Go 1.26.2, ten threads), using BN254 for both implementations.
For n=128,256,512,1024, commitment-inclusive mean proving times (seconds) are
respectively 2.0662,4.1358,9.0708,22.0986 for LAMP and
1.3470,4.6207,16.9261,66.5999 for our independent zkMatrix implementation.
Each entry contains ten verified repetitions; the actual serialized statements
and proofs were decoded and reverified. Setup, compilation and matrix
multiplication are excluded. Complete variability and separate setup,
precommitted proving, commitment and process-memory values accompany the raw
records in `results_20260929/`.

These measurements expose a prover/verifier/communication trade-off. LAMP has
smaller mean proving time at the three larger completed dimensions, while
zkMatrix has smaller mean proving time at n=128. zkMatrix verifies faster at all
four measured dimensions (approximately 9.1–11.3 ms versus 167.2–171.6 ms), and
its compressed proof payload is smaller (4096–5440 bytes versus mean
24288–60742.4 bytes). Statement sizes are separately 112 bytes for zkMatrix and
64 bytes for LAMP. These comparisons describe the tested implementations on
this host. Desktop load was uncontrolled; they require confirmation on the
common Linux host before inclusion as the requested Section 7 experiment.
They do not assert equal security to zkMatrix's published BLS12-381 setting.

The local independent-claim batch grid at n=128 and q=1..10 is also complete
(200 verified proofs). At q=1 and q=10, LAMP mean commitment-inclusive proving
times are 2.1099 and 19.2354 seconds, versus 1.1271 and 1.7240 seconds for
zkMatrix. Across this measured grid, zkMatrix has smaller mean proving and
verification time and smaller proof payload. LAMP verification and payload
remain approximately stable: mean 167.9–178.0 ms and 24,217.6–24,428.8 bytes.
zkMatrix payload increases from 4,100 to 11,624 bytes, with separate statements
of 112 to 1,120 bytes; LAMP statements are 64 bytes. The complete mean/sample-SD
rows and raw provenance are provided in the local report.

Two additional LAMP n=128 square profiles completed ten proofs each. With
rho=1/4 and 189 queries, mean proving is 1.6058 seconds, verification 105.248 ms
and payload 25,120 bytes. With rho=1/8 and 155 queries, these are 1.7234 seconds,
86.734 ms and 30,713.6 bytes. Lower rate does not uniformly reduce every cost.
The measured constraints match the supplied paper counts, respectively
107,503 and 95,917.

All 300 local proofs were serialized, decoded and reverified. Both schemes use
dense full-field matrices with matching dimensions/counts, but their input
generators differ (seeded canonical PRNG draws for zkMatrix, official
cryptographic generation for LAMP), so A/B values are not byte-identical.
A source-check interruption preserved 168 completed batch proofs; the remaining
32 completed with the same frozen source and binaries in a separate directory.
The interrupted attempt is excluded.

[Insert quiet common-host results for the full Section 7 dimensions and linked
workload before submission. These local experiments do not complete the
requested three-protocol common-host comparison.]

For zkMaP, the artifact URL specified in Section 8.1 currently returns
“Repository not found.” Reimplementation also encountered discrepancies between
the matrix polynomial encoding, the scalar multiplication check in Section 4.4,
and the additive check in Appendix E Algorithm 2. Our executable diagnostics
demonstrate the exact equations being evaluated, including false-output
acceptance by those isolated equations; we have not treated these incomplete
checks as a sound matrix multiplication baseline.

[Insert author clarification and a faithful zkMaP implementation and results,
or discuss the documented reproduction limitation with the shepherd.]

The latest official LAMP revision was rechecked against the supplied parameter table. At K=128, rho=1/2, L=309 it compiles to 167,065 constraints, matching the paper count. We preserve its sampler, challenge ordering, circuit, crypto, and QA-link verification. Decoded square and batch smokes and all 300 planned local proofs succeeded; these do not establish every Section 7 workload condition. We will report full results only after common-host runs and confirmation of the paper setup and workload details. Historical b1 measurements are excluded.

Best regards,
The LAMP authors
