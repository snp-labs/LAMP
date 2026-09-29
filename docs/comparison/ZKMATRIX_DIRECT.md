# Independent zkMatrix implementation

The default benchmark proof uses the optimized four-IPA composition and
aggregate pairing verifier described in [ZKMATRIX_FIDELITY_CHECKLIST.md](ZKMATRIX_FIDELITY_CHECKLIST.md).
The implementation maps Algorithms 1–5 and Section 5.2 masking to BN254, with
an Eq. 22 structured SRS and Eq. 21 aggregation. It is an independent
implementation, not the authors' code or a formal security review.

The prover receives private A, B, C and the three commitment openings. It does
not compute C=A·B; input generation does that before the commit/prove timers.
The verifier receives only immutable public parameters, the three-commitment
statement, and the proof. PublicParams fields are opaque after setup; the
verifier does not rehash the full SRS for each call. Proof serialization is
canonical and checks compressed subgroup points, dimension-derived round
counts, exact lengths, and trailing bytes.

Setup uses single-party random tau/nu values and discards their references. No
secure erasure or production MPC setup is claimed. BN254 differs from the
paper's BLS12-381 instantiation. The `direct` CLI variant uses the same optimized
proof and independently checks the four IPAs directly; its verifier is linear
in matrix dimensions. `VerifyConservative` is a separate six-IPA reference with
additional scalar/output knowledge checks and must not be reported as the
optimized construction.

For the accelerated verifier, each IPA still has logarithmically many folding
rounds. The residual polynomial coefficients for the four projections are
evaluated from folded challenges and dimension offsets (`factorizedPhi`), so
the verifier does not rebuild a dense matrix-sized basis for that check. The
final BN254 pairing check combines the four residuals into three pairing terms.
This is a common-curve adaptation of the paper's construction: the implementation
uses BN254 scalar and pairing groups, while the paper's reported instantiation
uses BLS12-381. Do not present the adaptation as the paper's curve or as a
security review.

The default development limit is 1,048,576 field elements per matrix. An
explicit `--max-matrix-elements` option can raise it for a server with adequate
memory; this is a resource opt-in, not evidence that K=11–13 were run locally.
For square K=13, the single unshifted/shifted structured SRS lists together
contain roughly 2×8192² G1 points (about 8 GiB of affine coordinates before
other process memory). Do not run that locally without a reviewed resource
budget.

The CLI reports setup, data-preparation matrix multiplication, commitments,
remaining proving work, total proving work, verification, actual serialized
bytes, machine/runtime metadata, and the selected verifier variant. Smoke runs
are not a paper reproduction or speed comparison. CSV creation uses exclusive
file creation and never overwrites a previous run.

The reported compressed SRS byte count is the sum for the two public G1 power
arrays and three G2 anchors. It excludes the fixed hiding point and all framing
or serialization headers; it is a point payload estimate, not a complete
transmitted SRS artifact size.
