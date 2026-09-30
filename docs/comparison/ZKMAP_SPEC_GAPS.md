# zkMaP Equation Diagnostics and Specification Questions

Audit date: 2026-09-29. This is a diagnostic of equations and one explicitly
documented interpretation of Appendix E, not a complete zkMaP implementation,
security proof, or performance benchmark. Executable code is in
`crypto/zkmap_audit`; raw CLI output is saved at
`benchmark/comparison/diagnostics/zkmap-audit.json`.

## Challenge construction

The paper does bind the challenge to public parameters. Section 4.2, equation
(12), p.14, and Section 4.4, p.16, specify
`y = H(pp || VA || VB || VC) mod p`; the text says `pp` includes matrix
dimensions and the SRS description. The earlier claim that dimensions or the
SRS are omitted was incorrect and is withdrawn. This audit's diagnostic hash
includes n, a digest of the serialized public SRS, and uncompressed `VA`, `VB`,
and `VC` encodings.

## Rectangular polynomial convolution

For the Section 4.1, p.13 row-major example:

- A = `[[2,3,5],[7,11,13]]`
- B = `[[17,19],[23,29],[31,37]]`
- Direct matrix product, flattened: `[258,310,775,933]`
- First four coefficients of ordinary row-major polynomial convolution:
  `[34,89,188,341]`

The audit computes both arrays directly and asserts each exact coefficient.
This demonstrates that this ordinary polynomial convolution is not the matrix
product encoding. It does not analyze any different encoding that may be
intended elsewhere in the paper.

## Equation-only public-SRS pairing attacks

Section 4.4, p.16, contains an unnumbered scalar-evaluation pairing equation.
Its preceding formula uses `P_ay(y)·P_by(y)G1`. Appendix E Algorithm 2, p.37,
instead states the literal equation

`e(VW, sG2-yG2) = e(Vmu,G2) · e(Vay,G2)^-1 · e(Vby,G2)^-1`.

These are different verifier readings: the Appendix equation subtracts the two
G1 commitment points, which is not the product of the two field evaluations.
The main text's later shorthand `Vay · Vby` in the claimed bilinear equivalent
does not define a multiplication operation on G1 points; that shorthand is
therefore separately flagged as unimplementable without an explicit encoding
or scalar evaluation rule. The scalar diagnostic uses the explicit preceding
field evaluations, while the Appendix diagnostic uses the literal point
subtractions.
The audit executes attacks against both equations separately. In each n=2 and
n=4 run it:

1. Samples a nonzero setup scalar inside the SRS helper and retains only the
   public KZG SRS. The attack helper receives no trapdoor.
2. Commits with KZG to dense, nonzero A, B, and C matrices.
3. Computes AB independently and asserts the committed C is not AB.
4. Derives y from n, the serialized public SRS identity, and the three actual
   matrix commitments.
5. Constructs public proof points satisfying each equation, calls
   `bn254.PairingCheck`, then adds G1 to Vmu and confirms rejection.

For the scalar-evaluation reading, it chooses field values a=3, b=5, w=7,
t=15, and sets `VW=wG1`, `D1=sG1-yG1`, and `Vmu=tG1+wD1`. For literal Appendix
E Algorithm 2, it chooses nonzero public points `Vay=aG1`, `Vby=bG1`,
`VW=wG1`, and sets `Vmu=Vay+Vby+wD1`. The actual commitments to the false
matrices are included in challenge derivation, but the equation-only proof
points are not shown to be projections of those matrices.

**Scope limitation:** These are conditional algebraic counterexamples to the
listed checks when considered without additional checks that bind `Vay`,
`Vby`, or `Vmu` to the committed matrices. They are not a claim that every
unspecified or complete author implementation accepts the statements. The
paper's prose around Section 4.4 and its Appendix E algorithm disagree on the
right-hand side; the implementation must resolve that discrepancy and specify
all checks that bind the projection commitments.

## Appendix E interpolation reproduction

Appendix E Algorithm 2 lines 11-18, p.37, says to interpolate `Pay` and `Pby`
from the projection vectors but does not name interpolation nodes or fully
specify their encoding. The diagnostic records one explicit choice: Lagrange
interpolation over BN254's scalar field at nodes `0,1,...,n-1`, followed by
ordinary coefficient KZG commitments. It computes honest `C=AB`, the published
projections and μ, forms `μ-Pay(x)Pby(x)`, and performs synthetic division by
`x-y`. The exact remainder is reported. A nonzero remainder means this chosen
interpretation has no polynomial witness and therefore cannot run the literal
Appendix pairing check; the output does not treat the rational expression as a
polynomial witness. A zero remainder would still not establish that this node
choice is the authors' intended encoding or that the pairing check passes.

## Retired claims

- The claimed Fiat–Shamir omission of dimensions/SRS is removed because
  equation (12) explicitly includes `pp` with those parameters.
- No claim is made that hashing a public parameter fingerprint proves
  projection correctness.
- The prose-only compression injection result is removed from executed
  findings. Section 4.3, pp.14-15, describes a Vandermonde compression and a
  row-commitment construction; a generic observation about evaluating a
  bivariate polynomial at `(s,s)` is not a demonstrated attack on that full
  construction.
- The unrelated LAMP parameter comparison is omitted from this zkMaP equation
  diagnostic.

## Run

```sh
go test ./crypto/zkmap_audit ./cmd/zkmap_audit -v
go run ./cmd/zkmap_audit --json
```

The CLI exits nonzero if any executed diagnostic fails its stated assertion.
Pairing/commitment operations here establish no valid zkMaP prover/verifier
performance measurements.
