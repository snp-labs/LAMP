# 2026 author thesis recheck

Source: [Biniyam Deressa, Towards Trustworthy Federated Learning](https://dspacemainprd01.lib.uwaterloo.ca/server/api/core/bitstreams/eff117c6-1e76-4546-b099-2286c03c0d78/content), Chapter 5, Sections 5.3.2–5.5.7.

The thesis explicitly acknowledges that ordinary row-major polynomial
multiplication does not encode the matrix product. It nevertheless claims that
evaluating two projected-vector polynomials and multiplying those evaluations
implements their inner product. The existing diagnostic counterexample concerns
that remaining step.

Section 5.5.5 clarifies the disputed product commitment through a cross-pairing
with an additional G2 polynomial commitment. That explains the intended group
operation, but does not specify checks linking the projected commitments to
the original matrices. Section 5.5.4 still leaves the projected interpolation
convention ambiguous. The declared SRS also needs reconciliation with the
additional G2 polynomial commitment.

This is supplementary specification evidence, not an author clarification
received in correspondence and not a validated replacement protocol.
No faithful zkMaP performance row follows from the thesis explanation alone.
The diagnostic results remain limited to their implemented isolated equations.
