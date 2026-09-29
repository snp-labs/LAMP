# Draft correspondence for resolving reproducibility gaps

These are drafts only. No messages have been sent. Verify executable diagnostic
results and attach their exact output before using the technical descriptions.

## zkMaP authors

Subject: Reproducing zkMaP for a matrix multiplication verification comparison

Dear Dr. Deressa and Professor Hasan,

We are preparing a same-machine comparison of matrix multiplication verification
protocols for our LAMP paper. We would like to benchmark zkMaP faithfully. The
repository named in Section 8.1 currently returns "Repository not found". Could
you share the artifact or an updated repository, along with its experiment settings?

While translating Sections 4.1--4.4 into code, we encountered several questions:

1. On page 13, the rectangular example claims that the row-major encodings satisfy
   P_C(x)=P_A(x)P_B(x) modulo x^4. For A=[[2,3,5],[7,11,13]] and
   B=[[17,19],[23,29],[31,37]], the product C has flattened coefficients
   [258,310,775,933], whereas the truncated polynomial convolution gives
   [34,89,188,341]. Is an additional encoding or transformation intended?
2. How exactly are the projection vectors a_y and b_y encoded in Section 4.2?
   Ordinary coefficient encoding does not turn their scalar inner product into
   P_ay(y)P_by(y). For A=B=I_2 and y=2 the inner product is 9 and the latter
   product is 45, so the numerator in Equation (14) is not divisible by x-y.
3. Your later thesis describes a cross-pairing with an additional G2 polynomial
   commitment for the product term. Should that construction be used for the
   published zkMaP benchmark? What SRS supports that G2 commitment, and what
   checks bind the projection commitments and evaluations to V_A,V_B,V_C?
4. Appendix E Algorithm 2's pairing equation appears to check V_mu-V_ay-V_by,
   whereas Section 4.4 refers to a product. Which equation should a faithful
   implementation use? What additional proof binds these intermediate values?
5. How are the column/row structures retained in the compressed F(s,s)
   commitment, where monomials with equal i+j share a univariate degree?
6. What security parameter, curve, SRS size, preprocessing, commitment accounting,
   thread count, and batch workloads should be used to reproduce Section 8?

We would welcome a corrected specification or clarification and will identify
any independent implementation clearly in our comparison.

Best regards,
The LAMP authors

## zkMatrix authors

Subject: zkMatrix artifact and benchmark parameters

Dear Dr. Cong, Dr. Yuen, and Professor Yiu,

We are preparing a same-machine comparison of committed matrix multiplication
verification protocols for LAMP. Could you share a zkMatrix implementation, if
available, or confirm the recommended implementation configuration?

We are implementing the final construction that adds zero knowledge within the
four projection/inner-product subprotocols, rather than applying the cubic masking
of Algorithm 5 to the full matrix product. We would particularly appreciate details
of the structured SRS layout for all subprotocols, the paired verification
acceleration and batching, and any fixed-base preprocessing used in the timings.

Our workloads include square dimensions 128 through 8192, ten independent
repetitions, batches of 1--10 independent products at dimension 128, and a
heterogeneous GPT-2 matrix multiplication workload. Please also clarify whether
commitment generation and setup/preprocessing are included in the reported costs.

Best regards,
The LAMP authors

## Shepherd progress response (only after checking results)

Dear shepherd,

We are preparing an independent implementation of zkMatrix and a reproducibility
assessment of zkMaP, and will distinguish independently reproduced measurements
from numbers reported in the original papers. We will report setup/preprocessing,
commitment generation, proving, verification, proof size and memory separately,
using a common machine and consistent parameter settings.

The zkMaP repository cited in its paper is currently inaccessible. We have also
identified specification questions in its matrix-to-polynomial encoding and
commitment verification that must be resolved before we can claim a faithful
benchmark. We can provide concrete algebraic counterexamples and diagnostic
tests, and intend to seek clarification from the authors.

We are checking the exact LAMP Section 7 artifact revision as well: the supplied
paper uses 309 queries, whereas the public snapshot defaults to 128 distinct
positions. The Appendix's independent-query convention supports an explicitly labelled
reconstruction with repeated positions. The public circuit with 309 queries
still differs in constraint count, so we will document that remaining revision
difference and distinguish reconstructed measurements from exact artifact runs.

Best regards,
The LAMP authors
