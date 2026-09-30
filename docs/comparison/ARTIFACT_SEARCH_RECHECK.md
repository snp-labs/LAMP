# Artifact search recheck — 2026-09-29

The package named `zkmatrix` on [Docs.rs](https://docs.rs/crate/zkmatrix/latest)
currently describes **DualMatrix**, its two-tier pairing commitments and four
subprotocols. This name alone does not identify an implementation of the
requested zkMatrix protocol. Its older source pages could not be retrieved in
this recheck; no conclusion about unseen older code is made.

The [DualMatrix authors’ publication](https://link.springer.com/article/10.1186/s42400-025-00462-6)
also states that its zkMatrix comparison used theoretical costs and measured
primitive timings because an implementation was unavailable to them. That is
historical evidence, not proof that no source exists today.

The supplied zkMatrix paper identifies its own BLS12-381 results as estimates
assuming 16-thread parallelism. Our implementation and measurements remain
explicitly independent, using BN254 and Go. We have not relabelled DualMatrix
code or its measurements as zkMatrix.

For zkMaP, the linked author artifact still returned 404 in the current check.
The original paper and the later thesis recheck are tracked separately in
`ZKMAP_SPEC_GAPS.md` and `ZKMAP_THESIS_RECHECK.md`. Equation diagnostics receive
no performance-baseline rows.

The exact zkMaP artifact was also queried with the locally available GitHub
API access and returned HTTP 404. Public Rust code searches for
`OptimizedBatchedZKMatrixProof` and `zkMaP` returned zero results in this check.
These observations describe the queried access and search scope; they do not
prove that no private or differently named implementation exists.

## Additional name-collision check (2026-09-29, 08:06 UTC)

Author-name searches for `zkMaP Deressa code github` and `zkMaP implementation
repository Hasan` did not yield a newly accessible author-confirmed artifact.
An indexed [Gitee repository named zkmap](https://gitee.com/ted668/zkmap) was
checked through its public [repository API](https://gitee.com/api/v5/repos/ted668/zkmap).
Its metadata records creation and last push on 2017-05-22; its root contains
`src`, `pom.xml`, and a README containing only the repository name. No connection
to the 2025 Deressa–Hasan paper is established. This name collision is not used
as a performance implementation. Metadata/root/README API responses are retained
in the parent `tmp/gitee-zkmap-candidate*.json` files. This remains a bounded
search, not evidence that an implementation can never be found.
