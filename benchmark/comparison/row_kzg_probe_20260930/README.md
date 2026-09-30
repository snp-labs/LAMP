# Full-field row-KZG Freivalds probe

Date: 2026-09-30. Host: Apple M1 Pro, macOS arm64, Go 1.26.2, 10 workers. The implementation is in `crypto/kzgrow` and `cmd/lamp_kzg_row_probe`. It is a complete, non-zero-knowledge matrix-product argument **for the supplied KZG row-commitment statement**, but it is a different protocol from LAMP's sampled encoded columns. In particular, it is not a drop-in replacement for the LAMP paper or a benchmark of the same transcript and external commitments.

Reproduce from the repository root:

```sh
go build -o /tmp/lamp_kzg_row_probe ./cmd/lamp_kzg_row_probe
for logk in 8 10 11 12; do /tmp/lamp_kzg_row_probe --logK "$logk" --workers 10 --seed 20260930; done
go test -race ./crypto/kzgrow ./cmd/lamp_kzg_row_probe
```

The benchmark uses dense A = I + uvᵀ, random dense B, and C = AB computed in O(K²) so large honest instances can be generated promptly. Matrix generation is timed separately and is excluded from `full_online_prove_seconds`. Row interpolation, all 3K row commitments, and the inner proof are included. KZG SRS setup is timed separately. The SRS is generated with a fresh cryptographic random alpha for this local benchmark; a deployment requires a trusted ceremony or existing trusted SRS. A and C's special algebraic form may affect performance despite their dense field entries, so these timings are exploratory.

Each row is committed as a degree-<K polynomial that interpolates its K entries on a roots-of-unity domain. After all row digests are fixed, a full-field challenge r is derived. The prover sends x=rᵀA. The verifier interpolates x, commits to it, and compares that commitment with the linear combination of A's row digests, binding x to A. There are two complete variants:

- **Batched point opening:** after x is fixed, derive a second full-field challenge s. One batched KZG proof opens B₀(s),…,Bₖ₋₁(s),Cᵣ(s), where Cᵣ is the r-weighted sum of C rows. Verify ΣᵢxᵢBᵢ(s)=Cᵣ(s). The algebraic error term for a fixed false product is at most 2(K−1)/|Fr| before Fiat–Shamir and KZG assumptions.
- **Direct commitment equality:** compare ΣᵢxᵢCom(Bᵢ) with ΣᵢrⁱCom(Cᵢ) directly. This needs no s challenge, B evaluations, or opening proof. The algebraic error term is at most (K−1)/|Fr| before Fiat–Shamir and KZG binding assumptions.

`results.jsonl` contains the one-run values for each size. `proof_bytes` is the batched-opening proof and `direct_proof_bytes` is the direct proof; `statement_bytes` counts the 3K compressed row digests plus header. These are actual serialized lengths and exclude SRS. Decoded payloads are verified separately. The 32-byte SHA-256 root binds those digests, but native verification still receives all of them. A future outer SNARK would need to verify the root and digest-dependent KZG operations inside its circuit. `direct_online_prove_seconds` includes row interpolation, all 3K commitments, and direct-proof creation; it excludes matrix generation and SRS setup.

The separate wrapper probe in `cmd/lamp_kzg_wrapper_probe` measures an isolated BN254 KZG opening check and small BN254 G1 MSMs inside BN254 Groth16 circuits. The direct variant uses MSMs but no KZG opening. Neither measurement is a full row-KZG verifier. Results and the cost implication are in `docs/comparison/ROW_KZG_FULL_FIELD_PILOT_KO.md`.
