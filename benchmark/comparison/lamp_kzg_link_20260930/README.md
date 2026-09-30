# Original LAMP circuit with in-Groth16 KZG links: research pilot

This experiment is confined to `prototype/fast-pcs`. It must not be merged into the main LAMP implementation or used in the Shepherd comparison. The default LAMP command is unchanged; the research variant requires `--kzg-link-probe`.

Run from the repository root:

```sh
go run ./cmd/lamp --kzg-link-probe -K 2 -rho 1/2 -L 1
LAMP_OUTPUT_DIR=/tmp/lamp-kzg-link-baseline go run ./cmd/lamp -K 2 -rho 1/2 -L 1
```

`k4_l1_stdout.log` is the full actual output of the first command. Its final JSON line is extracted to `k4_l1.json`. `baseline_k4_l1.csv` is the original LAMP command's CSV. Both runs used Apple M1 Pro, macOS arm64, Go 1.26.2, K=4, N=8 and L=1. They use different matrix values but the same circuit shape. The SRS and its trapdoor are generated afresh for the local research run; use of KZG in a real protocol would require a trusted SRS.

The probe embeds the original `circuit.LAMPCircuit` without changing its ECC/sample relations. KZG commits the encoded ABC columns and XYZ triples; the Groth16 circuit recomputes the sampled KZG commitments from its witness. The verifier reconstructs public inputs from the roots, challenges, indices and Merkle-authenticated sampled digests. The run also changes one ABC digest and checks that Groth16 proof generation rejects the inconsistent witness.

These KZG column commitments have no blinding and are not claimed to preserve the hiding property of the original Pedersen commitments. This is a correctness and cost pilot, not a privacy-preserving replacement protocol.

The measured KZG-link circuit has 686,813 constraints, with Groth16 setup 62.396 s, witness plus proving 3.250 s, and outer plus native verification 0.0029 s. The original LAMP circuit has 1,822 constraints and circuit proving rounds to 0.02 s in its CSV. These are single-run, tiny-parameter measurements; do not extrapolate them to paper sizes. The separate sampled digest and Merkle bytes are not included in `groth16_proof_bytes`.
