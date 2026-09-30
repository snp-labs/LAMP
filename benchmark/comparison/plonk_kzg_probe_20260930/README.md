# PLONK/KZG component probe raw logs

Date: 2026-09-30 Asia/Seoul. Host: Apple M1 Pro, macOS arm64, 10 logical CPUs, 32 GiB RAM, Go 1.26.2. Source base before this change: `c150eedf00cf8a20c407ecd7aaa0152b7038e576`. Probe source: `cmd/lamp/plonk_probe.go`; original `circuit/LAMPCircuit` definition. Binary SHA-256: `6bb6a034a5463d112474965a299b1ac165c269a58381361e6f524272178fb7fb`. Built with `go build -o /tmp/lamp-plonk-exact ./cmd/lamp`; standard Go release optimization (no `-gcflags='all=-N -l'`). Same binary was used for the PLONK logs here. It is a component diagnostic only: no external QA-link or Merkle opening is verified.

Commands:

```sh
./lamp-plonk-exact -plonk-probe -K 4 -L 5 -rho 1/4
./lamp-plonk-exact -plonk-probe -K 7 -L 309 -rho 1/2
./lamp-plonk-exact -plonk-probe -K 8 -L 309 -rho 1/2
./lamp-plonk-exact -K 7 -L 309 -rho 1/2
./lamp-plonk-exact -K 8 -L 309 -rho 1/2
```

The `k4_l5_*.log` files contain 20 independently generated random honest instances. Runs 15 and 18 failed at `plonk.Verify` after `plonk.Prove` returned; 18/20 verified. The `k7_l309_*.log` files contain three verified runs; `k8_l309_1.log` contains one verified run. Groth16 logs and CSVs are complete LAMP protocol runs for those sizes, including QA-link and Merkle proof. Some runs overlapped on this shared desktop; timings are exploratory. The probe uses gnark's test-only `unsafekzg.NewSRS`, so its setup is not a production ceremony.

The data and its security/accounting limits are analyzed in [`docs/comparison/GROTH16_FREE_BACKENDS_KO.md`](../../../docs/comparison/GROTH16_FREE_BACKENDS_KO.md).
