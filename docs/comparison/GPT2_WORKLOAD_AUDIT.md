# GPT-2 workload in the public LAMP checkout

This is a source inspection of `cmd/lamp_gpt2/main.go`, not an executed full
GPT-2 comparison. At sequence length S=1024 the public artifact constructs 36
matrix products:

| Claim family | Count | A shape | B shape | C shape |
| --- | ---: | --- | --- | --- |
| Packed QKV projection | 1 | S x 1024 | 1024 x 4096 | S x 4096 |
| Attention scores | 16 | S x 64 | 64 x S | S x S |
| Attention values | 16 | S x S | S x 64 | S x 64 |
| Attention output | 1 | S x 1024 | 1024 x 1024 | S x 1024 |
| MLP up | 1 | S x 1024 | 1024 x 4096 | S x 4096 |
| MLP down | 1 | S x 4096 | 4096 x 1024 | S x 1024 |

The logical QKV width is 3072, padded with 1024 zero columns to width 4096 by
`generatePaddedQKVWeights`. Therefore benchmarking an unpadded 3072-column
product does not match this checkout's actual packed product.

The data flow is also significant: Q, K and V are slices of the packed output,
K is transposed, score matrices feed the value products, head outputs are
concatenated, and the attention/MLP products use earlier results. The LAMP
circuit contains equality, transpose, sum and lookup wiring checks in addition
to each matmul relation. The grouped zkMatrix path uses the official generator's
actual shared values and outputs, not 36 independent random matrices. Equal
shapes form five groups with sizes 2, 16, 16, 1 and 1.

The zkMatrix claims-only certificate proves each supplied A·B=C product, but
the public commitments do not prove the LAMP graph's cross-claim equality,
transpose, or concatenation wiring. It also does not bind the designated public
input/output. The manifest explicitly sets both
`graph_wiring_certified=false` and
`public_input_output_binding_certified=false`; do not describe this as a full
linked GPT-2 certificate or an equivalent LAMP statement.

All dimensions of the padded workload are powers of two, so a rectangular IPA
implementation can handle these sizes. Heterogeneous dimensions require separate
parameter layouts or padding, with setup and communication accounting disclosed.

This shape inspection was rechecked against official revision e2d1cae. The
current circuit also binds the designated public input and output; independent
private matrix commitments do not provide that guarantee. `--baseline-plan`
lists all 36 shape-only claims without allocating values or setting up SRS.
Execution is guarded at 32 logical CPUs and 240 GiB usable memory, representing
a nominal 256 GiB host. Full sequence-1024 runs require that common host. Plan
output and tiny tests are not full workload measurements.
