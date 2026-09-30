# Groth16 없는 LAMP 비교와 대체 백엔드 조사 (2026-09-30)

## 결론과 비교 범위

현재 **완전한 LAMP 증명을 Groth16 없이 생성·검증하는 구현은 없다.** 따라서 기존 LAMP 측정값에서 Groth16 시간만 빼서 zkMatrix와 비교할 수 없다. 그 숫자는 회로가 맡았던 관계의 증명 비용을 누락한다. Groth16이 없는 완전한 committed-matrix 증명으로 검증된 것은 [zkMatrix 독립 구현](ZKMATRIX_FIDELITY_CHECKLIST.md)이며, LAMP와의 같은 매개변수 전체 프로토콜 비교는 [대형 행렬](LARGE_MATRIX_PILOT_KO.md)과 [배치](BATCH_K10_PILOT_KO.md)에 있다.

이번 조사는 기존 LAMP 회로를 **수정하지 않고** gnark PLONK/KZG에 넣어 보는 구성요소 실험을 추가했다. 정직한 입력에서도 간헐적으로 검증이 실패했고 외부 Pedersen/Merkle commitment와 회로 witness를 잇는 QA-link가 없다. 성공한 PLONK 실행은 기술적 가능성을 보이는 진단값일 뿐, LAMP 대체 프로토콜이나 zkMatrix와 비교 가능한 proof가 아니다.

이미 완료된 같은 호스트의 **전체 프로토콜** 측정에서는 n=128에서 LAMP 2.066초, IPA 기반 zkMatrix 1.347초, n=256에서 LAMP 4.136초, zkMatrix 4.621초였다(각 10회 평균; [원자료·조건](LOCAL_RESULTS.md)). 새 PLONK/KZG의 성공 사례는 n=128에서 회로 proof만 5.95–11.61초(3회), n=256에서 13.28초(1회)였고, 불완전한 proof이므로 이 숫자로 대체 후의 승패를 판정하지 않는다. n=2048의 기존 전체 프로토콜 파일럿은 LAMP 60.666초, zkMatrix 261.695초였지만 그것 역시 Groth16을 제거한 LAMP 수치는 아니다.

## 왜 단순 교체가 불가능한가

LAMP 회로의 세 번의 `frontend.Committer.Commit`은 sampled A/B/C 열, sampled 접힘 값, RS 메시지와 codeword를 묶는다. 현재 증명기는 gnark Groth16의 내부 BSB22 commitment와 blinding을 추출하고, `CK2`를 사용하는 QA-link로 회로 witness를 외부 Pedersen 열 commitment에 연결한다 (`protocol/prover.go`, `crypto/cpLink.go`, vendored `lib/gnark/backend/groth16/bn254/prove.go`). PLONK의 내부 BSB22 commitment는 KZG polynomial digest이고 commitment key와 masking 방법이 다르다 (`lib/gnark/backend/plonk/bn254/prove.go`). 기존 QA-link를 그대로 호출할 수 없다. Merkle opening 검증, challenge 순서, ZK masking, proof codec도 새 backend와 함께 검증해야 한다.

| 후보 | 현재 실험 가능성 | 같은 LAMP 명제를 완성하려면 |
|---|---|---|
| KZG + PLONK | gnark SCS와 PLONK으로 원래 회로를 컴파일·증명·검증하는 진단 코드를 작성했다. 작은 사례에서 실패가 재현된다. | PLONK/KZG 내부 witness commitment를 외부 Pedersen commitment에 안전하게 연결하는 새 commit-and-prove 구성, 결함 원인 수정, soundness/ZK 분석. KZG 자체는 SNARK가 아니다. |
| IPA 기반 SNARK | zkMatrix는 IPA 기반의 **행렬곱 전용** 증명으로 실제 전체 비교를 완료했다. | LAMP의 hash, lookup, RS, sampled fold 전체를 위한 IPA 기반 일반 회로 SNARK와 Pedersen 연결 증명 또는 전용 프로토콜이 필요하다. 투명한 setup 가능성과 proof/verifier 비용을 함께 재야 한다. |
| Sumcheck 기반 | 다항식 관계를 새로 표현하면 RS·fold 검사를 batch하기에 유망하다. | multilinear witness commitment, lookup/hash 관계, Fiat–Shamir, ZK masking, 공개 commitment 연결을 모두 설계해야 한다. Sumcheck 단독으로는 숨겨진 witness를 묶지 않는다. |
| GKR 기반 | 층 구조가 규칙적인 연산에서는 후보가 된다. | LAMP 회로를 layered arithmetic circuit으로 다시 만들고 입력 commitment와 GKR 출력을 연결해야 한다. 일반 gnark GKR API가 현재 LAMP Groth16 proof의 drop-in backend인 것은 아니다. |

LAMP의 실제 비용 구조상 SNARK만 빨라져도 전체가 같은 비율로 빨라지지 않는다. 예를 들어 기존 n=2048, q=1 실행에서 online 60.67초 중 solver 10.76초와 Groth16 prover 19.45초, 행렬 인코딩·commitment 23.96초였다. n=4096에서는 online 162.30초 중 행렬 commitment 89.11초, solver 18.63초, Groth16 prover 41.86초였다. 이 수치는 [원자료와 회계 정의](LARGE_MATRIX_PILOT_KO.md)를 따른다. 새 backend가 회로·link 비용을 0으로 만든다는 추정은 성립하지 않는다.

## 실제 구성요소 측정

Apple M1 Pro, macOS arm64, 10 logical CPUs, Go 1.26.2, BN254. `K=128`은 행렬 한 변, `N=256`, `rho=1/2`, `L=309`는 공식 sampler의 복원추출 질의 수다. `go build` 기본 최적화 빌드. PLONK은 `scs.NewBuilder`, `plonk.Setup/Prove/Verify`, gnark의 **시험용** `unsafekzg.NewSRS`를 사용했다. 원래 `circuit.LAMPCircuit` 정의를 변경하지 않았다. 원자료와 명령은 [`benchmark/comparison/plonk_kzg_probe_20260930`](../../benchmark/comparison/plonk_kzg_probe_20260930)에 있다.

| 실행 | 회로 제약 수 | proof 생성 | 검증 | proof bytes | 범위 |
|---|---:|---:|---:|---:|---|
| 기존 LAMP Groth16, K=128 | R1CS 167,065 | 회로 1.68초; 전체 proof 단계 2.02초 | 전체 0.17초 | 전체 44,324 | QA-link·Merkle 포함, 검증 성공 |
| PLONK/KZG, K=128, 실행 1 | SCS 456,614 | 9.77초 | 1.94ms | 776 | 회로 proof만, QA-link·Merkle 제외, 검증 성공 |
| PLONK/KZG, K=128, 실행 2 | SCS 456,614 | 5.95초 | 2.04ms | 776 | 회로 proof만, QA-link·Merkle 제외, 검증 성공 |
| PLONK/KZG, K=128, 실행 3 | SCS 456,614 | 11.61초 | 2.29ms | 776 | 회로 proof만, QA-link·Merkle 제외, 검증 성공 |
| 기존 LAMP Groth16, K=256 | R1CS 329,378 | 회로 3.58초; 전체 proof 단계 4.36초 | 전체 0.17초 | 전체 52,132 | QA-link·Merkle 포함, 검증 성공 |
| PLONK/KZG, K=256, 실행 1 | SCS 904,230 | 13.28초 | 1.77ms | 776 | 회로 proof만, QA-link·Merkle 제외, 검증 성공 |

서로 다른 constraint 시스템이고 PLONK 수치에는 외부 commitment를 연결하는 proof가 빠져 있다. 실행이 공유 데스크톱에서 겹친 구간도 있으므로 시간의 비율은 성능 결론으로 사용하지 않는다. K=128 Groth16 전체 proof 크기 44,324 B 중 43,904 B는 Merkle proof다. PLONK 776 B와 이 전체 크기를 직접 비교하면 필수 구성요소를 누락한다. K=128 PLONK KZG SRS 생성 약 7.4–11.8초, PLONK setup 약 1.4–3.3초는 온라인 proving 값에 포함되지 않는다. K=256 실행에서는 SRS 생성 24.13초, setup 2.55초였다.

**재현된 정확성 문제:** 동일한 원래 회로에서 `K=16, N=64, L=5, rho=1/4`의 정직한 행렬 20개를 각각 새로 생성하자 PLONK `Prove`는 20회 모두 반환했지만 `Verify`가 2회 `algebraic relation does not hold`로 실패했다. 로그는 `k4_l5_15.log`, `k4_l5_18.log`다. 중복 query가 없는 실패도 관측됐다. 원인 분석과 수정 전에는 PLONK 측정을 논문 비교 표에 넣지 않는다. 이 실패를 회로의 잘못, gnark 버그 또는 프로토콜 결함 중 하나로 단정하지 않는다.

## Groth16 없는 직접 검증의 의미

검증자에게 A/B/C 및 중간값을 공개해 Freivalds 또는 직접 행렬곱을 검사하면 Groth16 없이 빠른 기준값을 얻을 수 있지만 공개 정보와 검증 비용이 달라진다. sampled encoded columns를 공개하는 방식은 LAMP의 행렬 비공개 보장을 유지하지 않는다. 따라서 그런 실행은 **public-input reference**로만 보고, committed-matrix ZK protocol의 같은 보안 목표를 만족하는 zkMatrix와 한 열에 놓지 않는다. Groth16 없는 실제 전체 protocol 비교를 원하면 먼저 새 backend의 cross-commitment link와 ZK 증명을 완성해야 한다.

## 우선순위

1. PLONK의 간헐적 verifier 실패를 결정적 seed로 재현하고 회로/solver/prover/verifier 중 원인을 찾는다.
2. PLONK KZG 내부 commitment와 기존 외부 Pedersen commitment의 메시지 동일성을 증명하는 별도 link를 설계·검증한다. 이 단계가 끝나기 전에는 성능 우위를 주장하지 않는다.
3. 같은 매개변수의 q=1 및 q>1에서 setup, 입력 commitment, link, proof, verifier, memory, proof 크기를 모두 재고 zkMatrix와 비교한다.
4. IPA/sumcheck/GKR은 별도 protocol 설계가 필요한 연구선으로 두되, 먼저 matrix commitment가 지배적인 n=2048/4096과 배치 q=4/10에서 비용 모델을 검증한다.

### 1차 자료

- [gnark 공식 저장소와 PLONK backend](https://github.com/Consensys/gnark/tree/master/backend/plonk)
- [Spartan: sumcheck를 쓰는 범용 zkSNARK](https://www.microsoft.com/en-us/research/publication/spartan-efficient-and-general-purpose-zksnarks-without-trusted-setup/)
- [Libra: zero-knowledge GKR 구현·측정](https://eprint.iacr.org/2019/317)
- [LegoSNARK: commitment를 가진 증명 구성요소의 연결](https://eprint.iacr.org/2019/142)
- [Bulletproofs: inner-product argument 기반 증명](https://eprint.iacr.org/2017/1066)
