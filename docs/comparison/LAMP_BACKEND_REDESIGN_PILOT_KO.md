# Pedersen·Groth16·CP-link 제거 연구 파일럿

**연구 전용:** `research/sparse-column-openings` 브랜치의 [`cmd/lamp_backend_probe`](../../cmd/lamp_backend_probe/main.go)에서 두 별도 경로를 구현했다. 공식 LAMP 구현과 논문용 비교 표는 바꾸지 않았다. 두 경로 모두 현재 영지식이 아니며 외부 SNARK 집계 비용을 포함하지 않는다. 아래 수치는 같은 보안 수준의 원래 LAMP 또는 zkMatrix와 성능 우열을 주장하지 않는다.

## 왜 이 두 경로인가

공식 LAMP의 `K=4096,N=8192,L=309` 로컬 한 번 실행에서 행렬 커밋먼트는 인코딩 제외 77.56초, Groth16은 60.49초, CP/QA-link 증명은 1.81초였다. 크기는 Merkle 114,816 B / 전체 115,236 B였다. 검증 0.17초 중 CP/QA-link가 약 0.16초, Merkle 검사는 약 0.003초다. [기준 원자료](../../benchmark/comparison/large_k12_m1pro_20260930_pilot/lamp_square/lamp/lamp_benchmark_results.csv). Merkle만 KZG로 교체하면 커밋·Groth16·link 비용을 해소하지 못한다.

### 1. RS + 원시 열 해시 + 직접 검증

원래 LAMP처럼 A/B/C 각 행을 가로 방향 RS로 인코딩한다 (`N=2K`). [`HashABCOracle`](../../crypto/hashoracle.go)는 부호화된 ABC 열의 **원시 필드 값**을 한 SHA-256 Merkle 트리에 고정한다. 커밋 이후 root에서 `r,b`를 얻어 `x=rᵀA`, `yz=xᵀB`, `btest=bᵀB`를 계산하고, 세 벡터를 transcript에 넣은 뒤 가로 열 인덱스를 고른다. 검증자는 해당 열의 인증된 전체 값을 받아 `Enc(x)[j]=rᵀEnc(A)[:,j]`, `Enc(yz)[j]=xᵀEnc(B)[:,j]=rᵀEnc(C)[:,j]`, `Enc(btest)[j]=bᵀEnc(B)[:,j]`를 직접 검사한다. Merkle multiproof와 독립 B 접힘을 포함한다. 이는 Shockwave 논문의 RS 기반 Ligero-PC testing과 가까운 구조지만 **Shockwave 전체 SNARK 구현은 아니다**. [원 논문 §4.1](https://eprint.iacr.org/2021/1043.pdf)

이 경로는 Pedersen·Groth16·CP-link의 증명 작업을 하지 않는다. 대신 인증된 열 값이 공개되어 proof가 커진다. 향후 바깥 SNARK로 검증을 감싸려면 이 원시 값과 SHA-256 검사를 그 회로의 비공개 witness·제약에 넣어야 한다. 따라서 현재 온라인 시간에 집계 비용을 더해야만 최종 성능을 판단할 수 있다.

### 2. 행별 KZG 커밋 + 접힘 평가 증명

A/B/C의 각 원래 행을 차수 `<K` 다항식으로 보간하고 KZG 커밋한다. 커밋먼트 목록을 고정한 후 `r,b`를 뽑는다. 공개 벡터 `x=rᵀA`, `yz=xᵀB`, `btest=bᵀB`를 고정한 후 평가점 `z`를 뽑는다. 검증자는 행 커밋먼트의 선형 결합으로 `rᵀA`, `xᵀB`, `rᵀC`, `bᵀB`에 대응하는 네 커밋먼트를 만들고, 한 점의 batched KZG opening을 검증한다. 각 평가값은 보내진 `x,yz,btest`의 보간 다항식 평가와 일치해야 한다. Pedersen·Merkle·Groth16·CP-link가 없다. [KZG 원 논문](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)

**이 경로는 LAMP의 RS 표본 검사를 유지한 백엔드 교체가 아니다.** KZG의 다항식 결합/평가 증명으로 대체한 `Freivalds형 접힘 + KZG`라는 별도 프로토콜이다. 행 커밋먼트 `3K`개가 공개 statement에 들어가고, 행 커밋 생성은 여전히 대량의 곡선 연산이다. benchmark용 SRS는 각 프로세스에서 임의 trapdoor로 로컬 생성한다. 실제 보안 배포에는 trapdoor가 폐기된 MPC SRS가 필요하다. 이 코드로 보안 정리를 주장하지 않는다.

## 한 번씩 실행한 비교

Apple M1 Pro, macOS arm64, Go 1.26.2, 기본 최적화 `go build`, 결정적 full-field 입력 seed 7, `N=2K`, 직접 검증 질의 309개(복원추출). 각 K에서 **동일한 A/B/C**를 두 경로에 입력하고 정직한 증명·검증을 확인했다. 온라인 시간은 행렬 인코딩/보간, 행렬 커밋, 접힘과 opening까지 포함한다. 입력 생성, 실제 `C=AB`, KZG SRS 생성은 제외한다. setup과 외부 SNARK 시간, 네트워크 시간은 제외한다. 단일 실행이며 시스템 부하를 통제하지 않았다.

| K | 경로 | 온라인 증명 | 행렬 커밋 | 검증 | proof payload | 공개 statement |
|---:|---|---:|---:|---:|---:|---:|
| 128 | 직접 해시 | 0.024 s | 0.003 s | 0.006 s | 2.29 MB* | 32 B |
| 128 | KZG 접힘 | 0.141 s | 0.116 s | 0.004 s | 12.5 KB | 12.3 KB |
| 256 | 직접 해시 | 0.082 s | 0.012 s | 0.011 s | 5.74 MB* | 32 B |
| 256 | KZG 접힘 | 0.411 s | 0.348 s | 0.004 s | 24.7 KB | 24.6 KB |
| 512 | 직접 해시 | 0.329 s | 0.050 s | 0.026 s | 13.49 MB* | 32 B |
| 512 | KZG 접힘 | 1.452 s | 1.235 s | 0.006 s | 49.3 KB | 49.2 KB |
| 1024 | 직접 해시 | 1.246 s | 0.194 s | 0.055 s | 28.34 MB* | 32 B |
| 1024 | KZG 접힘 | 4.711 s | 3.948 s | 0.009 s | 98.5 KB | 98.3 KB |
| 2048 | 직접 해시 | 4.546 s | 0.758 s | 0.112 s | 58.63 MB* | 32 B |
| 2048 | KZG 접힘 | 18.374 s | 15.369 s | 0.014 s | 196.8 KB | 196.6 KB |
| 4096 | 직접 해시 | 32.247 s | 4.123 s | 0.247 s | 119.59 MB* | 32 B |
| 4096 | KZG 접힘 | 67.733 s | 52.912 s | 0.025 s | 393.4 KB | 393.2 KB |

`*` 직접 해시 payload는 원시 열·fold 벡터·salt·Merkle multiproof의 **크기 추정**이며 별도 바이너리 codec 실측이 아니다. KZG batch opening은 실제 gnark-crypto 직렬화 길이, fold 벡터는 정규 필드 원소 32 B씩으로 계산했다. KZG의 `3K`개 행 커밋먼트는 proof payload가 아니라 statement에 넣었다. fresh matrix를 전달해야 한다면 proof와 statement를 **함께** 세야 한다. SRS 크기는 제외했다. 정확한 수치와 phase 구분은 [JSONL 원자료](../../benchmark/comparison/backend_probe_20261001/results.jsonl)에서 확인한다.

## 판정과 다음 과제

- **증명 시간만 우선하면** 이 파일럿의 직접 해시 경로가 빠르다. `K=4096`에서 KZG는 행 커밋에 52.91초를 사용했다. 현재 원래 LAMP의 162.30초와 두 경로를 나란히 놓아도, 원래 LAMP만 영지식이며 별도의 link/집계가 포함되므로 동등한 보안 목표의 비교가 아니다.
- **증명 크기와 검증 시간도 중요하면** KZG 경로가 직접 해시보다 유리하지만, K=4096에서 KZG proof+statement는 약 786.6 KB로 공식 LAMP의 압축 payload 95.4 KB보다 크다. 단순한 “Merkle→KZG”가 최종 전송량을 줄인다고 단정할 수 없다.
- 직접 해시 경로의 표본 수 309는 기존 LAMP의 선택을 사용했으나, Pedersen·Groth16·QA-link를 제거한 새 transcript와 공개 opening의 **전체 soundness/knowledge soundness를 별도 분석**해야 한다. KZG 경로 역시 별도 프로토콜 분석, 안전한 SRS, statement/증명 직렬화 및 악의적 prover 검증이 필요하다.
- 외부 Groth16류 집계가 최종 목표라면 직접 해시 경로의 약 120 MB 공개 열과 SHA-256 검증, KZG 경로의 pairing 검증을 각각 외부 회로에서 실제로 측정해야 한다. 현재 표에는 아직 구현·측정하지 않은 외부 회로 비용이 없다.
