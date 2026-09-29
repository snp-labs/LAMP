# 2048·4096 정사각형 행렬 로컬 파일럿 (2026-09-30)

## 목적과 범위

Shepherd가 요구한 §7 비교에서 작은 행렬 결과만으로 LAMP의 효용을 판단하지 않도록, 기존 n≤1024 반복 측정에 n=2048 단일 행렬과 독립 행렬곱 2개 배치, n=4096 단일 행렬을 추가한다. 이 문서는 **1회씩 실행한 로컬 파일럿**이다. 동일한 고메모리 Linux 호스트에서 반복한 논문용 결과나 zkMaP의 유효 증명 비교를 대체하지 않는다.

LAMP의 공식 프로토콜 기준은 `e2d1cae15988779b0c65c7e492eb1dc4df2dd032`이다. 이 측정에 사용한 Go 소스는 비교 계측과 독립 zkMatrix 구현이 추가된 `5dec63453f98222464ba2bd365edf97a53c716ea`이다. n=4096 zkMatrix 실행 전 `0045640` 문서·원자료 commit이 추가됐지만 Go 소스와 바이너리는 바뀌지 않았고, 두 크기에서 binary SHA-256이 일치한다. zkMatrix는 논문을 바탕으로 작성한 독립 BN254 구현이며 저자 구현은 아니다. 실행 호스트는 Apple M1 Pro, 10 CPU, 32 GiB RAM, macOS, Go 1.26.2, `GOMAXPROCS=10`이다. 두 프로토콜 모두 정직한 독립 dense 행렬곱을 생성하고 실제로 증명을 생성·검증했으며, 각 직렬화 payload를 decode한 뒤 별도로 재검증했다. 입력 분포는 같지만 두 프로세스의 A/B 원소를 byte 단위로 일치시키지는 않았다.

온라인 시간은 행렬 commitment 시작부터 proof 생성 완료까지이며, 입력 생성, `C=AB`, circuit compile, setup을 제외한다. Commitment를 제외한 시간을 별도 보인다. 검증 시간은 serialize/decode와 추가 재검증을 제외한다. Proof payload 크기는 압축 직렬화된 proof만으로, public statement와 setup key는 제외한다. LAMP는 `rho=1/2`, `L=309`, 공식 복원추출 sampler이고 zkMatrix는 accelerated verifier다.

## 검증된 측정값

| workload | 방식 | online prove (s) | matrix commitment (s) | commitment 제외 online (s) | setup (s) | verify (ms) | compressed proof (B) |
|---|---|---:|---:|---:|---:|---:|---:|
| n=2048, q=1 | LAMP | 60.666 | 23.961 | 36.705 | 277.244 | 170.080 | 79,360 |
| n=2048, q=1 | zkMatrix | 261.695 | 7.678 | 254.017 | 60.617 | 12.478 | 5,888 |
| n=2048, q=2 | LAMP | 115.646 | 42.875 | 72.771 | 568.448 | 172.030 | 77,824 |
| n=2048, q=2 | zkMatrix | 273.671 | 13.827 | 259.844 | 65.945 | 14.622 | 6,984 |
| n=4096, q=1 | LAMP | 162.305 | 89.105 | 73.199 | 575.983 | 170.307 | 95,424 |
| n=4096, q=1 | zkMatrix | 1,136.639 | 34.637 | 1,102.001 | 289.983 | 23.203 | 6,336 |

q=1의 LAMP online prove는 zkMatrix보다 **4.31배 짧았다**. LAMP 안에서는 gnark constraint solver **10.76초**와 Groth16 prover **19.45초**가 합쳐 약 **30.21초**로 online의 약 절반, 행렬 인코딩·commitment가 **23.96초**로 약 40%였다. q=2는 solver **16.50초**, Groth16 prover **46.70초**, 합계 **63.20초**이고 회로는 **5,170,042 constraints**다. q=1의 **2,609,194 constraints**에 비례하여 증가했다.

더 빠른 SNARK가 LAMP를 가속할 가능성은 있지만 측정으로 확인해야 한다. 현재 `cmd/lamp`·`cmd/lamp_batch`는 Groth16 proof의 내부 witness commitments와 blindings를 추출하고, Groth16 proving key의 `CK2`로 QA-link를 만든다. 다른 backend로 `Prove` 호출만 바꾸면 외부 행렬 commitments와 회로 witness의 연결 검증이 유지되지 않는다. 호환되는 commitment 추출·link proof와 새 setup·proof codec을 먼저 구현해 검증해야 한다. 같은 온라인 흐름에서 q=1의 solver와 Groth16 prover **둘 다 시간이 0이 되는 비현실적인 상한**을 가정해도 남는 시간이 약 **30.46초**다. 따라서 backend 교체만으로 전체가 임의로 빨라지지는 않으며, 행렬 commitment와 batch 회로 구조도 별도 최적화 대상이다.

q=2 online prove는 LAMP가 zkMatrix보다 **2.37배 짧았다**. q=1→2에서 LAMP 시간은 60.67→115.65초로 거의 두 배가 됐지만 zkMatrix는 261.69→273.67초로 조금 증가했다. zkMatrix Algorithm 6의 공유 투영 비용이 이 크기에서 두드러진다는 관찰과 일치한다. 따라서 같은 n에서 q가 더 늘면 상대 우위가 바뀔 가능성이 있으며, q=2만으로 crossover를 단정할 수 없다.

n=4096에서 LAMP online prove는 zkMatrix보다 **7.00배 짧았다**. LAMP 온라인 **162.30초** 중 행렬 commitment가 **89.11초**, solver와 Groth16 prover 합계가 **60.49초**였다. Solver는 **18.63초**, Groth16 prover는 **41.86초**다. n=2048에 비해 행렬 commitment가 훨씬 빠르게 증가해, 이 크기에서는 Groth16 backend만 바꾸는 전략의 효과가 더 제한된다. Groth16 prover만 비용이 0이 되어도 동일한 나머지 단계만으로 약 **120.44초**가 걸리는 산술상 한계가 있다. Solver까지 비용이 0이 되는 비현실적인 가정에서도 약 **101.82초**가 남는다. 실제 backend 교체에는 새 비용이 생기므로 이는 성능 예측이 아니라 병목을 설명하는 상한이다. 회로는 **5,214,878 constraints**였다.

n=2048의 별도 rate 실험에서는 같은 논문 sampling 목표의 `ρ=1/4,L=189`가 online 69.37초, `ρ=1/8,L=155`가 118.56초로 이 표의 `ρ=1/2,L=309` 60.67초보다 길었다. 낮은 rate가 Groth16 시간을 줄여도 commitment 증가가 더 컸다. Setup을 매번 포함하면 `ρ=1/4`가 유리할 수 있으므로 비용 목표와 key 재사용 횟수를 분리해서 선택해야 한다. [ECC rate 분석](CODE_RATE_TRADEOFF_KO.md)에 논문 Table 7과 로컬 원자료를 함께 설명한다.

작은 행렬에서의 batch q=10 결과는 zkMatrix에 유리했으므로, n=2048 q=1만으로 큰 행렬의 모든 batch 크기에서 LAMP가 빠르다고 일반화하지 않는다. 반면 단일 행렬 결과는 기존 n=1024의 LAMP 22.10초 대 zkMatrix 66.60초(약 3.01배)에 이어 큰 n에서 차이가 커지는 방향을 보인 **예비 관찰**이다. 두 측정은 서로 다른 소스 revision의 별도 실험이므로 하나의 통계 회귀나 논문 표로 합치지 않는다.

추가 [n=1024 독립 행렬곱 배치 파일럿](BATCH_K10_PILOT_KO.md)에서는 q=1,2,3에서 LAMP가 빠르고 q=4,10에서 zkMatrix가 빨랐다. q=10의 온라인 시간은 LAMP 248.08초, zkMatrix 85.00초였다. 이는 단일 행렬의 크기와 batch 크기가 서로 다른 성능 축임을 보여주는 로컬 1회 관찰이다.

zkMatrix의 verifier와 proof payload는 n=4096에서도 작다. LAMP는 큰 행렬의 prover 시간, zkMatrix는 verifier·통신량 및 setup 시간에 장점이 있다. 측정한 zkMatrix setup SRS는 n=2048에서 8,396,804 G1 points(압축 추정 268,697,920 B), n=4096에서 33,570,820 points(1,074,266,432 B)다. LAMP와 zkMatrix의 setup 모델 및 재사용 범위가 다르므로 setup 시간을 online prove에 더해 하나의 우열 수치로 해석하지 않는다. 이 1회 실행의 전체 프로세스 경과 시간은 LAMP 약 1,012초, zkMatrix 약 1,693초였다. 행렬곱 계산과 setup, 추가 직렬화 재검증을 포함한 값이다.

## 재현성과 한계

원자료는 n=2048의 [`benchmark/comparison/large_k11_m1pro_20260930_pilot`](../../benchmark/comparison/large_k11_m1pro_20260930_pilot)와 n=4096의 [`benchmark/comparison/large_k12_m1pro_20260930_pilot`](../../benchmark/comparison/large_k12_m1pro_20260930_pilot)에 있다. 각 하위 폴더의 `metadata.json`에는 정확한 CLI, binary SHA-256, commit, runtime과 자원 상한이 있으며, `lamp_comparison.jsonl` 또는 `zk.csv`에 검증 여부와 구성 단계별 시간이 있다. `stdout.log`에는 Groth16 constraint와 solver/prover 시간, `stderr.log`에는 `/usr/bin/time -l`의 프로세스 최대 RSS가 있다. 실행 바이너리는 저장소에 포함하지 않는다. 같은 commit과 Go 버전으로 기본 `go build` 최적화 빌드를 재생성할 수 있다. 측정은 1회, warmup 없음, 공유 데스크톱의 다른 작업 부하를 통제하지 않았다.

n=2048 q=1의 최대 resident set은 LAMP **5.079 GB**, zkMatrix **3.506 GB**였고, q=2는 LAMP **12.754 GB**, zkMatrix **4.461 GB**였다. n=4096 q=1은 LAMP **6.394 GB**, zkMatrix **14.667 GB**였다. 이 수치에는 setup과 입력 생성의 peak가 포함되어 online prover만의 메모리가 아니다. 첫 LAMP q=1 metadata의 원래 child RSS poll은 `/usr/bin/time` wrapper만 읽은 계측 오류였으므로 무효로 표시했고, `stderr.log`의 운영체제 측정치를 사용한다. n=2048 q=2 LAMP 실행 중 RSS 상한을 12→16 GiB, n=4096 zkMatrix 실행 중 16→20 GiB로 조정하고 별도 자원 감시기를 사용했으며 metadata에 기록했다.

논문 §7의 n=4096·8192 및 충분한 반복은 32코어·256GB급 공통 Linux 서버에서 재실행해야 한다. 현재 접근 가능한 SSH 개발 호스트는 8 CPU·11 GiB여서 그 조건을 만족하지 않는다. zkMaP는 공개 수식의 불일치로 정직한 입력에 대한 유효 증명을 아직 만들 수 없었으며, 잠정 연산 시간은 이 표에 넣지 않았다. 상세 이유는 [zkMaP 재현 분석](ZKMAP_SPEC_GAPS.md)과 [잠정 연산 기록](ZKMAP_PROVISIONAL_TIMING.md)에 있다.
