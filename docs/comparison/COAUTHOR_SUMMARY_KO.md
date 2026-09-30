# LAMP–zkMatrix 비교와 zkMaP 재현 분석: 공저자 공유용

작성일: 2026-09-30. 이 문서는 완료된 로컬 실험과 아직 남은 shepherd 대응을 구분한다. 상세 수치·표준편차는 [LOCAL_RESULTS.md](LOCAL_RESULTS.md), 추가 대형 행렬 1회 파일럿은 [LARGE_MATRIX_PILOT_KO.md](LARGE_MATRIX_PILOT_KO.md), 원자료는 아래 원자료 링크에 있다.

## 1. 공유용 요약

LAMP의 공식 코드에 비교 측정을 위한 선택적 계측을 추가하고, zkMatrix 논문을 바탕으로 독립적인 Go 구현을 작성했다. 현재 완료한 실험은 같은 M1 Pro 데스크톱에서 수행한 BN254 비교다. 최초 반복 실험에서는 단일 정사각형 행렬 n=128, 256, 512, 1024와 독립 행렬 곱 batching n=128, q=1..10을 각 조건 10회 측정했다. 추가 LAMP code-rate 실험까지 총 300개의 증명을 생성했다. 이어서 n=2048 단일·q=2와 n=4096 단일 행렬을 각 방식 1회씩 별도 파일럿으로 측정했다. 기록된 증명은 검증에 성공했으며 직렬화 후 다시 decode한 증명도 검증했다. 이 기능 검증은 독립 구현에 대한 형식적 보안 증명을 의미하지 않는다.

결과는 일률적인 우열이 아니다. 단일 행렬의 proving에서는 n=128은 zkMatrix가 빠르고, n=256부터는 LAMP의 평균 시간이 더 작았다. 특히 n=512에서 LAMP는 약 1.87배, n=1024에서 약 3.01배 빠르게 증명했다. 반면 모든 측정 크기에서 zkMatrix의 verifier가 빠르고 proof payload가 작았다. n=1024에서 LAMP는 proving 22.10초, verification 171.59ms, proof 약 60.74kB였고, zkMatrix는 66.60초, 11.30ms, 5.44kB였다. 따라서 큰 단일 행렬의 prover 비용에서는 LAMP의 장점이 확인됐지만, verifier 비용과 통신량에서는 zkMatrix가 유리했다.

n=128 독립 행렬 곱을 여러 개 묶는 batching에서는 측정한 q=1..10 전체에서 zkMatrix의 평균 proving·verification·proof 크기가 더 작았다. q=10의 전체 batch proving은 LAMP 19.24초, zkMatrix 1.72초였고 약 11.16배 차이가 났다. LAMP의 verification 시간과 proof 크기는 q에 따라 거의 일정한 반면, zkMatrix의 두 비용은 q에 따라 증가했다. 다만 q≤10에서는 zkMatrix가 여전히 더 작았다. 이 결과만으로 큰 n이나 더 큰 q에서의 crossover를 예측하지 않는다. 이 workload는 독립 claim batching이며, LAMP의 연결된 계산 그래프·GPT-2 전체 인증과 동일한 기능을 비교한 결과가 아니다.

zkMaP는 공개 논문의 특정 수식에 직접적인 반례가 있고, witness 구성과 verifier 식에도 재현을 막는 불일치가 있다. 두 명시적 보간 가정으로 잠정 연산 구현을 작성해 80회 측정했지만, 정직한 C=AB를 넣어도 모두 나머지가 0이 아니어서 유효한 witness가 생기지 않았다. 잠정 연산 시간은 유효한 zkMaP proof timing으로 사용할 수 없다. 현재 실측 비교는 LAMP–zkMatrix로 제시하고, zkMaP는 수학적 반례와 재현 분석으로 별도 설명하는 것이 타당하다. Shepherd가 두 프로토콜을 명시했으므로 이 대체안은 동의를 받아야 한다. 아직 동의를 받은 상태가 아니다.

## 2. 논문과 구현의 출처

- **zkMatrix**: Mingshu Cong, Tsz Hon Yuen, Siu-Ming Yiu, *zkMatrix: Batched Short Proof for Committed Matrix Multiplication*, ACM AsiaCCS 2024, pp.289–305. [저자 기관 출판 기록](https://research.monash.edu/en/publications/zkmatrix-batched-short-proof-for-committed-matrix-multiplication/), [DOI](https://doi.org/10.1145/3634737.3645003), [논문 PDF](https://eprint.iacr.org/2024/161.pdf).
- **zkMaP**: Biniyam Deressa, M. Anwar Hasan, *zkMaP: Zero-Knowledge Succinct Non-Interactive Matrix Multiplication Proofs*, IACR Communications in Cryptology, Vol.2 No.3, 2025. [공식 페이지](https://cic.iacr.org/p/2/3/23), DOI 10.62056/angy11fgx.
- LAMP 공식 기준 revision: `e2d1cae15988779b0c65c7e492eb1dc4df2dd032`. zkMatrix는 저자 코드가 아닌 논문 기반 독립 BN254 구현이다. 최적화된 four-IPA 구성, accelerated/direct verifier, Algorithm 6 batching, proof/statement codec과 변조 테스트를 포함한다.
- zkMatrix 구현·300회 결과 commit: `23dac21`. Claude Haiku 4.5의 zkMaP 잠정 연산 구현과 검토·수정, 80회 결과 commit: `62a5307`.
- 저장소: snp-labs/LAMP, 브랜치 `comparison/zkmatrix-benchmarks`, [draft PR #1](https://github.com/snp-labs/LAMP/pull/1). master merge는 아직 하지 않았다.

## 3. 측정 조건과 해석 범위

호스트는 Apple M1 Pro, macOS, 10 CPUs, 32GiB, Go 1.26.2, GOMAXPROCS=10이다. 같은 데스크톱의 다른 프로세스 부하는 통제하지 않았다. 두 구현 모두 BN254의 전체 scalar field에서 dense 행렬을 생성하지만 byte 단위로 동일한 A/B를 공유하지는 않는다. LAMP의 기본 비교 조건은 rho=1/2, 복원추출 query 309개다. 공식 sampler·circuit·challenge 순서를 유지했다.

온라인 proving 시간은 입력 행렬 commitment부터 모든 online proof 생성 작업을 포함한다. 입력 생성, C=AB 계산, circuit compilation 및 setup은 제외한다. 검증 시간에서는 payload 직렬화·decode와 추가 재검증을 제외한다. 표의 proof bytes는 compressed proof payload이며 public statement와 key는 별도다. 단위 kB는 1000 bytes로 환산한다.

LAMP/zkMatrix 300회 실험의 소스 SHA256은 `c34bd62bee6f07a879d7e4b48d8b9c17e0ca48c34e796425e2bec93ed74e6f93`다. 이후 CLI의 timer 밖 C 계산을 병렬 helper로 바꾼 수정과 zkMaP 코드는 별도 소스이며, 과거 측정값의 소스 표기를 바꾸지 않았다. 소스 archive·binary hash·명령·원자료 연결을 보존했다.

BN254로 맞춘 구현 비교는 zkMatrix 논문의 BLS12-381 설정과 같은 보안 수준이라고 주장하는 실험이 아니다. 독립 구현의 상수 비용·병렬화·전처리도 결과에 영향을 준다. zkMatrix 논문에 제시된 primitive timing 기반 추정과 여기의 end-to-end 로컬 실측을 혼합하지 않는다. LAMP circuit constraint 수는 제공된 논문 표와 일치하지만, 이것만으로 논문 전체 실험을 재현했다고 할 수 없다.

## 4. 단일 정사각형 행렬 결과

각 셀은 10회 평균이다. 표준편차는 [상세 결과](LOCAL_RESULTS.md)에 있다.

| n | LAMP prove(s) | zkMatrix prove(s) | LAMP verify(ms) | zkMatrix verify(ms) | LAMP proof(bytes) | zkMatrix proof(bytes) |
|---:|---:|---:|---:|---:|---:|---:|
| 128 | 2.0662 | 1.3470 | 167.239 | 9.072 | 24,288.0 | 4,096 |
| 256 | 4.1358 | 4.6207 | 167.174 | 9.628 | 32,339.2 | 4,544 |
| 512 | 9.0708 | 16.9261 | 169.738 | 10.436 | 44,633.6 | 4,992 |
| 1024 | 22.0986 | 66.5999 | 171.588 | 11.296 | 60,742.4 | 5,440 |

LAMP의 proving speedup(zkMatrix/LAMP)은 n=256 약 1.12배, 512 약 1.87배, 1024 약 3.01배다. n=128은 zkMatrix가 약 1.53배 빠르다. n=256의 작은 평균 차이는 큰 n의 차이보다 신중히 해석해야 하며 통계적 유의성을 주장하지 않는다. n=1024에서 zkMatrix verification은 약 15.19배 빠르고 proof payload는 약 11.17배 작다. Statement bytes는 LAMP 64, zkMatrix 112이며 위 payload에서 제외했다.

## 5. 독립 claim batching

n=128, 조건별 10회. 아래 시간은 claim당 시간이 아니라 **전체 batch의 평균 시간**이다. q=1도 batch 경로이며 단일 square 경로와 구분한다.

| q | LAMP prove(s) | zkMatrix prove(s) | LAMP verify(ms) | zkMatrix verify(ms) | LAMP proof(bytes) | zkMatrix proof(bytes) |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2.110 | 1.127 | 168.530 | 8.716 | 24,377.6 | 4,100 |
| 2 | 3.818 | 1.194 | 168.814 | 10.794 | 24,275.2 | 4,936 |
| 3 | 5.256 | 1.394 | 174.367 | 12.564 | 24,384.0 | 5,772 |
| 4 | 7.423 | 1.473 | 168.245 | 14.359 | 24,236.8 | 6,608 |
| 5 | 8.734 | 1.671 | 167.864 | 16.263 | 24,396.8 | 7,444 |
| 6 | 10.540 | 1.528 | 169.420 | 17.702 | 24,217.6 | 8,280 |
| 7 | 14.239 | 1.679 | 169.545 | 19.509 | 24,281.6 | 9,116 |
| 8 | 15.567 | 1.720 | 177.951 | 24.139 | 24,384.0 | 9,952 |
| 9 | 16.814 | 1.802 | 168.656 | 23.103 | 24,428.8 | 10,788 |
| 10 | 19.235 | 1.724 | 170.640 | 25.127 | 24,320.0 | 11,624 |

q=10에서는 zkMatrix가 proving에서 약 11.16배, verification에서 약 6.79배 빠르고 proof payload는 약 2.09배 작다. LAMP의 statement는 64bytes로 일정하고, zkMatrix는 112q bytes이므로 q=10에서 1120bytes다. LAMP proof 크기가 거의 일정하다는 특성은 관측되지만, 이 범위에서 LAMP 통신량이 더 적다고 주장할 수 없다. 측정하지 않은 큰 q로 외삽하지 않는다.

## 6. LAMP code rate 설정

n=128, 조건별 10회. rho는 LAMP 고유의 설정이며 zkMatrix에 같은 설정이 있다는 뜻은 아니다.

| rho | queries | prove(s) | verify(ms) | proof(bytes) |
|---|---:|---:|---:|---:|
| 1/2 | 309 | 2.066 | 167.239 | 24,288.0 |
| 1/4 | 189 | 1.606 | 105.248 | 25,120.0 |
| 1/8 | 155 | 1.723 | 86.734 | 30,713.6 |

측정한 중에는 rho=1/4의 평균 proving 시간이 가장 짧고, rho=1/8의 평균 verification 시간이 가장 짧다. rho=1/8에서는 proof가 더 크므로 모든 비용이 함께 개선되지는 않는다. 이 두 설정의 n=128 proving 시간도 zkMatrix의 단일 square 평균 1.347초보다는 크다.

n=2048에서는 같은 논문 sampling 목표로 `rho=1/2,1/4,1/8`을 각각 1회씩 추가 측정했다. Commitment 포함 online proving은 차례로 **60.67, 69.37, 118.56초**였으므로, 큰 행렬의 1회 파일럿에서는 `rho=1/2`가 가장 빨랐다. 하지만 setup을 매번 수행하면 `rho=1/4`의 더 작은 회로가 전체 실행 시간을 낮췄다. Key 재사용 횟수와 검증·proof 크기에 따라 최적 rate가 달라진다. 논문 Appendix F Table 7과 단계별 원자료는 [ECC rate 절충 분석](CODE_RATE_TRADEOFF_KO.md)에 정리했다.

## 7. zkMaP 재현 문제

### 7.1 논문의 특정 등식에 대한 직접 반례

원문 §4.1(p.13)은 행 우선 다항식 인코딩에서 A가 m×ell, B가 ell×n, C=AB일 때 PC(x)=PA(x)PB(x) mod x^(mn)이라는 관계를 적는다. A를 원소가 모두 1인 2×3 행렬, B를 원소가 모두 1인 3×2 행렬로 두자. C는 원소가 모두 3인 2×2 행렬이어서 PC=3+3x+3x²+3x³이다. 반면 PA=PB=1+x+x²+x³+x⁴+x⁵이고, 곱의 첫 네 계수는 1,2,3,4이다. 이 등식은 BN254에서 성립하지 않는다.

이는 공개된 인코딩과 일반 등식에 대한 직접 반례다. 보간 노드나 우리 FFT 구현의 선택과 무관하다. 따라서 논문의 **해당 일반 등식이 잘못됐다**고 말할 수 있다. 다만 이 반례만으로 저자가 가진 미공개 코드나 가능한 모든 수정안을 부정하는 것은 아니다. 저자의 2026년 학위논문은 일반적인 row-major 다항식 곱이 행렬 곱을 인코딩하지 않는다고 명시한다. [학위논문과의 대조](ZKMAP_THESIS_RECHECK.md)를 참고한다.

### 7.2 witness 생성 단계

C=AB일 때 μ=yLᵀCyR=dot(ay,by)는 맞다. 하지만 Appendix E Algorithm 2(p.37)의 W(x)=(μ−Pay(x)Pby(x))/(x−y)가 다항식이 되려면 μ=Pay(y)Pby(y)여야 한다. 일반적인 벡터 보간만으로 내적이 평가값의 곱으로 바뀌지는 않는다.

예를 들어 노드 0,1에서 a=(1,2), b=(3,4)를 보간하면 Pa=1+x, Pb=3+x다. 내적은 11이지만 y=2에서 평가값의 곱은 15이므로 나머지는 −4다. 이는 일반 보간으로 필요한 등식을 도출할 수 없다는 예다. 저자가 의도한 완전한 인코딩을 확정하는 예는 아니며, 원문은 이 단계의 보간 노드와 인코딩을 충분히 지정하지 않는다.

### 7.3 검증식과 projection binding

Appendix의 pairing 우변은 Vmu−Vay−Vby에 대응하는 반면, witness 분자는 μ−Pay·Pby다. 차와 곱이 일치하지 않으므로 본문과 Appendix 식을 정합시켜야 한다. 학위논문의 추가 G2 commitment 설명은 곱의 group operation 의도를 보충하지만, 원래의 A/B/C commitments와 projection commitments를 연결하는 완전한 검증 절차는 확인하지 못했다.

별도 진단에서는 고립된 pairing 식만 검사하는 경우 공개 SRS로 만든 점이 거짓 C를 통과시키는 조건부 반례를 확인했다. **추가 binding 검증이 없는 경우의 해당 식에 대한 반례**이며, 명시되지 않은 저자의 전체 구현에 대한 공격을 확인했다는 뜻은 아니다. [수식·진단의 범위](ZKMAP_SPEC_GAPS.md)에 조건을 기록했다.

## 8. zkMaP 잠정 연산 시간 80회

Claude Haiku 4.5로 Appendix의 연산을 구현하고 검토·수정했다. 정수 노드 0..n−1과 실제 FFT domain이라는 두 가지 명시적 가정으로 n=128/256/512/1024를 각각 10회 측정했다. 정직한 C=AB, 입력 KZG commitments 세 개, challenge, projection, 보간, 다항식 곱·나눗셈, 모든 auxiliary commitments의 비용을 포함했다. 나머지가 0이 아니어도 연산 비용을 재기 위해 quotient commitment는 계산하되 유효한 witness로 취급하지 않는다. Compression, 완전한 projection binding, zero-knowledge masking은 포함하지 않았다.

| n | 정수 노드 online(s) | FFT 노드 online(s) |
|---:|---:|---:|
| 128 | 0.0470 | 0.0495 |
| 256 | 0.1623 | 0.1504 |
| 512 | 0.5624 | 0.5934 |
| 1024 | 2.0330 | 1.8862 |

**80회 모두 μ의 내적 관계는 맞았지만 나머지가 0이 아니었고, 유효한 witness와 literal pairing 수락은 각각 0회였다.** 따라서 이 표는 zkMaP의 유효한 prover가 LAMP보다 빠르다는 근거가 아니다. 실패한 명세 해석의 연산 비용이며, 유효한 proof throughput이나 proof size·보안성을 나타내지 않는다. 측정 소스와 실행 시점도 기존 LAMP/zkMatrix 실험과 달라 유효한 증명 비교 표에 합치지 않는다. [원자료, SD, 소스 해시](ZKMAP_PROVISIONAL_TIMING.md)에 상세 내용이 있다.

## 9. Shepherd 대응안과 미완료 범위

현재 근거로는 (1) LAMP–zkMatrix의 유효한 증명 비교, (2) prover·verifier·통신·batching trade-off, (3) zkMaP 공개 수식의 작은 반례와 재현 장애를 함께 제시하는 것이 적절하다. Shepherd가 두 프로토콜을 명시했으므로 zkMaP 성능 측정을 수식 분석으로 대체하는 데 대한 동의가 필요하다. 단순히 소스가 없어서 제외했다고 설명하는 것보다 반례와 재현 시도를 보여주는 편이 정확하다.

저자나 shepherd에게 문의를 보내지는 않았다. 문안은 [문의 초안](AUTHOR_CLARIFICATION_DRAFTS.md)에 있다. 저자의 수정된 명세나 코드가 제공되면 그에 따라 다시 검증해야 한다.

n=2048의 단일 행렬과 q=2 배치, n=4096 단일 행렬을 추가로 각 1회씩 측정하고 검증했다. Commitment 포함 온라인 증명은 n=2048 단일에서 LAMP 60.67초 대 zkMatrix 261.69초(4.31배), q=2에서 LAMP 115.65초 대 zkMatrix 273.67초(2.37배), n=4096 단일에서 LAMP 162.30초 대 zkMatrix 1,136.64초(7.00배)였다. 공유 M1 Pro의 **1회 파일럿**이므로 위 300회 반복 결과와 통계적으로 합치거나 논문용 우열로 제시하지 않는다. 이 크기에서 LAMP의 verifier·proof payload는 여전히 zkMatrix보다 크다. n=4096 LAMP 온라인 시간에서는 행렬 commitment 89.11초가 Groth16 prover 41.86초보다 길어, Groth16만 교체하는 최적화로 전체 병목을 해결할 수 없다. 원자료와 단계별 시간은 [대형 행렬 파일럿](LARGE_MATRIX_PILOT_KO.md)에 있다.

추가로 n=1024의 **독립 행렬곱 배치**를 q=1,2,3,4,10에서 각 방식 1회씩 측정했다. Commitment 포함 전체 배치 온라인 증명 시간은 순서대로 LAMP **25.16, 46.94, 56.92, 87.10, 248.08초**, zkMatrix **60.96, 67.41, 72.87, 72.98, 85.00초**였다. 이 호스트에서는 q≤3에서 LAMP가, q=4와 q=10에서 zkMatrix가 빨랐다. q=10은 zkMatrix가 약 2.92배 빠르다. LAMP q=10 회로는 12,837,854 constraints이고 setup만 1,502.88초였으며, zkMatrix의 setup은 17.27초였다. LAMP의 증명 payload와 검증 시간도 zkMatrix보다 컸다. 이 결과는 기능이 같은 **독립 claim 배치**에 대한 비교이며, GPT-2 계산 그래프 전체 인증의 비교는 아니다. q=5..9와 통계적 반복은 아직 없다. [n=1024 배치 파일럿](BATCH_K10_PILOT_KO.md)에 방법·원자료·한계를 정리했다.

n=8192 및 논문 §7의 공통 Linux 호스트 반복 실험, sequence-1024 GPT-2 전체 비교는 아직 수행하지 않았다. n=4096은 로컬 1회 파일럿만 있다. zkMatrix의 GPT-2 보조 CLI는 36개 matrix product claim의 baseline이며, cross-claim wiring이나 공개 입출력 binding까지 인증하는 LAMP와 동등한 전체 graph certificate는 아니다. 기존 300회 실험의 setup은 LAMP가 각 proof 프로세스에서 수행하고 zkMatrix는 10회에 걸쳐 공유한다. 기록한 RSS는 setup·입력 생성이 포함된 프로세스 전체 값이므로 prover 자체의 메모리 우열로 읽어서는 안 된다.

## 10. 원자료와 상세 문서

- [유효한 proof 300회, SD, 측정 조건과 그림](LOCAL_RESULTS.md)
- [n=2048·4096 검증된 1회 대형 행렬 파일럿](LARGE_MATRIX_PILOT_KO.md)
- [n=1024 독립 행렬곱 배치 q=1,2,3,4,10 파일럿](BATCH_K10_PILOT_KO.md)
- [ECC rate와 commitment·Groth16 절충](CODE_RATE_TRADEOFF_KO.md)
- [square manifest](../../benchmark/comparison/published_20260929/manifests/squares_k7_k10_m1pro_20260929_run1.json)
- [batch 완료 manifest](../../benchmark/comparison/published_20260929/manifests/batch_q1_q10_m1pro_20260929_resume1.json)
- [수치 summary](results_20260929/compact_summary.json)
- [zkMaP 수식과 진단 범위](ZKMAP_SPEC_GAPS.md)
- [zkMaP 학위논문 대조](ZKMAP_THESIS_RECHECK.md)
- [zkMaP 잠정 연산 80회](ZKMAP_PROVISIONAL_TIMING.md)
- [zkMatrix 구현 충실성 점검](ZKMATRIX_FIDELITY_CHECKLIST.md)
- [Linux 서버 실행 절차](SERVER_EXECUTION.md)
