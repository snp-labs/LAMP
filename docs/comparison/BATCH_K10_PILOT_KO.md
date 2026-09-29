# 1024×1024 독립 행렬곱 배치 로컬 파일럿 (2026-09-30)

## 측정 목적과 조건

큰 단일 행렬의 LAMP 우위가 여러 행렬곱을 묶었을 때도 유지되는지 확인했다. `q`는 서로 독립적인 `1024×1024 · 1024×1024 = 1024×1024` claim의 개수다. 각 행은 **전체 배치 1개의 증명**을 만들고 검증한 결과이며, claim당 시간으로 나누지 않았다. q=1도 단일 square CLI가 아니라 양쪽 모두 batch CLI를 사용했다. 이 실험은 연결된 GPT-2 계산 그래프의 증명이 아니다.

공식 LAMP 기준 revision은 `e2d1cae15988779b0c65c7e492eb1dc4df2dd032`이고, 비교 계측과 zkMatrix 독립 구현의 Go 소스는 `5dec63453f98222464ba2bd365edf97a53c716ea`에서 빌드한 고정 바이너리를 사용했다. zkMatrix는 저자 코드를 실행한 것이 아니라 논문 기반 독립 BN254 구현이다. LAMP는 `ρ=1/2,L=309`, 공식 복원추출 sampler와 QA-link를 사용했고 zkMatrix는 accelerated batch verifier를 사용했다. 두 방식 모두 BN254다. Apple M1 Pro, 10 CPU, 32 GiB RAM, macOS, Go 1.26.2, `GOMAXPROCS=10`에서 각 조건을 **1회**씩 순차 실행했다. 서로 다른 프로세스에서 정직한 dense A/B를 생성하므로 입력 분포·형상은 같지만 원소가 byte 단위로 같은 쌍은 아니다. 각 CLI는 생성한 proof와 압축 직렬화 후 decode한 proof를 검증했다.

`online prove`는 matrix commitment 시작부터 proof 생성 완료까지이며 C=AB, circuit compile, setup을 제외한다. zkMatrix의 CSV `totalprove_seconds`, LAMP JSONL `full_online_prove`를 사용한다. `commit`은 이 온라인 시간의 일부다. Setup은 별도 측정치이며 두 방식에서 key의 구조·재사용 범위가 다르다. Verification은 CLI의 proof verification 구간이며 별도 decode/reverification의 시간을 포함하지 않는다. `proof B`는 압축 직렬화한 proof payload만이다. LAMP의 64 B public statement, zkMatrix의 commitment·public data, setup key는 포함하지 않는다.

## 검증된 1회 결과

| q | 방식 | online prove (s) | matrix commit (s) | setup (s) | verify (ms) | proof (B) |
|---:|---|---:|---:|---:|---:|---:|
| 1 | LAMP | 25.156 | 7.627 | 151.181 | 190.484 | 59,776 |
| 1 | zkMatrix | 60.955 | 1.671 | 15.815 | 11.152 | 5,444 |
| 2 | LAMP | 46.945 | 12.672 | 285.822 | 224.596 | 61,952 |
| 2 | zkMatrix | 67.414 | 3.685 | 16.840 | 13.518 | 6,472 |
| 3 | LAMP | 56.920 | 16.243 | 401.618 | 185.929 | 61,120 |
| 3 | zkMatrix | 72.867 | 5.452 | 18.555 | 15.840 | 7,500 |
| 4 | LAMP | 87.101 | 20.208 | 570.334 | 172.366 | 61,056 |
| 4 | zkMatrix | 72.977 | 6.062 | 15.611 | 19.185 | 8,528 |
| 10 | LAMP | 248.079 | 44.872 | 1,502.883 | 231.985 | 60,544 |
| 10 | zkMatrix | 85.001 | 17.006 | 17.274 | 31.451 | 14,696 |

온라인 증명에서는 q=1,2,3에서 LAMP가 빠르고 q=4,10에서 zkMatrix가 빠르다. q=1의 LAMP 우위는 2.42배지만 q=3에는 1.28배로 좁아지며, q=4에서는 zkMatrix가 1.19배, q=10에서는 2.92배 빠르다. 따라서 **이 기기·파라미터·독립 구현의 단일 실행에서 관찰한 첫 역전 경계는 q=3과 q=4 사이**다. q=5..9는 측정하지 않았으므로 그 구간의 상세 형태는 알 수 없다. 유한한 표본과 통제되지 않은 다른 데스크톱 부하 때문에 이를 논문의 일반적인 crossover로 주장하지 않는다.

LAMP circuit은 q=1에서 1,306,973 constraints이고 이후 claim당 1,281,209개씩 증가해 q=4에서 5,150,600개, q=10에서 12,837,854개다. Setup도 151.18→570.33→1,502.88초로 증가했다. q=10의 LAMP online 248.08초 중 matrix commitment는 44.87초, gnark solver 55.26초, Groth16 prover 117.82초였으며 QA-link 등 나머지 비용도 있다. zkMatrix는 공유 투영을 사용하는 batch 구조로 측정 범위의 online 증가가 작지만, 짧은 proof·빠른 verifier·작은 프로세스 RSS라는 별도 장점이 있다. LAMP proof 크기는 모든 측정 q에서 약 60–62 kB이고 zkMatrix는 q=1의 5.4 kB에서 q=10의 14.7 kB로 증가한다. zkMatrix의 SRS는 이 크기에서 2,101,252 G1 points이며 압축 G1만의 추정 크기는 67,240,256 B다. LAMP와 zkMatrix setup을 단순 합산해 한 숫자로 비교하면 key 재사용 모델을 숨기게 된다.

## 원자료와 한계

원자료는 [`benchmark/comparison/batch_k10_m1pro_20260930_pilot`](../../benchmark/comparison/batch_k10_m1pro_20260930_pilot)에 있다. `summary.csv`는 아래 10개 원자료를 재검증해 추린 값이다. 각 조건의 `metadata.json`은 실제 CLI, 빌드 바이너리 SHA-256, git HEAD, 실행 시간·자원 상한을 기록한다. `lamp_comparison.jsonl` 또는 `zk.csv`는 단계별 시간과 verification 결과, `stdout.log`는 회로 constraints, `stderr.log`는 `/usr/bin/time -l`의 최대 resident set을 담는다. 바이너리는 저장소에 포함하지 않는다. Go 빌드 최적화 기본 설정을 사용했고, 모든 q에서 LAMP 바이너리 SHA-256은 `90a5f28484de5938c87d1070b130376acd0b53cd39e4689f9897213f109f7346`, zkMatrix 바이너리는 `fda74283eae8f0a66d145d85ce8a91684e7c44ba4479cbe4b8c9cc8c3d481daf`이다.

q=1,2,3,4,10의 프로세스 전체 최대 RSS는 LAMP에서 각각 3.71, 3.92, 7.21, 6.97, 15.08 GB이고 zkMatrix에서 1.19, 1.30, 1.35, 1.88, 3.61 GB였다. 여기에는 setup과 입력 생성이 포함되므로 online prover만의 메모리 값은 아니다. 로컬 실험은 통계적 반복·warmup 없이 1회씩이며 공유 데스크톱의 다른 부하를 통제하지 않았다. q=5..9는 아직 측정하지 않았다. 논문 §7의 결과로 사용하려면 두 방식 모두 같은 고메모리 Linux 호스트에서 q=1..10 전체를 반복 측정하고, 저자 구현 부재에 따른 zkMatrix 독립 구현의 한계를 명시해야 한다. n=2048 단일·q=2와 n=4096 단일 결과는 [대형 행렬 파일럿](LARGE_MATRIX_PILOT_KO.md)에 있다.
