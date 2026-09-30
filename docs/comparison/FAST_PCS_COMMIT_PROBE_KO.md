# 빠른 PCS 연구: 해시 커밋 구성요소 실험

2026-09-30. 이 문서는 완전한 LAMP 증명 비교가 아니라, Pedersen leaf 생성 비용을 대체할 여지가 있는지 확인하는 **구성요소 실험**이다. 현재의 LAMP, zkMatrix, zkMaP 결과 표에 아래 시간을 합쳐서는 안 된다.

## 실험

`cmd/lamp_commit_probe`는 동일한 세 개의 무작위 (K\times K) 행렬을 기존 `crypto.Encoder`로 RS 부호화한다. (C=AB) 계산은 커밋 비용과 무관하므로 실행하지 않는다. 같은 부호화된 A/B/C 열에 대해 다음 두 작업을 잰다.

1. 기존 `BatchPedersenCommitABCBlinded`와 MiMC Merkle tree.
2. 각 A/B/C 열의 원소를 인덱스·벡터 길이·독립 256비트 salt와 함께 SHA-256으로 해시하고, 그 해시를 배열형 이진 Merkle tree에 넣는 실험용 oracle.

기존 방식의 commitment key 생성, 입력 행렬 생성, RS 부호화는 양쪽 커밋 시간에서 제외한다. RS 부호화는 별도 시간으로 보고한다. 양쪽 모두 복원추출로 생성한 309개 질의에 대한 Merkle multiproof를 만들고 검증한다. 이 해시 oracle의 단독 검증에는 **질의된 A/B/C 열 전체와 salt**가 필요하다. 내부 opening을 나중에 외부 Groth16의 비공개 witness로 넣는다면 내부 방식 자체는 영지식일 필요가 없다. 다만 이 프로브에는 LAMP의 표본 관계 증명과 외부 Groth16 검증 회로가 없다.

Apple M1 Pro 10 CPU, 32 GiB, macOS, Go 1.26.2에서 한 번씩 실행했다. `rho=1/2`, seed 20260930, 질의 309개. 단위는 초다.

| K | N | RS 부호화 | Pedersen+Merkle 커밋 | SHA-256+Merkle 커밋 | 해시 opening 데이터량 |
|---:|---:|---:|---:|---:|---:|
| 1024 | 2048 | 0.726 | 7.194 | 0.189 | 28,242,880 B |
| 2048 | 4096 | 2.308 | 21.760 | 0.803 | 59,414,816 B |
| 4096 | 8192 | 9.088 | 70.899 | 2.989 | 118,013,216 B |

검증된 서로 다른 열의 수는 순서대로 287, 302, 300개다. K=4096에서는 서로 다른 질의 300개마다 A/B/C의 길이 4096인 열 세 개를 연다. 필드 원소를 32 B로 직렬화하므로 열 값만 `300 × 3 × 4096 × 32 = 117,964,800 B`다. 여기에 salt 9,600 B와 Merkle 형제 노드 38,816 B가 더해져 총 **118,013,216 B(약 112.55 MiB)**다. 309개 질의 중 중복 9개는 한 번만 연다.

해시 경로 검증 시간에는 opening의 모든 열을 다시 해시하는 시간이 포함된다. 독립 salt와 Merkle tree 저장량은 K=4096에서 786,400 B였다. K=4096 프로세스 최대 RSS는 약 6.50 GB였다. 외부 Groth16을 쓰면 118 MB는 공개 증명 크기가 아니라 비공개 witness 데이터가 될 수 있다. 그러나 외부 회로가 이 열과 경로의 해시 검증을 수행해야 하며 그 증명 시간은 측정하지 않았다. 따라서 표의 커밋 시간 차이를 LAMP 전체 증명 가속 비율로 해석할 수 없다.

재현:

```sh
go build -o /tmp/lamp_commit_probe ./cmd/lamp_commit_probe
/tmp/lamp_commit_probe --logK 10 --rho 1/2 --queries 309 --seed 20260930
/tmp/lamp_commit_probe --logK 11 --rho 1/2 --queries 309 --seed 20260930
/tmp/lamp_commit_probe --logK 12 --rho 1/2 --queries 309 --seed 20260930
go test ./crypto ./cmd/lamp_commit_probe
```

## 다음 구현에서 해결해야 할 관계

해시 커밋을 실제 LAMP에 사용하려면 사전에 고정된 A/B/C와 중간 codeword가 표본 위치에서 네 가지 접힘 등식과 RS 관계를 만족함을 증명해야 한다. 검증자가 행렬 commitment를 받은 뒤 접힘 난수를 만들고, 중간값 commitment를 받은 뒤 표본 인덱스를 만드는 순서도 보존해야 한다. 이 프로브에는 그 관계 증명이 없다. 단순 opening을 외부 SNARK의 비공개 witness로 넣을 수는 있지만, 300개의 열 전체를 확인하는 큰 검증 회로가 필요할 수 있다.

후속 백엔드 후보는 [DeepFold](https://www.usenix.org/conference/usenixsecurity25/presentation/guo-yanpei) 계열의 비영지식 RS 기반 PCS와 sumcheck 관계 증명이다. 외부 Groth16이 내부 증명 검증을 비공개로 감싼다면 내부 영지식성보다 **내부 증명 시간과 외부 검증 회로 비용**을 먼저 최적화해야 한다. 원 논문의 DeepFold matrix multiplication 증명은 LAMP의 ECC 표본 관계와 다르므로 통째로 사용하거나 논문 수치를 LAMP 성능으로 옮겨서는 안 된다. 저자 공개 구현의 BN254 경로도 완료 여부를 별도로 검증해야 한다. 집계 SNARK를 적용한다면 `기본 증명 시간 + 집계 증명 시간`을 온라인 비용으로 보고한다.

저자의 [DeepFold-HyperPlonk 공개 아티팩트](https://doi.org/10.5281/zenodo.14725129)를 확인했다. 포함된 BN254 필드 모듈의 `inv_2`는 미구현이고 DeepFold 벤치마크는 Goldilocks64를 사용한다. 따라서 이 아티팩트를 현재 BN254 LAMP에 단순 연결하여 완전한 내부 증명을 얻을 수 없다. 독립적인 PCS 검증뿐 아니라 LAMP 샘플 관계·외부 입력 바인딩·challenge 순서에 대한 구현 및 악의적 prover 테스트가 필요하다.
