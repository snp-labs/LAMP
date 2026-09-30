# 연구 전용: 원래 LAMP 회로와 KZG 커밋먼트의 Groth16 연결

**범위:** 이 작업은 `prototype/fast-pcs` 연구 브랜치에만 둔다. LAMP 메인 구현과 논문용 비교 결과에는 반영하지 않는다. 기본 `cmd/lamp` 실행 경로, 기존 Pedersen·Merkle·QA-link 프로토콜, 공식 수치는 유지한다. `--kzg-link-probe`를 명시했을 때에만 이 실험 경로를 실행한다. 메인에 병합하려면 별도의 보안 검토, 큰 크기의 성능 검증, 프로토콜 명세가 필요하다.

## 실제 연결 방식

이 실험은 이전의 [행 KZG/Freivalds 대안](ROW_KZG_FULL_FIELD_PILOT_KO.md)을 LAMP라고 바꿔 부른 것이 아니다. `circuit.LAMPCircuit`을 그대로 포함해 원래의 수평 RS 부호화, 표본 열의 A/B/C 접힘, `xᵀB`, 독립 B 접힘, XYZ 코드워드 검사 관계를 실행한다. 차이는 표본 열의 외부 데이터와 Groth16 witness를 잇는 부분이다.

1. 원래와 같이 A/B/C의 각 행을 길이 N으로 RS 부호화한다.
2. 각 열의 A/B/C 원소 `3K`개를 KZG의 계수로 커밋하고, 각 XYZ 열의 원소 3개도 KZG로 커밋한다. 두 커밋먼트 배열을 원래 LAMP의 Merkle 방식으로 고정한다.
3. 원래 transcript대로 root에서 `r`, `b`, 표본 인덱스를 도출한다.
4. `LAMPCircuit`을 포함한 연구용 `LAMPKZGLinkCircuit` 안에서 각 표본 열과 XYZ 값의 KZG 커밋먼트를 BN254 G1 MSM으로 다시 계산하고, 공개 digest와 비교한다. 따라서 외부 QA-link 증명은 이 실험 경로에서 사용하지 않는다.
5. 검증자는 Groth16 공개 입력을 root·난수·인덱스·표본 digest에서 직접 구성하고, digest의 Merkle membership과 transcript 재계산을 회로 바깥에서 확인한다.

KZG trapdoor는 임의로 생성한 로컬 SRS로 실험한다. 보안 배포에는 신뢰 가능한 SRS가 필요하다. 내부의 원래 LAMP Groth16 witness commitment는 RS 일관성 검사에 여전히 쓰인다. 외부 Pedersen commitment와 CP-link만 연구용 KZG 연결로 교체한 것이다.

이 열 KZG 커밋먼트에는 blinding을 넣지 않았다. 따라서 원래 Pedersen 커밋먼트와 같은 hiding 성질을 주장할 수 없다. 이 파일럿의 목적은 **연결의 정확성과 Groth16 비용 측정**이며, 기존 LAMP의 프라이버시 목표를 충족한 새 프로토콜이 아니다.

## 재현

```sh
go run ./cmd/lamp --kzg-link-probe -K 2 -rho 1/2 -L 1
go run ./cmd/lamp -K 2 -rho 1/2 -L 1
```

프로브는 비용 때문에 `logK=2..3`, `L=1..4`, 부호율 `1/2`만 허용한다. 두 명령의 출력은 각각 연구용 KZG 연결 경로와 기존 LAMP 경로다. 작은 K·L의 성공은 논문 보안 파라미터에서의 soundness나 성능을 보증하지 않는다.

## 작은 사례의 결과

Apple M1 Pro, macOS arm64, Go 1.26.2, K=4, N=8, L=1, 한 번씩 실행했다. 기존 경로는 1,822개 제약, 연구용 KZG 연결 회로는 686,813개 제약이었다. 연구용 회로는 Groth16 setup `62.396초`, witness 생성과 증명 `3.250초`, Groth16 및 외부 검증 `0.0029초`였다. 기존 회로의 증명은 CSV 기준 약 `0.02초`다. Groth16 증명 자체의 직렬화 길이는 두 경로 모두 292바이트였지만, 연구용 경로에는 Merkle sibling 192바이트와 압축 표본 digest 64바이트가 별도로 든다. 공개 root·SRS도 이 크기에 포함되지 않는다. 정확한 수치와 명령 출력은 [원자료](../../benchmark/comparison/lamp_kzg_link_20260930/README.md)에 기록했다.

이 방식은 Groth16과 실제로 연결되고 정직한 증명이 검증된다. ABC의 표본 KZG digest를 다른 열의 digest로 바꾼 witness는 Groth16 제약에서 거부되었다. 그러나 표본 열 하나의 KZG MSM 두 개만으로도 제약 수가 약 377배가 된다. 큰 K·L에서의 전체 proof time은 아직 측정하지 않았으며, 현재 방식은 사용자가 중시하는 빠른 증명 목표에 적합하지 않을 가능성이 크다. 이러한 비용 문제 때문에 메인 LAMP로 승격하지 않는다.
