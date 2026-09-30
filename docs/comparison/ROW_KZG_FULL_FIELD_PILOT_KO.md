# 전체 필드 KZG/Freivalds 대안과 외부 Groth16 비용

2026-09-30. 열 방향 RS 코드의 한 행만 표본으로 뽑는 방식은 부호율 1/2에서 최악의 오류 확률이 약 1/2이다. 이 문제를 피하면서 남은 `xᵀB` 관계까지 실제로 검증하기 위해 **별도의 비영지식 행 KZG/Freivalds 프로토콜**을 구현했다. 이는 기존 LAMP 논문의 표본 열 프로토콜을 그대로 교체한 구현이 아니다. 코드: `crypto/kzgrow`, `cmd/lamp_kzg_row_probe`. 원자료와 재현 명령은 [실험 README](../../benchmark/comparison/row_kzg_probe_20260930/README.md)에 둔다.

## 검증 관계

각 K×K 행렬의 K개 행을 차수 `<K` 다항식으로 보간하여 KZG로 고정한다. A/B/C에 총 `3K`개의 행 커밋먼트가 생긴다. 이후 공개 커밋먼트로부터 전체 BN254 필드의 난수 `r`을 만들고, 증명자는 길이 K인 `x=rᵀA`를 보낸다. 검증자는 `x`의 보간 다항식을 KZG에 다시 커밋해 `Σᵢ rⁱ Com(Aᵢ)`와 비교하므로 `x`가 기존 A에 묶인다.

그다음 두 가지 완전한 검증 변형을 구현했다.

1. **점 평가 변형:** `x`가 고정된 뒤 난수 `s`를 만든다. 증명자는 K개 B행의 `Bᵢ(s)`와 `r`로 합친 C행의 `Cᵣ(s)`를 **하나의 batched KZG opening**으로 연다. 검증자는 `Σᵢ xᵢ Bᵢ(s)=Cᵣ(s)`를 확인한다. 잘못된 `AB=C`에 대한 대수적 오류항은 최대 `2(K−1)/|Fr|`이다.
2. **직접 커밋먼트 비교 변형:** KZG의 선형성을 이용해 `Σᵢ xᵢ Com(Bᵢ)=Σᵢ rⁱ Com(Cᵢ)`를 검증한다. 이 방식에는 `s`, B의 점 평가값, KZG opening이나 pairing 검증이 필요 없다. 첫 번째 `x` 결합 검사와 함께 전체 행 다항식의 관계를 확인하며 대수적 오류항은 최대 `(K−1)/|Fr|`이다.

두 오류항 모두 Fiat–Shamir 변환과 KZG binding 가정을 제외한 값이다. 정직한 곱, 틀린 C, 변조된 `x`·opening·커밋먼트·root, 두 변형의 직렬화 round-trip을 테스트했다.

두 변형 모두 내부 영지식이 없다. 직접 비교 변형의 증명에는 `x`만, 점 평가 변형에는 `x`와 B의 K개 점 평가가 들어간다. 외부 Groth16으로 검증기를 감싸면 이를 비공개 witness로 둘 수 있지만, 외부 회로의 비용은 별도다.

## 1회 측정

Apple M1 Pro, Go 1.26.2, 10 worker, `A=I+uvᵀ`, 무작위 dense B, `C=AB`. 구조화된 A를 사용해 큰 크기의 정직한 곱을 O(K²)로 만들었으며 행 값은 dense다. 행렬 생성과 SRS 설정은 온라인 증명 시간에서 제외했다.

| K | 행 보간 | 3K개 KZG 커밋 | 점 평가 변형: 온라인/검증/증명 | 직접 비교 변형: 온라인/검증/증명 | 행 커밋 statement |
|---:|---:|---:|---:|---:|---:|
| 256 | 0.005 s | 0.312 s | 0.325 s / 0.003 s / 16,456 B | 0.319 s / 0.003 s / 8,200 B | 24,584 B |
| 1024 | 0.058 s | 3.571 s | 3.713 s / 0.008 s / 65,608 B | 3.657 s / 0.007 s / 32,776 B | 98,312 B |
| 2048 | 0.213 s | 12.797 s | 13.337 s / 0.013 s / 131,144 B | 13.123 s / 0.011 s / 65,544 B | 196,616 B |
| 4096 | 0.865 s | 50.140 s | 52.726 s / 0.030 s / 262,216 B | 51.462 s / 0.030 s / 131,080 B | 393,224 B |

`proof`와 `statement`는 실제 바이너리 직렬화 길이이고, 별도 KZG SRS 크기는 포함하지 않는다. 직접 비교 변형에서는 전체 증명 시간의 대부분이 3K개 행 커밋먼트 계산이다. 기존 LAMP의 n=4096 온라인 162.305초는 [기존 파일럿](LARGE_MATRIX_PILOT_KO.md)의 다른 프로토콜과 다른 행렬 생성 경로이므로 이 표와 동일 조건의 성능 승부로 볼 수 없다.

## 외부 Groth16의 비용 하한 실험

gnark의 BN254 KZG verifier gadget을 BN254 Groth16 회로에 넣어 **KZG opening 한 개만** 측정했다. 회로 제약은 `589,227`개였고, 한 번의 Groth16 증명은 `3.72초`, setup은 `58.49초`였다. 이는 **점 평가 변형에만 해당하는 부품 비용**이다. 직접 비교 변형에는 opening이나 pairing이 없다.

두 변형 모두 다수의 BN254 행 커밋먼트를 scalar multiplication으로 결합해야 한다. 별도로 MSM 회로 하나를 컴파일하자 `K=4,8,16,32`에서 각각 `172,944 / 337,523 / 609,449 / 1,153,300` 제약이었다. 큰 K로의 단순 선형 외삽은 실측이 아니며, 전체 wrapper는 구현·측정하지 않았다. 특히 3K개 행 커밋먼트의 SHA-256 root 검증과 Fiat–Shamir 난수 생성도 회로에 포함되어야 한다. 따라서 최종 ZK 증명 시간은 아직 없다. 원자료는 [wrapper constraints](../../benchmark/comparison/row_kzg_probe_20260930/wrapper_constraints.jsonl)와 [single-opening Groth16](../../benchmark/comparison/row_kzg_probe_20260930/wrapper_prove.json)에 있다.

## 판정

전체 필드 난수와 두 가지 KZG 검증 변형으로 수직 표본 방식의 안전성 문제와 `xᵀB` 관계를 해결했다. 그러나 이것은 **별도의 행 KZG/Freivalds 프로토콜**이다. 행을 K개 점에서 보간할 뿐 별도의 부호 중복도나 LAMP의 표본 열 검사는 사용하지 않는다. KZG 행 커밋의 trusted setup, `O(K)` 크기 증명·statement, 그리고 외부 SNARK 안의 BN254 곡선 연산 비용을 가진다. 따라서 내부 네이티브 증명 시간이 기존 LAMP보다 낮게 나와도 이를 최종 LAMP 개선이나 Shepherd 비교 결과로 제시해서는 안 된다.

원래 LAMP의 ECC 표본 구조를 유지하면서 외부 SNARK 증명 시간을 줄이려면, 검증기가 주로 필드 연산과 회로 친화적 해시를 수행하는 **비영지식 code 기반 PCS와 일괄 내적 증명**이 더 적합한 다음 후보이다. [DeepFold](https://www.usenix.org/conference/usenixsecurity25/presentation/guo-yanpei)와 [Brakedown](https://eprint.iacr.org/2021/1043.pdf)은 관련 1차 자료이지만, 이 저장소에서 BN254 LAMP 관계에 연결해 검증된 구현은 아직 없다.
