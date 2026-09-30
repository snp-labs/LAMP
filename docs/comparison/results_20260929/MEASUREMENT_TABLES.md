# Verified local measurement tables

Mean ± sample standard deviation; ten verified proofs per row. Setup and compilation are excluded from online proving. Matrix multiplication is excluded. Compressed proof and statement bytes are actual decoded/reverified payloads. Whole-process RSS includes setup and preparation; process counts differ between schemes. Sample SD is unavailable (JSON null / empty CSV cell) for a single setup or RSS invocation.

| Profile | Path | n | q | rho | Scheme | Online prove (s) | Precommitted (s) | Commit (s) | Verify (ms) | Proof bytes | Statement bytes | Setup mean (s), invocations | Process RSS mean (MiB), processes |
|---|---|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---|---|
| official_batch_q1_q10_local | batch | 128 | 1 | 1/2 | LAMP | 2.1099 ± 0.1453 | 1.9276 ± 0.1373 | 0.1822 ± 0.0192 | 168.5297 ± 3.6988 | 24377.6 | 64 | 17.615, 10 | 464.3, 10 |
| official_batch_q1_q10_local | batch | 128 | 1 | n/a | Independent zkMatrix | 1.1271 ± 0.0793 | 1.0885 ± 0.0777 | 0.0386 ± 0.0029 | 8.7164 ± 0.1112 | 4100.0 | 112 | 0.287, 1 | 30.5, 1 |
| official_batch_q1_q10_local | batch | 128 | 2 | 1/2 | LAMP | 3.8184 ± 0.2879 | 3.5267 ± 0.2824 | 0.2916 ± 0.0176 | 168.8140 ± 4.0619 | 24275.2 | 64 | 34.754, 10 | 901.8, 10 |
| official_batch_q1_q10_local | batch | 128 | 2 | n/a | Independent zkMatrix | 1.1943 ± 0.0684 | 1.1179 ± 0.0646 | 0.0763 ± 0.0045 | 10.7944 ± 1.1195 | 4936.0 | 224 | 0.257, 1 | 33.8, 1 |
| official_batch_q1_q10_local | batch | 128 | 3 | 1/2 | LAMP | 5.2562 ± 0.3096 | 4.8610 ± 0.3058 | 0.3952 ± 0.0329 | 174.3673 ± 21.8950 | 24384.0 | 64 | 49.921, 10 | 1230.7, 10 |
| official_batch_q1_q10_local | batch | 128 | 3 | n/a | Independent zkMatrix | 1.3938 ± 0.0886 | 1.2659 ± 0.0831 | 0.1279 ± 0.0066 | 12.5635 ± 0.7939 | 5772.0 | 336 | 0.327, 1 | 37.3, 1 |
| official_batch_q1_q10_local | batch | 128 | 4 | 1/2 | LAMP | 7.4226 ± 0.2976 | 6.9312 ± 0.2940 | 0.4915 ± 0.0267 | 168.2450 ± 1.1468 | 24236.8 | 64 | 69.245, 10 | 1741.4, 10 |
| official_batch_q1_q10_local | batch | 128 | 4 | n/a | Independent zkMatrix | 1.4735 ± 0.0306 | 1.2954 ± 0.0232 | 0.1781 ± 0.0128 | 14.3590 ± 0.2492 | 6608.0 | 448 | 0.334, 1 | 43.1, 1 |
| official_batch_q1_q10_local | batch | 128 | 5 | 1/2 | LAMP | 8.7338 ± 0.3750 | 8.1536 ± 0.3812 | 0.5802 ± 0.0279 | 167.8642 ± 1.7811 | 24396.8 | 64 | 84.911, 10 | 2069.1, 10 |
| official_batch_q1_q10_local | batch | 128 | 5 | n/a | Independent zkMatrix | 1.6713 ± 0.1521 | 1.4366 ± 0.1334 | 0.2347 ± 0.0205 | 16.2626 ± 0.5126 | 7444.0 | 560 | 0.285, 1 | 44.8, 1 |
| official_batch_q1_q10_local | batch | 128 | 6 | 1/2 | LAMP | 10.5398 ± 0.6063 | 9.7906 ± 0.5984 | 0.7492 ± 0.1042 | 169.4202 ± 2.8300 | 24217.6 | 64 | 99.400, 10 | 2325.0, 10 |
| official_batch_q1_q10_local | batch | 128 | 6 | n/a | Independent zkMatrix | 1.5278 ± 0.0419 | 1.2814 ± 0.0369 | 0.2464 ± 0.0071 | 17.7024 ± 0.2105 | 8280.0 | 672 | 0.310, 1 | 49.7, 1 |
| official_batch_q1_q10_local | batch | 128 | 7 | 1/2 | LAMP | 14.2394 ± 1.0899 | 13.4590 ± 1.0707 | 0.7803 ± 0.0557 | 169.5446 ± 2.0514 | 24281.6 | 64 | 123.658, 10 | 2801.3, 10 |
| official_batch_q1_q10_local | batch | 128 | 7 | n/a | Independent zkMatrix | 1.6792 ± 0.1467 | 1.3827 ± 0.1361 | 0.2965 ± 0.0312 | 19.5086 ± 0.1697 | 9116.0 | 784 | 0.409, 1 | 60.1, 1 |
| official_batch_q1_q10_local | batch | 128 | 8 | 1/2 | LAMP | 15.5670 ± 1.6080 | 14.6910 ± 1.6474 | 0.8760 ± 0.0691 | 177.9509 ± 28.8450 | 24384.0 | 64 | 139.322, 10 | 3130.7, 10 |
| official_batch_q1_q10_local | batch | 128 | 8 | n/a | Independent zkMatrix | 1.7203 ± 0.0597 | 1.3834 ± 0.0506 | 0.3369 ± 0.0197 | 24.1389 ± 8.9988 | 9952.0 | 896 | 0.331, 1 | 59.7, 1 |
| official_batch_q1_q10_local | batch | 128 | 9 | 1/2 | LAMP | 16.8143 ± 1.6985 | 15.8309 ± 1.7739 | 0.9834 ± 0.0927 | 168.6563 ± 2.0785 | 24428.8 | 64 | 154.386, 10 | 3317.5, 10 |
| official_batch_q1_q10_local | batch | 128 | 9 | n/a | Independent zkMatrix | 1.8015 ± 0.0648 | 1.4171 ± 0.0524 | 0.3844 ± 0.0210 | 23.1035 ± 0.3302 | 10788.0 | 1008 | 0.302, 1 | 69.0, 1 |
| official_batch_q1_q10_local | batch | 128 | 10 | 1/2 | LAMP | 19.2354 ± 2.2496 | 18.1053 ± 2.2221 | 1.1301 ± 0.1115 | 170.6403 ± 4.4397 | 24320.0 | 64 | 169.420, 10 | 3605.0, 10 |
| official_batch_q1_q10_local | batch | 128 | 10 | n/a | Independent zkMatrix | 1.7240 ± 0.1598 | 1.3379 ± 0.1381 | 0.3861 ± 0.0269 | 25.1271 ± 0.2341 | 11624.0 | 1120 | 0.297, 1 | 76.1, 1 |
| official_square_rho_1_4_local | square | 128 | 1 | 1/4 | LAMP | 1.6058 ± 0.0952 | 1.2718 ± 0.0877 | 0.3340 ± 0.0242 | 105.2481 ± 2.3931 | 25120.0 | 64 | 11.345, 10 | 296.6, 10 |
| official_square_rho_1_8_local | square | 128 | 1 | 1/8 | LAMP | 1.7234 ± 0.0764 | 1.1064 ± 0.0451 | 0.6169 ± 0.0427 | 86.7343 ± 0.8217 | 30713.6 | 64 | 9.600, 10 | 266.7, 10 |
| official_squares_k7_k10_local | square | 128 | 1 | 1/2 | LAMP | 2.0662 ± 0.1113 | 1.9010 ± 0.1075 | 0.1652 ± 0.0104 | 167.2395 ± 1.4795 | 24288.0 | 64 | 17.743, 10 | 453.6, 10 |
| official_squares_k7_k10_local | square | 128 | 1 | n/a | Independent zkMatrix | 1.3470 ± 0.1263 | 1.3023 ± 0.1233 | 0.0447 ± 0.0040 | 9.0715 ± 0.6362 | 4096.0 | 112 | 0.335, 1 | 30.8, 1 |
| official_squares_k7_k10_local | square | 256 | 1 | 1/2 | LAMP | 4.1358 ± 0.3497 | 3.5856 ± 0.3166 | 0.5502 ± 0.0464 | 167.1740 ± 0.6560 | 32339.2 | 64 | 34.776, 10 | 835.3, 10 |
| official_squares_k7_k10_local | square | 256 | 1 | n/a | Independent zkMatrix | 4.6207 ± 0.1875 | 4.4507 ± 0.1858 | 0.1700 ± 0.0568 | 9.6276 ± 0.2598 | 4544.0 | 112 | 1.122, 1 | 89.5, 1 |
| official_squares_k7_k10_local | square | 512 | 1 | 1/2 | LAMP | 9.0708 ± 0.4573 | 6.9962 ± 0.3871 | 2.0746 ± 0.1907 | 169.7381 ± 5.7903 | 44633.6 | 64 | 70.214, 10 | 1681.4, 10 |
| official_squares_k7_k10_local | square | 512 | 1 | n/a | Independent zkMatrix | 16.9261 ± 1.4706 | 16.4393 ± 1.4356 | 0.4868 ± 0.0467 | 10.4355 ± 0.1585 | 4992.0 | 112 | 4.417, 1 | 337.6, 1 |
| official_squares_k7_k10_local | square | 1024 | 1 | 1/2 | LAMP | 22.0986 ± 1.7448 | 14.9410 ± 1.9203 | 7.1576 ± 0.6064 | 171.5882 ± 3.1584 | 60742.4 | 64 | 139.520, 10 | 3271.4, 10 |
| official_squares_k7_k10_local | square | 1024 | 1 | n/a | Independent zkMatrix | 66.5999 ± 4.2575 | 64.8053 ± 4.2319 | 1.7946 ± 0.2743 | 11.2956 ± 0.2395 | 5440.0 | 112 | 17.097, 1 | 1127.0, 1 |
