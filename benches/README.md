# Benching ChaCha20
## ChaCha20 Cipher benching
You can bench the ChaCha20 cipher using `cargo bench -- apply_keystream`

## ChaCha20 RNG bench comparisons
This is an example of a test procedure for comparing `rand_chacha` and `chacha20`, which are 2 fast implementations of ChaCha20:
1) Ensure that line 70 of `benches/src/chacha20.rs` is active and line 69 is commented
2) run `cargo bench -- fill_bytes`
- alternatively, you can compare the ChaCha20 Cipher to measure the RNG's overhead by commenting lines 69-71 and uncommenting lines 72-73. Ideally, there wouldn't be any overhead, but the cipher defines a "speed limit" for the RNG—not that it is slow, but the RNG cannot be faster than the cipher without a completely separate implementation of ChaCha20, or by trying to skew the results of the cipher by triggering CPU throttling while it is running.
3) comment out line 70 and uncomment line 69
4) run `cargo bench -- fill_bytes`
5) optionally, you can view the generated reports and charts in:
`benches/target/criterion`

## ChaCha20 RNG Overhead with AVX2
Running `chacha20 cipher` followed by `chacha20` RNG:
```
chacha-SIMD-comparison-x86/fill_bytes/1024                                                                            
                        time:   [1038.0927 cycles 1039.7822 cycles 1041.5326 cycles]
                        thrpt:  [1.0171 cpb 1.0154 cpb 1.0138 cpb]
                 change:
                        time:   [+3.6109% +4.1106% +4.6048%] (p = 0.00 < 0.05)
                        thrpt:  [-4.4021% -3.9483% -3.4851%]
                        Performance has regressed.
Found 6 outliers among 100 measurements (6.00%)
  5 (5.00%) high mild
  1 (1.00%) high severe
chacha-SIMD-comparison-x86/fill_bytes/2048                                                                             
                        time:   [2082.7552 cycles 2092.2750 cycles 2103.2769 cycles]
                        thrpt:  [1.0270 cpb 1.0216 cpb 1.0170 cpb]
                 change:
                        time:   [+5.8304% +6.3071% +6.8129%] (p = 0.00 < 0.05)
                        thrpt:  [-6.3783% -5.9329% -5.5092%]
                        Performance has regressed.
Found 8 outliers among 100 measurements (8.00%)
  5 (5.00%) high mild
  3 (3.00%) high severe
chacha-SIMD-comparison-x86/fill_bytes/4096                                                                             
                        time:   [4164.4707 cycles 4175.9468 cycles 4189.0674 cycles]
                        thrpt:  [1.0227 cpb 1.0195 cpb 1.0167 cpb]
                 change:
                        time:   [+6.6977% +7.1506% +7.6829%] (p = 0.00 < 0.05)
                        thrpt:  [-7.1348% -6.6734% -6.2773%]
                        Performance has regressed.
Found 6 outliers among 100 measurements (6.00%)
  3 (3.00%) high mild
  3 (3.00%) high severe
chacha-SIMD-comparison-x86/fill_bytes/8192                                                                             
                        time:   [8289.8595 cycles 8306.5768 cycles 8324.4376 cycles]
                        thrpt:  [1.0162 cpb 1.0140 cpb 1.0119 cpb]
                 change:
                        time:   [+6.9187% +7.4968% +8.0257%] (p = 0.00 < 0.05)
                        thrpt:  [-7.4295% -6.9740% -6.4710%]
                        Performance has regressed.
Found 8 outliers among 100 measurements (8.00%)
  5 (5.00%) high mild
  3 (3.00%) high severe
chacha-SIMD-comparison-x86/fill_bytes/16384                                                                             
                        time:   [16656.5840 cycles 16706.5595 cycles 16760.4190 cycles]
                        thrpt:  [1.0230 cpb 1.0197 cpb 1.0166 cpb]
                 change:
                        time:   [+7.8200% +8.2519% +8.7070%] (p = 0.00 < 0.05)
                        thrpt:  [-8.0096% -7.6229% -7.2528%]
                        Performance has regressed.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild
```

## AVX2 RNG bench comparison
Running `rand_chacha` followed by `chacha20` on a `13th gen i9` with `AVX2`:
```
chacha-SIMD-comparison-x86/fill_bytes/1024                                                                            
                        time:   [1037.8568 cycles 1040.5950 cycles 1044.3938 cycles]
                        thrpt:  [1.0199 cpb 1.0162 cpb 1.0135 cpb]
                 change:
                        time:   [-3.6337% -3.2894% -2.9152%] (p = 0.00 < 0.05)
                        thrpt:  [+3.0027% +3.4013% +3.7707%]
                        Performance has improved.
Found 5 outliers among 100 measurements (5.00%)
  2 (2.00%) high mild
  3 (3.00%) high severe
chacha-SIMD-comparison-x86/fill_bytes/2048                                                                             
                        time:   [2079.5816 cycles 2083.6528 cycles 2088.0301 cycles]
                        thrpt:  [1.0195 cpb 1.0174 cpb 1.0154 cpb]
                 change:
                        time:   [-4.1172% -3.6939% -3.2446%] (p = 0.00 < 0.05)
                        thrpt:  [+3.3534% +3.8356% +4.2940%]
                        Performance has improved.
Found 6 outliers among 100 measurements (6.00%)
  3 (3.00%) high mild
  3 (3.00%) high severe
chacha-SIMD-comparison-x86/fill_bytes/4096                                                                             
                        time:   [4146.6663 cycles 4152.7313 cycles 4159.3642 cycles]
                        thrpt:  [1.0155 cpb 1.0139 cpb 1.0124 cpb]
                 change:
                        time:   [-4.5449% -4.1512% -3.7761%] (p = 0.00 < 0.05)
                        thrpt:  [+3.9242% +4.3310% +4.7613%]
                        Performance has improved.
Found 6 outliers among 100 measurements (6.00%)
  5 (5.00%) high mild
  1 (1.00%) high severe
chacha-SIMD-comparison-x86/fill_bytes/8192                                                                             
                        time:   [8291.6899 cycles 8308.1529 cycles 8325.4636 cycles]
                        thrpt:  [1.0163 cpb 1.0142 cpb 1.0122 cpb]
                 change:
                        time:   [-4.5805% -4.2674% -3.9447%] (p = 0.00 < 0.05)
                        thrpt:  [+4.1067% +4.4576% +4.8004%]
                        Performance has improved.
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild
chacha-SIMD-comparison-x86/fill_bytes/16384                                                                             
                        time:   [16565.5002 cycles 16593.7577 cycles 16623.0492 cycles]
                        thrpt:  [1.0146 cpb 1.0128 cpb 1.0111 cpb]
                 change:
                        time:   [-4.4860% -4.1708% -3.8353%] (p = 0.00 < 0.05)
                        thrpt:  [+3.9883% +4.3523% +4.6967%]
                        Performance has improved.
Found 8 outliers among 100 measurements (8.00%)
  6 (6.00%) high mild
  2 (2.00%) high severe
```
## NEON bench comparison
Running `rand_chacha` followed by `chacha20` on an `Apple M1` chip using `NEON`. The main reason that it is faster is due to there being `NEON` support in `chacha20`. Also, the library used for measuring the cycles in the x86 examples does not work on aarch64, so it is measured with time instead of cycles.
```
chacha-SIMD-comparison/fill_bytes/1024                        
                        time:   [794.99 ns 795.52 ns 796.28 ns]
                        thrpt:  [1.1977 GiB/s 1.1988 GiB/s 1.1996 GiB/s]
                 change:
                        time:   [-62.108% -62.046% -61.983%] (p = 0.00 < 0.05)
                        thrpt:  [+163.04% +163.47% +163.91%]
chacha-SIMD-comparison/fill_bytes/2048                        
                        time:   [1.5936 µs 1.5951 µs 1.5968 µs]
                        thrpt:  [1.1945 GiB/s 1.1958 GiB/s 1.1969 GiB/s]
                 change:
                        time:   [-62.298% -62.164% -62.048%] (p = 0.00 < 0.05)
                        thrpt:  [+163.49% +164.30% +165.24%]
chacha-SIMD-comparison/fill_bytes/4096                        
                        time:   [3.2040 µs 3.2097 µs 3.2154 µs]
                        thrpt:  [1.1864 GiB/s 1.1885 GiB/s 1.1906 GiB/s]
                 change:
                        time:   [-62.041% -61.949% -61.858%] (p = 0.00 < 0.05)
                        thrpt:  [+162.18% +162.80% +163.44%]
chacha-SIMD-comparison/fill_bytes/8192                        
                        time:   [6.4385 µs 6.4500 µs 6.4624 µs]
                        thrpt:  [1.1806 GiB/s 1.1829 GiB/s 1.1850 GiB/s]
                 change:
                        time:   [-62.059% -61.963% -61.873%] (p = 0.00 < 0.05)
                        thrpt:  [+162.28% +162.90% +163.57%]
chacha-SIMD-comparison/fill_bytes/16384                        
                        time:   [12.881 µs 12.897 µs 12.913 µs]
                        thrpt:  [1.1816 GiB/s 1.1831 GiB/s 1.1846 GiB/s]
                 change:
                        time:   [-62.002% -61.928% -61.851%] (p = 0.00 < 0.05)
                        thrpt:  [+162.13% +162.66% +163.17%]
```
