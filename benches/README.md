# Benching ChaCha20

## A note from the criterion-cycles-per-byte github
```
[`criterion-cycles-per-byte`] measures clock ticks rather than cycles. It will not provide accurate results on modern machines unless you calculate the ratio of ticks to cycles and take steps to ensure that that ratio remains consistent.
```

## ChaCha20 Cipher benching
You can bench the ChaCha20 cipher using `cargo bench -- apply_keystream`

## ChaCha20Rng benching
You can bench ChaCha20Rng using `cargo bench -- fill_bytes`

## Measuring CPB for aarch64
`criterion-cycles-per-byte` can work on `aarch64` with Linux, but it might produce an error. This error occurred on an up-to-date Raspberry Pi 4b (as of 12/14/2023):
```
     Running src/chacha20.rs (target/release/deps/chacha20-02f555ae0af3670b)
Gnuplot not found, using plotters backend
Benchmarking stream-cipher/apply_keystream/1024: Warming up for 3.0000 serror: bench failed, to rerun pass `--bench chacha20`

Caused by:
  process didn't exit successfully: `..../benches/target/release/deps/chacha20-02f555ae0af3670b --bench` (signal: 4, SIGILL: illegal instruction)
```

The following adjustment can fix this.

### Installing the cycle counter Linux Kernel Module on a Raspberry Pi 4b
```
$ sudo apt-get update
$ sudo apt-get upgrade
$ sudo apt-get install build-essential raspberrypi-kernel-headers
# cd to your chosen directory
$ cd ../..
$ git clone https://github.com/jerinjacobk/armv8_pmu_cycle_counter_el0.git
$ cd armv8_pmu_cycle_counter_el10
$ make
$ sudo insmod pmu_el0_cycle_counter.ko
# Verifying that it is installed
$ lsmod | grep pmu_el0_cycle_counter
pmu_el0_cycle_counter    16384  0
```
Without any other commands, this module will be deactivated after every reboot, and can be reactivated using
```
$ cd armv8_pmu_cycle_counter_el10
$ sudo insmod pmu_el0_cycle_counter.ko
```