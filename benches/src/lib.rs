use criterion::Criterion;

#[cfg(any(target_arch = "x86_64", target_arch = "x86", all(target_arch = "aarch64", target_os = "linux")))]
pub type Benchmarker = Criterion<criterion_cycles_per_byte::CyclesPerByte>;
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", all(target_arch = "aarch64", target_os = "linux"))))]
pub type Benchmarker = Criterion;

#[macro_export]
macro_rules! criterion_group_bench {
    ($Name:ident, $Target:ident) => {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86", all(target_arch = "aarch64", target_os = "linux")))]
        criterion_group!(
            name = $Name;
            config = Criterion::default().with_measurement(criterion_cycles_per_byte::CyclesPerByte);
            targets = $Target
        );
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", all(target_arch = "aarch64", target_os = "linux"))))]
        criterion_group!(
            name = $Name;
            config = Criterion::default();
            targets = $Target
        );
    }
}