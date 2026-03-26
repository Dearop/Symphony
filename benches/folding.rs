//! Benchmarks for commitment and folding operations.

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_ring_mul(c: &mut Criterion) {
    use symphony::ring::RingElement;
    let a = RingElement::from_constant(42);
    let b = RingElement::monomial(3);
    let q = 12289u64;

    c.bench_function("ring_mul_schoolbook", |bencher| {
        bencher.iter(|| a.mul(&b, q));
    });
}

fn bench_ntt_ring_mul(c: &mut Criterion) {
    use symphony::ring::RingElement;
    use symphony::ring::ntt::NttContext;
    let q = 12289u64;
    let ctx = NttContext::new(q);
    let a = RingElement::from_constant(42);
    let b = RingElement::monomial(3);

    c.bench_function("ring_mul_ntt", |bencher| {
        bencher.iter(|| ctx.ring_mul(&a, &b));
    });
}

fn bench_commitment(c: &mut Criterion) {
    use symphony::commitment::AjtaiParams;
    use symphony::ring::{RingElement, RingVector};

    let kappa = 4; // smaller for benchmarking
    let n = 64;
    let q = 12289u64;
    let params = AjtaiParams::setup(kappa, n, q);
    let witness = RingVector {
        elements: (0..n).map(|i| RingElement::from_constant(i as i64)).collect(),
    };

    c.bench_function("ajtai_commit_64", |bencher| {
        bencher.iter(|| params.commit(&witness));
    });
}

fn bench_decomposition(c: &mut Criterion) {
    use symphony::decomposition;

    c.bench_function("gadget_decompose_16_16", |bencher| {
        bencher.iter(|| decomposition::decompose(123456789, 16, 16));
    });
}

criterion_group!(
    benches,
    bench_ring_mul,
    bench_ntt_ring_mul,
    bench_commitment,
    bench_decomposition,
);
criterion_main!(benches);
