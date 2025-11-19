use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqc_combo::*;

fn benchmark_ml_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-1024");
    
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let keys = KyberKeys::generate_key_pair();
            black_box(keys);
        });
    });
    
    let keys = KyberKeys::generate_key_pair();
    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let (ct, ss) = encapsulate_shared_secret(&keys.pk);
            black_box((ct, ss));
        });
    });
    
    let (ct, _ss) = encapsulate_shared_secret(&keys.pk);
    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            let ss = decapsulate_shared_secret(&keys.sk, &ct);
            black_box(ss);
        });
    });
    
    group.finish();
}

fn benchmark_ml_dsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-65");
    
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let (pk, sk) = generate_dilithium_keypair();
            black_box((pk, sk));
        });
    });
    
    let (pk, sk) = generate_dilithium_keypair();
    let msg = b"benchmark message";
    
    group.bench_function("sign", |b| {
        b.iter(|| {
            let sig = sign_message(&sk, msg);
            black_box(sig);
        });
    });
    
    let sig = sign_message(&sk, msg);
    group.bench_function("verify", |b| {
        b.iter(|| {
            let valid = verify_signature(&pk, msg, &sig);
            black_box(valid);
        });
    });
    
    group.finish();
}

criterion_group!(benches, benchmark_ml_kem, benchmark_ml_dsa);
criterion_main!(benches);
