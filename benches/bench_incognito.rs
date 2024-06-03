use anon::incognito::IncognitoParams;
use anon::schnorr::SchnorrSignature;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BenchmarkId;
use criterion::Criterion;
use elliptic_curve::Field;
use k256::sha2::Sha256;
use k256::ProjectivePoint;
use k256::Scalar;
use k256::Secp256k1;
use rand::rngs::ThreadRng;
use rand::Rng;

fn incognito_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Incognito Signing");
    for n in [32, 64, 128, 256, 512, 1024].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            let mut rng = ThreadRng::default();
            let params = IncognitoParams::<Secp256k1, 1024>::new();
            let sks: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let pks: Vec<_> = sks.iter().map(|s| ProjectivePoint::GENERATOR * s).collect();
            let index = rng.gen_range(0..n);
    
            let message = [0, 3, 6, 9];
            let signature = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&sks[index], &message);    
            
            b.iter(|| params.convert::<Sha256>(&pks, &message, &signature, index).unwrap());
        });
    }
    group.finish();
}

fn incognito_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Incognito Verification");
    for n in [32, 64, 128, 256, 512, 1024].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            let mut rng = ThreadRng::default();
            let params = IncognitoParams::<Secp256k1, 1024>::new();
            let sks: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let pks: Vec<_> = sks.iter().map(|s| ProjectivePoint::GENERATOR * s).collect();
            let index = rng.gen_range(0..n);
    
            let message = [0, 3, 6, 9];
            let signature = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&sks[index], &message);    

            let incsig = params.convert::<Sha256>(&pks, &message, &signature, index).unwrap();
            b.iter(|| params.verify::<Sha256>(&pks, &message, &incsig).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, incognito_sign, incognito_verify);
criterion_main!(benches);