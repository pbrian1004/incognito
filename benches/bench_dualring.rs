use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BenchmarkId;
use criterion::Criterion;
use digest::Digest;
use elliptic_curve::ops::Reduce;
use elliptic_curve::Field;
use k256::sha2::Sha256;
use k256::ProjectivePoint;
use k256::Scalar;
use k256::U256;
use rand::rngs::ThreadRng;
use rand::Rng;
use elliptic_curve::group::GroupEncoding;

fn sign(message: &[u8], sk: &Scalar, pks: &[ProjectivePoint], index: usize) -> anyhow::Result<(Vec<Scalar>, Scalar)> {
    anyhow::ensure!(index < pks.len());

    let mut rng = ThreadRng::default();
    let r = Scalar::random(&mut rng);
    let mut cs: Vec<_> = (0..pks.len()).map(|i| if i == index { Scalar::ZERO } else { Scalar::random(&mut rng) }).collect();

    let point_r = ProjectivePoint::GENERATOR * r + pks.iter().zip(cs.iter()).map(|(pk, c)| pk * c).sum::<ProjectivePoint>();
    let c_final = challenge(message, &point_r, pks);

    let c_index = c_final - cs.iter().sum::<Scalar>();
    cs[index] = c_index;

    let z = r - c_index * sk;

    Ok((cs, z))
}

fn verify(message: &[u8], pks: &[ProjectivePoint], signature: &(Vec<Scalar>, Scalar)) -> anyhow::Result<()>{
    let (cs, z) = signature;
    anyhow::ensure!(pks.len() == cs.len());

    let point_r = ProjectivePoint::GENERATOR * z + pks.iter().zip(cs.iter()).map(|(pk, c)| pk * c).sum::<ProjectivePoint>();

    anyhow::ensure!(challenge(message, &point_r, &pks) == cs.iter().sum());

    Ok(())
}

fn challenge(message: &[u8], point_r: &ProjectivePoint, pks: &[ProjectivePoint]) -> Scalar {
    let mut digest = Sha256::default();
    digest.update(&message);
    digest.update(point_r.to_bytes());
    for pk in pks {
        digest.update(pk.to_bytes());
    };
    <Scalar as Reduce<U256>>::reduce_bytes(&digest.finalize())
}

fn dualring_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dualring Signing");
    for n in [32, 64, 128, 256, 512, 1024].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            let mut rng = ThreadRng::default();
            let sks: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let pks: Vec<_> = sks.iter().map(|s| ProjectivePoint::GENERATOR * s).collect();
            let index = rng.gen_range(0..n);
    
            let message = [0, 3, 6, 9];
            
            b.iter(|| sign(&message, &sks[index], &pks, index).unwrap());
        });
    }
    group.finish();
}

fn dualring_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dualring Verification");
    for n in [32, 64, 128, 256, 512, 1024].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            let mut rng = ThreadRng::default();
            let sks: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let pks: Vec<_> = sks.iter().map(|s| ProjectivePoint::GENERATOR * s).collect();
            let index = rng.gen_range(0..n);
    
            let message = [0, 3, 6, 9];
            
            let signature = sign(&message, &sks[index], &pks, index).unwrap();

            b.iter(|| verify(&message, &pks, &signature).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, dualring_sign, dualring_verify);
criterion_main!(benches);
