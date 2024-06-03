use anon::{incognito::{IncognitoParams, IncognitoSignature}, schnorr::SchnorrSignature};
use elliptic_curve::Field;
use k256::{sha2::Sha256, ProjectivePoint, Scalar, Secp256k1};
use rand::rngs::ThreadRng;

fn main() {
    let n = 128;
    let index = 65;
    let mut rng = ThreadRng::default();
    let params = IncognitoParams::<Secp256k1, 256>::new();
    let sks: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let pks: Vec<_> = sks.iter().map(|s| ProjectivePoint::GENERATOR * s).collect();

    let message = [0, 3, 6, 9];
    let signature = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&sks[index], &message);

    signature.verify::<Sha256>(&pks[index], &message).unwrap();

    let incsig = params.convert::<Sha256>(&pks, &message, &signature, index).unwrap();

    let params_new: IncognitoParams::<Secp256k1, 256> = bincode::deserialize(&bincode::serialize(&params).unwrap()).unwrap();
    let incsig_new: IncognitoSignature::<Secp256k1> = bincode::deserialize(&bincode::serialize(&incsig).unwrap()).unwrap();
    params_new.verify::<Sha256>(&pks, &message, &incsig_new).unwrap();

    println!("PK len: {:?}", bincode::serialize(&pks[0].to_affine()).unwrap().len());
    println!("Schnorr len: {:?}", bincode::serialize(&signature).unwrap().len());
    println!("PK set len: {:?}", bincode::serialize(&pks.iter().map(|each| each.to_affine()).collect::<Vec<_>>()).unwrap().len());
    println!("Incognito len: {:?}", bincode::serialize(&incsig_new).unwrap().len());
    assert_eq!(params, params_new);
}