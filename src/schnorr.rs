use std::ops::{Add, Mul};

use digest::{Digest, FixedOutput};
use elliptic_curve::{group::{Curve, GroupEncoding}, ops::Reduce, AffinePoint, CurveArithmetic, Field, FieldBytesSize, Group, ProjectivePoint, Scalar};
use rand::rngs::ThreadRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(bound = "Scalar<C>: Serialize + DeserializeOwned, AffinePoint<C>: Serialize + DeserializeOwned", from = "SchnorrSignatureSerde<C>", into = "SchnorrSignatureSerde<C>")]
pub struct SchnorrSignature<C: CurveArithmetic>{
    pub point_r: ProjectivePoint<C>,
    pub z: Scalar<C>
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(bound = "Scalar<C>: Serialize + DeserializeOwned, AffinePoint<C>: Serialize + DeserializeOwned")]
pub struct SchnorrSignatureSerde<C: CurveArithmetic>{
    pub point_r: AffinePoint<C>,
    pub z: Scalar<C>
}

impl <C: CurveArithmetic> SchnorrSignature<C>
where
    ProjectivePoint<C>: GroupEncoding
{
    pub(crate) fn challenge<D>(point_r: &ProjectivePoint<C>, m: &[u8]) -> Scalar<C>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(
            &D::new()
            .chain_update(point_r.to_bytes())
            .chain_update(m)
            .finalize()
        )
    }

    pub fn sign<D>(sk: &Scalar<C>, message: &[u8]) -> Self
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let mut rng = ThreadRng::default();
        let r = Scalar::<C>::random(&mut rng);
        let point_r = ProjectivePoint::<C>::generator() * r;
        let c = Self::challenge::<D>(&point_r, &message);
        let z = r + sk.mul(c);
        Self {
            point_r,
            z
        }
    }

    pub fn verify<D>(&self, pk: &ProjectivePoint<C>, message: &[u8]) -> anyhow::Result<()>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let Self {
            point_r,
            z,
            ..
        } = self;
        if pk.mul(Self::challenge::<D>(point_r, message)).add(point_r) == ProjectivePoint::<C>::generator() * z{
            Ok(())
        } else {
            anyhow::bail!("Invalid Schnorr signature")
        }
    }
}

impl <C:CurveArithmetic> From<SchnorrSignature<C>> for SchnorrSignatureSerde<C>
where
    Scalar<C>: Serialize + DeserializeOwned,
    AffinePoint<C>: Serialize + DeserializeOwned
{
    fn from(value: SchnorrSignature<C>) -> Self {
        Self {
            point_r: value.point_r.to_affine(),
            z: value.z
        }
    }
}

impl <C:CurveArithmetic> From<SchnorrSignatureSerde<C>> for SchnorrSignature<C>
where
    Scalar<C>: Serialize + DeserializeOwned,
    AffinePoint<C>: Serialize + DeserializeOwned
{
    fn from(value: SchnorrSignatureSerde<C>) -> Self {
        Self {
            point_r: ProjectivePoint::<C>::from(value.point_r),
            z: value.z
        }
    }
}

#[cfg(test)]
mod tests{
    use elliptic_curve::Field;
    use k256::{sha2::Sha256, ProjectivePoint, Scalar, Secp256k1};
    use rand::rngs::ThreadRng;

    use super::SchnorrSignature;

    #[test]
    fn test_sign() {
        let mut rng = ThreadRng::default();
        let sk = Scalar::random(&mut rng);
        let pk = ProjectivePoint::GENERATOR * sk;

        let m = [0, 3, 5, 8, 1];
        let sig = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&sk, &m);
        sig.verify::<Sha256>(&pk, &m).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_sign_panic() {
        let mut rng = ThreadRng::default();
        let sk = Scalar::random(&mut rng);
        let pk = ProjectivePoint::GENERATOR * sk;

        let m1 = [0, 3, 5, 8, 1];
        let sig = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&sk, &m1);
        let m2 = [0, 0, 3, 5, 8, 1];
        sig.verify::<Sha256>(&pk, &m2).unwrap();
    }

    #[test]
    fn test_serialization() {
        let mut rng = ThreadRng::default();
        let sk = Scalar::random(&mut rng);
        let pk = ProjectivePoint::GENERATOR * sk;

        let m = [0, 3, 5, 8, 1];
        let sig = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&sk, &m);

        let sig_new: SchnorrSignature<Secp256k1> = bincode::deserialize(&bincode::serialize(&sig).unwrap()).unwrap();
        sig_new.verify::<Sha256>(&pk, &m).unwrap();
    }
}