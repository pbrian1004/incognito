use digest::{Digest, FixedOutput};
use elliptic_curve::{group::{Curve, GroupEncoding}, ops::Reduce, AffinePoint, CurveArithmetic, Field, FieldBytes, FieldBytesSize, ProjectivePoint, Scalar};
use serde::{de::DeserializeOwned, Deserialize, Serialize};


#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(bound = "Scalar<C>: Serialize + DeserializeOwned, AffinePoint<C>: Serialize + DeserializeOwned", from = "BulletProofSerde<C>", into = "BulletProofSerde<C>")]
pub struct  BulletProof <C: CurveArithmetic> {
    pub target: ProjectivePoint<C>,
    pub(crate) vec_point_l: Vec<ProjectivePoint<C>>,
    pub(crate) vec_point_r: Vec<ProjectivePoint<C>>,
    pub(crate) l: Scalar<C>,
    pub(crate) r: Scalar<C>
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(bound = "Scalar<C>: Serialize + DeserializeOwned, AffinePoint<C>: Serialize + DeserializeOwned")]
pub(crate) struct BulletProofSerde <C: CurveArithmetic> {
    target: AffinePoint<C>,
    vec_point_l: Vec<AffinePoint<C>>,
    vec_point_r: Vec<AffinePoint<C>>,
    l: Scalar<C>,
    r: Scalar<C>
}

impl <C: CurveArithmetic> BulletProof<C> 
where
    ProjectivePoint<C>: GroupEncoding,
    Scalar<C>: Serialize + DeserializeOwned,
    AffinePoint<C>: Serialize + DeserializeOwned
{
    #[inline]
    fn challenge<D>(
        target: &ProjectivePoint<C>,
        point_l: &ProjectivePoint<C>,
        point_r: &ProjectivePoint<C>
    ) -> Scalar<C>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let digest = D::new()
            .chain_update(target.to_bytes())
            .chain_update(point_l.to_bytes())
            .chain_update(point_r.to_bytes())
            .finalize_fixed();
        let fieldbytes = digest as FieldBytes<C>;
        <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(&fieldbytes)
    }

    pub fn prove<D>(vec_g: &[ProjectivePoint<C>], vec_h: &[ProjectivePoint<C>], vec_l: &[Scalar<C>], vec_r: &[Scalar<C>], target: &ProjectivePoint<C>) -> BulletProof<C> 
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let mut n = vec_g.len();

        let mut vec_point_l = Vec::new();
        let mut vec_point_r = Vec::new();

        let mut vec_g = vec_g.to_owned();
        let mut vec_h = vec_h.to_owned();
        let mut vec_l = vec_l.to_owned();
        let mut vec_r = vec_r.to_owned();
        let mut point_p = target.to_owned();

        while n > 1 {
            n = n / 2;

            let (vec_g0, vec_g1) = vec_g.split_at(n);
            let (vec_h0, vec_h1) = vec_h.split_at(n);
            let (vec_l0, vec_l1) = vec_l.split_at(n);
            let (vec_r0, vec_r1) = vec_r.split_at(n);
            let point_l: ProjectivePoint<C> = (0..n).map(|i| {
                vec_g1[i] * vec_l0[i] + vec_h0[i] * vec_r1[i]
            }).sum();
            let point_r: ProjectivePoint<C> = (0..n).map(|i| {
                vec_g0[i] * vec_l1[i] + vec_h1[i] * vec_r0[i]
            }).sum();
            vec_point_l.push(point_l);
            vec_point_r.push(point_r);

            let x = Self::challenge::<D>(&target, &point_l, &point_r);
            let x_inv = x.invert().unwrap();

            point_p = point_l * x * x + point_p + point_r * x_inv * x_inv;
            vec_g = (0..n).map(|i| vec_g0[i] * x_inv + vec_g1[i] * x).collect();
            vec_h = (0..n).map(|i| vec_h0[i] * x + vec_h1[i] * x_inv).collect();
            vec_l = (0..n).map(|i| vec_l0[i] * x + vec_l1[i] * x_inv).collect();
            vec_r = (0..n).map(|i| vec_r0[i] * x_inv + vec_r1[i] * x).collect();

            debug_assert_eq!(
                point_p, 
                (0..n).map(|i| vec_g[i] * vec_l[i] + vec_h[i] * vec_r[i]).sum()

            );
        }

        let l = vec_l[0];
        let r = vec_r[0];

        BulletProof::<C>{
            target: target.to_owned(),
            vec_point_l,
            vec_point_r,
            l,
            r,
        }
    }

    pub fn verify<D>(&self, vec_g: &[ProjectivePoint<C>], vec_h: &[ProjectivePoint<C>]) -> anyhow::Result<()> 
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let mut n = vec_g.len();
        anyhow::ensure!(n == 2_usize.pow(self.vec_point_l.len() as u32));

        let mut vec_g = vec_g.to_owned();
        let mut vec_h = vec_h.to_owned();
        let mut point_p = self.target.to_owned();

        for i in 0..self.vec_point_l.len() {
            n = n / 2;

            let (vec_g0, vec_g1) = vec_g.split_at(n);
            let (vec_h0, vec_h1) = vec_h.split_at(n);
            let point_l = self.vec_point_l[i];
            let point_r = self.vec_point_r[i];

            let x = Self::challenge::<D>(&self.target, &point_l, &point_r);
            let x_inv = x.invert().unwrap();

            point_p = point_l * x * x + point_p + point_r * x_inv * x_inv;
            vec_g = (0..n).map(|i| vec_g0[i] * x_inv + vec_g1[i] * x).collect();
            vec_h = (0..n).map(|i| vec_h0[i] * x + vec_h1[i] * x_inv).collect();
        }

        anyhow::ensure!(point_p == vec_g[0] * self.l + vec_h[0] * self.r);
        Ok(())

    }
}

impl <C:CurveArithmetic> From<BulletProof<C>> for BulletProofSerde<C>
where
    Scalar<C>: Serialize + DeserializeOwned,
    AffinePoint<C>: Serialize + DeserializeOwned
{
    fn from(value: BulletProof<C>) -> Self {
        Self {
            target: value.target.to_affine(),
            vec_point_l: value.vec_point_l.into_iter().map(|each| each.to_affine()).collect(),
            vec_point_r: value.vec_point_r.into_iter().map(|each| each.to_affine()).collect(),
            l: value.l,
            r: value.r,
        }
    }
}

impl <C:CurveArithmetic> From<BulletProofSerde<C>> for BulletProof<C>
where
    Scalar<C>: Serialize + DeserializeOwned,
    AffinePoint<C>: Serialize + DeserializeOwned
{
    fn from(value: BulletProofSerde<C>) -> Self {
        Self {
            target: ProjectivePoint::<C>::from(value.target),
            vec_point_l: value.vec_point_l.into_iter().map(|each| ProjectivePoint::<C>::from(each)).collect(),
            vec_point_r: value.vec_point_r.into_iter().map(|each| ProjectivePoint::<C>::from(each)).collect(),
            l: value.l,
            r: value.r,
        }
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::Field;
    use k256::{sha2::Sha256, ProjectivePoint, Scalar, Secp256k1};
    use rand::rngs::ThreadRng;

    use super::BulletProof;

    #[test]

    fn test_correctness() {
        for n in [1, 2, 4, 8, 16] {
            test_correctness_n(n);
        }
    }

    fn test_correctness_n(n: usize) {
        let mut rng = ThreadRng::default();
        let l: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let r: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let g: Vec<_> = (0..n).map(|_| ProjectivePoint::GENERATOR * Scalar::random(&mut rng)).collect();
        let h: Vec<_> = (0..n).map(|_| ProjectivePoint::GENERATOR * Scalar::random(&mut rng)).collect();

        let target: ProjectivePoint = (0..n).map(|i| g[i] * l[i] + h[i] * r[i]).sum();

        let proof = BulletProof::<Secp256k1>::prove::<Sha256>(&g, &h, &l, &r, &target);
        proof.verify::<Sha256>(&g, &h).unwrap();
        assert!(target == proof.target);
    }

    #[test]
    fn test_convertion_compact() {
        let n = 16;
        let mut rng = ThreadRng::default();
        let l: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let r: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let g: Vec<_> = (0..n).map(|_| ProjectivePoint::GENERATOR * Scalar::random(&mut rng)).collect();
        let h: Vec<_> = (0..n).map(|_| ProjectivePoint::GENERATOR * Scalar::random(&mut rng)).collect();

        let target: ProjectivePoint = (0..n).map(|i| g[i] * l[i] + h[i] * r[i]).sum();

        let proof = BulletProof::<Secp256k1>::prove::<Sha256>(&g, &h, &l, &r, &target);

        let proof_converted: BulletProof<Secp256k1> = bincode::deserialize(&bincode::serialize(&proof).unwrap()).unwrap();
        proof_converted.verify::<Sha256>(&g, &h).unwrap();
        assert!(target == proof_converted.target);
        assert!(proof_converted == proof);
    }
}