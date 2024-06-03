use std::array;

use digest::{Digest, FixedOutput};
use elliptic_curve::{group::{Curve, GroupEncoding}, ops::Reduce, AffinePoint, CurveArithmetic, Field, FieldBytes, FieldBytesSize, Group, PrimeField, ProjectivePoint, Scalar};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{bulletproof::BulletProof, schnorr::SchnorrSignature};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(bound = "Scalar<C>: Serialize + DeserializeOwned, AffinePoint<C>: Serialize + DeserializeOwned", from = "IncognitoParamsSerde<C, MAXN>", into = "IncognitoParamsSerde<C, MAXN>")]
pub struct IncognitoParams<C: CurveArithmetic, const MAXN: usize> {
    g: ProjectivePoint<C>,
    h: ProjectivePoint<C>,
    vec_g: [ProjectivePoint<C>; MAXN],
    vec_h: [ProjectivePoint<C>; MAXN]
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "Scalar<C>: Serialize + DeserializeOwned, AffinePoint<C>: Serialize + DeserializeOwned")]
struct IncognitoParamsSerde<C: CurveArithmetic, const MAXN: usize> {
    g: AffinePoint<C>,
    h: AffinePoint<C>,
    vec_g: Vec<AffinePoint<C>>,
    vec_h: Vec<AffinePoint<C>>
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(bound = "Scalar<C>: Serialize + DeserializeOwned, AffinePoint<C>: Serialize + DeserializeOwned", from = "IncognitoSignatureSerde<C>", into = "IncognitoSignatureSerde<C>")]
pub struct IncognitoSignature<C: CurveArithmetic> {
    point_r: ProjectivePoint<C>,
    point_c_pk: ProjectivePoint<C>,
    point_r_z: ProjectivePoint<C>,
    s_z: Scalar<C>,
    s_beta: Scalar<C>,
    point_a: ProjectivePoint<C>,
    point_s: ProjectivePoint<C>,
    point_s_pk: ProjectivePoint<C>,
    point_t1: ProjectivePoint<C>,
    point_t2: ProjectivePoint<C>,
    taux: Scalar<C>,
    mu: Scalar<C>,
    nu: Scalar<C>,
    tx: Scalar<C>,
    bulletproof: BulletProof<C>
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "Scalar<C>: Serialize + DeserializeOwned, AffinePoint<C>: Serialize + DeserializeOwned")]
struct IncognitoSignatureSerde<C: CurveArithmetic> {
    point_r: AffinePoint<C>,
    point_c_pk: AffinePoint<C>,
    point_r_z: AffinePoint<C>,
    s_z: Scalar<C>,
    s_beta: Scalar<C>,
    point_a: AffinePoint<C>,
    point_s: AffinePoint<C>,
    point_s_pk: AffinePoint<C>,
    point_t1: AffinePoint<C>,
    point_t2: AffinePoint<C>,
    taux: Scalar<C>,
    mu: Scalar<C>,
    nu: Scalar<C>,
    tx: Scalar<C>,
    bulletproof: BulletProof<C>
}

impl <C: CurveArithmetic, const MAXN: usize> IncognitoParams<C, MAXN> 
where
    ProjectivePoint<C>: GroupEncoding,
    Scalar<C>: Serialize + DeserializeOwned,
    AffinePoint<C>: Serialize + DeserializeOwned
{
    pub fn new() -> Self {
        let mut rng = rand::rngs::ThreadRng::default();
        Self {
            g: ProjectivePoint::<C>::random(&mut rng),
            h: ProjectivePoint::<C>::random(&mut rng),
            vec_g: array::from_fn(|_| {
                ProjectivePoint::<C>::random(&mut rng)
            }),
            vec_h: array::from_fn(|_| {
                ProjectivePoint::<C>::random(&mut rng)
            })
        }
    }

    #[inline]
    fn build_vec_yn(n: usize, y: &Scalar<C>) -> Vec<Scalar<C>> {
        let mut vec_yn = Vec::new();
        let mut cur = Scalar::<C>::ONE;
        for _ in 0..n {
            vec_yn.push(cur);
            cur *= y;
        }
        vec_yn
    }

    #[inline]
    fn challenge_cz<D>(commitment_pk_mask: &ProjectivePoint<C>, commitment_pk: &ProjectivePoint<C>) -> Scalar<C>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let digest = D::new()
            .chain_update(commitment_pk_mask.to_bytes())
            .chain_update(commitment_pk.to_bytes())
            .finalize_fixed();
        let fieldbytes = digest as FieldBytes<C>;
        <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(&fieldbytes)
    }

    #[inline]
    fn challenge_y<D>(
        point_g: &ProjectivePoint<C>,
        point_a: &ProjectivePoint<C>,
        point_s: &ProjectivePoint<C>,
        point_s_pk: &ProjectivePoint<C>,
        point_c_pk: &ProjectivePoint<C>
    ) -> Scalar<C>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let digest = D::new()
            .chain_update(point_g.to_bytes())
            .chain_update(point_a.to_bytes())
            .chain_update(point_s.to_bytes())
            .chain_update(point_s_pk.to_bytes())
            .chain_update(point_c_pk.to_bytes())
            .chain_update(&[0])
            .finalize_fixed();
        let fieldbytes = digest as FieldBytes<C>;
        <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(&fieldbytes)
    }

    #[inline]
    fn challenge_w<D>(
        point_g: &ProjectivePoint<C>,
        point_a: &ProjectivePoint<C>,
        point_s: &ProjectivePoint<C>,
        point_s_pk: &ProjectivePoint<C>,
        point_c_pk: &ProjectivePoint<C>
    ) -> Scalar<C>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let digest = D::new()
            .chain_update(point_g.to_bytes())
            .chain_update(point_a.to_bytes())
            .chain_update(point_s.to_bytes())
            .chain_update(point_s_pk.to_bytes())
            .chain_update(point_c_pk.to_bytes())
            .chain_update(&[1])
            .finalize_fixed();
        let fieldbytes = digest as FieldBytes<C>;
        <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(&fieldbytes)
    }

    #[inline]
    fn challenge_x<D>(
        point_t1: &ProjectivePoint<C>,
        point_t2: &ProjectivePoint<C>,
        y: &Scalar<C>,
        w: &Scalar<C>,
    ) -> Scalar<C>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let digest = D::new()
            .chain_update(point_t1.to_bytes())
            .chain_update(point_t2.to_bytes())
            .chain_update(y.to_repr())
            .chain_update(w.to_repr())
            .finalize_fixed();
        let fieldbytes = digest as FieldBytes<C>;
        <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(&fieldbytes)
    }

    #[inline]
    fn challenge_d<D>(
        x: &Scalar<C>,
        taux: &Scalar<C>,
        mu: &Scalar<C>,
        nu: &Scalar<C>,
        tx: &Scalar<C>,
    ) -> Scalar<C>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let digest = D::new()
            .chain_update(x.to_repr())
            .chain_update(taux.to_repr())
            .chain_update(mu.to_repr())
            .chain_update(nu.to_repr())
            .chain_update(tx.to_repr())
            .finalize_fixed();
        let fieldbytes = digest as FieldBytes<C>;
        <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(&fieldbytes)
    }

    pub fn convert<D>(
        &self,
        pks: &[ProjectivePoint<C>],
        message: &[u8],
        signature: &SchnorrSignature<C>,
        index: usize
    ) -> anyhow::Result<IncognitoSignature<C>>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        anyhow::ensure!(pks.len() <= MAXN);
        anyhow::ensure!(index < pks.len());

        let mut rng = rand::rngs::ThreadRng::default();
        let beta = Scalar::<C>::random(&mut rng);
        let point_c_pk = self.g * &beta + pks[index];

        let r_z = Scalar::<C>::random(&mut rng);
        let r_beta = Scalar::<C>::random(&mut rng);
        let c = SchnorrSignature::<C>::challenge::<D>(&signature.point_r, message);

        let point_r_z = ProjectivePoint::<C>::generator() * r_z + self.g * r_beta * c;
        let c_z = Self::challenge_cz::<D>(&point_r_z, &point_c_pk);

        let s_z = r_z + c_z * signature.z;
        let s_beta = r_beta + c_z * beta;

        let alpha = Scalar::<C>::random(&mut rng);
        let rho = Scalar::<C>::random(&mut rng);
        let zeta = Scalar::<C>::random(&mut rng);

        let n = pks.len();
        let vec_s_a = (0..n).map(|_| Scalar::<C>::random(&mut rng)).collect::<Vec<_>>();
        let vec_s_b = (0..n).map(|_| Scalar::<C>::random(&mut rng)).collect::<Vec<_>>();

        let vec_b: Vec<_> = (0..n).map(|i| if i == index { Scalar::<C>::ONE } else { Scalar::<C>::ZERO }).collect();
        let vec_a: Vec<_> = vec_b.iter().map(|bi| *bi - Scalar::<C>::ONE).collect();

        let mut point_a = self.h * alpha;
        for i in 0..n {
            point_a += self.vec_g[i] * vec_b[i];
            point_a += self.vec_h[i] * vec_a[i];
        }
        let mut point_s = self.h * rho;
        for i in 0..n {
            point_s += self.vec_g[i] * vec_s_b[i];
            point_s += self.vec_h[i] * vec_s_a[i];
        }
        let mut point_s_pk = self.g * zeta;
        for i in 0..n {
            point_s_pk += pks[i] * vec_s_b[i];
        }

        let y = Self::challenge_y::<D>(&self.g, &point_a, &point_s, &point_s_pk, &point_c_pk);
        let w = Self::challenge_w::<D>(&self.g, &point_a, &point_s, &point_s_pk, &point_c_pk);

        let vec_yn: Vec<<C as CurveArithmetic>::Scalar> = Self::build_vec_yn(n, &y);
        let mut t1 = Scalar::<C>::ZERO;
        let mut t2 = Scalar::<C>::ZERO;
        for i in 0..n {
            t1 += vec_s_b[i] * (vec_yn[i] * (vec_a[i] + w) + w * w);
            t1 += (vec_b[i] - w) * (vec_yn[i] * vec_s_a[i]);
            t2 += vec_s_b[i] * vec_yn[i] * vec_s_a[i];
        }

        let tau1 = Scalar::<C>::random(&mut rng);
        let tau2 = Scalar::<C>::random(&mut rng);
        let point_t1 = ProjectivePoint::<C>::generator() * t1 + self.h * tau1;
        let point_t2 = ProjectivePoint::<C>::generator() * t2 + self.h * tau2;

        let x = Self::challenge_x::<D>(&point_t1, &point_t2, &y, &w);
        let taux = tau2 * x * x + tau1 * x;
        let mu = alpha + rho * x;
        let nu = beta + zeta * x;

        let vec_l: Vec<_> = (0..n).map(|i| (vec_b[i] - w) + vec_s_b[i] * x).collect();
        let vec_r: Vec<_> = (0..n).map(|i| vec_yn[i] * (vec_a[i] + w + vec_s_a[i] * x) + w * w).collect();
        let tx = (0..n).map(|i| vec_l[i] * vec_r[i]).sum();

        #[cfg(debug_assertions)]
        {
            let mut scalar_n = Scalar::<C>::ZERO;
            let mut scalar_sum_yn = Scalar::<C>::ZERO;
            for i in 0..n {
                scalar_n += Scalar::<C>::ONE;
                scalar_sum_yn += vec_yn[i];
            }
            let t0 = w * w - w * w * w * scalar_n + (w - w * w) * scalar_sum_yn;
            debug_assert_eq!(tx, t0 + t1 * x + t2 * x * x);
        }

        let d = Self::challenge_d::<D>(&x, &taux, &mu, &nu, &tx);

        let vec_yn_inv: Vec<<C as CurveArithmetic>::Scalar> = Self::build_vec_yn(n, &y.invert().unwrap());
        let bulletproof_base1: Vec<_> = (0..n).map(|i| self.vec_g[i] + pks[i] * d). collect();
        let bulletproof_base2: Vec<_> = (0..n).map(|i| self.vec_h[i] * vec_yn_inv[i]). collect();
        // Proving exists l and r such that P = g ^ l h ^ r and c = <l, r>
        let bulletproof_target: ProjectivePoint::<C> = (0..n).map(|i| {
            (self.vec_g[i] + pks[i] * d) * vec_l[i] + self.vec_h[i] * vec_yn_inv[i] * vec_r[i]
        }).sum();
        let bulletproof = BulletProof::<C>::prove::<D>(&bulletproof_base1, &bulletproof_base2, &vec_l, &vec_r, &bulletproof_target);

        Ok(IncognitoSignature {
            point_c_pk,
            point_r: signature.point_r,
            point_r_z,
            s_z,
            s_beta,
            point_a,
            point_s,
            point_s_pk,
            point_t1,
            point_t2,
            taux,
            mu,
            nu,
            tx,
            bulletproof
        })
    }

    pub fn verify<D>(
        &self,
        pks: &[ProjectivePoint<C>],
        message: &[u8],
        signature: &IncognitoSignature<C>
    ) -> anyhow::Result<()>
    where
        D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>
    {
        let n = pks.len();

        let IncognitoSignature {
            point_c_pk,
            point_r,
            point_r_z,
            s_z,
            s_beta,
            point_a,
            point_s,
            point_s_pk,
            point_t1,
            point_t2,
            taux,
            mu,
            nu,
            tx,
            bulletproof
        } = signature;

        let c = SchnorrSignature::<C>::challenge::<D>(&signature.point_r, message);

        let c_z = Self::challenge_cz::<D>(&point_r_z, &point_c_pk);
        let y = Self::challenge_y::<D>(&self.g, &point_a, &point_s, &point_s_pk, &point_c_pk);
        let w = Self::challenge_w::<D>(&self.g, &point_a, &point_s, &point_s_pk, &point_c_pk);



        anyhow::ensure!(
            ProjectivePoint::<C>::generator() * s_z + self.g * s_beta * c == *point_r_z + *point_r * c_z + *point_c_pk * c_z * c
        );

        let x = Self::challenge_x::<D>(&point_t1, &point_t2, &y, &w);

        let mut scalar_n = Scalar::<C>::ZERO;
        let mut scalar_sum_yn = Scalar::<C>::ZERO;
        let mut yn = Scalar::<C>::ONE;
        for _ in 0..n {
            scalar_n += Scalar::<C>::ONE;
            scalar_sum_yn += yn;

            yn *= y;
        }
        let t0 = w * w - w * w * w * scalar_n + (w - w * w) * scalar_sum_yn;
        anyhow::ensure!(
            ProjectivePoint::<C>::generator() * tx + self.h * taux == ProjectivePoint::<C>::generator() * t0 + *point_t1 * x + *point_t2 * x * x
        );

        let vec_yn: Vec<<C as CurveArithmetic>::Scalar> = Self::build_vec_yn(n, &y);
        let vec_yn_inv: Vec<<C as CurveArithmetic>::Scalar> = Self::build_vec_yn(n, &y.invert().unwrap());
        let d = Self::challenge_d::<D>(&x, &taux, &mu, &nu, &tx);
        let point_1 = self.g * d * nu + self.h * mu;
        let mut point_2 = *point_a + *point_s * x + *point_c_pk * d + *point_s_pk * x * d;
        for i in 0..n {
            point_2 += (self.vec_g[i] + pks[i] * d) * (-w);
            point_2 += (self.vec_h[i] * vec_yn_inv[i]) * (w * vec_yn[i] + w * w);
        }

        // let bullet_target: ProjectivePoint::<C> = (0..n).map(|i| {
        //     (self.vec_g[i] + pks[i] * d) * vec_l[i] + self.vec_h[i] * vec_yn_inv[i] * vec_r[i]
        // }).sum();
        let bulletproof_base1: Vec<_> = (0..n).map(|i| self.vec_g[i] + pks[i] * d). collect();
        let bulletproof_base2: Vec<_> = (0..n).map(|i| self.vec_h[i] * vec_yn_inv[i]). collect();
        bulletproof.verify::<D>(&bulletproof_base1, &bulletproof_base2)?;

        anyhow::ensure!(
            point_1 + bulletproof.target == point_2
        );

        Ok(())
    }
}

impl <C: CurveArithmetic, const MAXN: usize> From<IncognitoParamsSerde<C, MAXN>> for IncognitoParams<C, MAXN> {
    fn from(value: IncognitoParamsSerde<C, MAXN>) -> Self {
        Self {
            g: ProjectivePoint::<C>::from(value.g),
            h: ProjectivePoint::<C>::from(value.h),
            vec_g: value.vec_g.into_iter().map(|each| ProjectivePoint::<C>::from(each)).collect::<Vec<_>>().try_into().unwrap(),
            vec_h: value.vec_h.into_iter().map(|each| ProjectivePoint::<C>::from(each)).collect::<Vec<_>>().try_into().unwrap(),
        }
    }
}

impl <C: CurveArithmetic, const MAXN: usize> From<IncognitoParams<C, MAXN>> for IncognitoParamsSerde<C, MAXN> {
    fn from(value: IncognitoParams<C, MAXN>) -> Self {
        Self {
            g: value.g.to_affine(),
            h: value.h.to_affine(),
            vec_g: value.vec_g.into_iter().map(|each| each.to_affine()).collect(),
            vec_h: value.vec_h.into_iter().map(|each| each.to_affine()).collect(),
        }
    }
}

impl <C: CurveArithmetic> From<IncognitoSignatureSerde<C>> for IncognitoSignature<C> {
    fn from(value: IncognitoSignatureSerde<C>) -> Self {
        Self {
            point_r: ProjectivePoint::<C>::from(value.point_r),
            point_c_pk: ProjectivePoint::<C>::from(value.point_c_pk),
            point_r_z: ProjectivePoint::<C>::from(value.point_r_z),
            s_z: value.s_z,
            s_beta: value.s_beta,
            point_a: ProjectivePoint::<C>::from(value.point_a),
            point_s: ProjectivePoint::<C>::from(value.point_s),
            point_s_pk: ProjectivePoint::<C>::from(value.point_s_pk),
            point_t1: ProjectivePoint::<C>::from(value.point_t1),
            point_t2: ProjectivePoint::<C>::from(value.point_t2),
            taux: value.taux,
            mu: value.mu,
            nu: value.nu,
            tx: value.tx,
            bulletproof: value.bulletproof,
        }
    }
}

impl <C: CurveArithmetic> From<IncognitoSignature<C>> for IncognitoSignatureSerde<C> {
    fn from(value: IncognitoSignature<C>) -> Self {
        Self {
            point_r: value.point_r.to_affine(),
            point_c_pk: value.point_c_pk.to_affine(),
            point_r_z: value.point_r_z.to_affine(),
            s_z: value.s_z,
            s_beta: value.s_beta,
            point_a: value.point_a.to_affine(),
            point_s: value.point_s.to_affine(),
            point_s_pk: value.point_s_pk.to_affine(),
            point_t1: value.point_t1.to_affine(),
            point_t2: value.point_t2.to_affine(),
            taux: value.taux,
            mu: value.mu,
            nu: value.nu,
            tx: value.tx,
            bulletproof: value.bulletproof,
        }
    }
}

// impl <C: CurveArithmetic, const MAXN: usize> Serialize for IncognitoParams<C, MAXN> 
// where
//     AffinePoint<C>: Serialize + DeserializeOwned
// {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer {
//         let mut state = serializer.serialize_struct("IncognitoParams", 4)?;
//         state.serialize_field("g", &self.g.to_affine())?;
//         state.serialize_field("h", &self.h.to_affine())?;
//         state.serialize_field("vec_g", &self.vec_g.iter().map(|each| each.to_affine()).collect::<Vec<_>>())?;
//         state.serialize_field("vec_h", &self.vec_g.iter().map(|each| each.to_affine()).collect::<Vec<_>>())?;
//         state.end()
//     }
// }

// impl<'de, C: CurveArithmetic, const MAXN: usize> Deserialize<'de> for IncognitoParams<C, MAXN>
// where
//     AffinePoint<C>: Deserialize<'de>
// {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de> {
//         #[derive(Deserialize)]
//         #[serde(field_identifier, rename_all = "snake_case")]
//         enum Field { G, H, VecG, VecH }

//         struct SignatureVisitor<C: CurveArithmetic, const MAXN: usize> {
//             _phantom1: PhantomData<C>,
//         }

//         impl <'de, C: CurveArithmetic, const MAXN: usize> Visitor<'de> for SignatureVisitor<C, MAXN> 
//         where
//             AffinePoint<C>: Deserialize<'de>
//         {
//             type Value = IncognitoParams::<C, MAXN>;
        
//             fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
//                 formatter.write_str("Incognito Params")
//             }

//             fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
//                 where
//                     A: serde::de::SeqAccess<'de>, {
                
//                 let g = ProjectivePoint::<C>::from(seq.next_element::<AffinePoint<C>>()?.ok_or_else(|| de::Error::invalid_length(0, &self))?);
//                 let h = ProjectivePoint::<C>::from(seq.next_element::<AffinePoint<C>>()?.ok_or_else(|| de::Error::invalid_length(1, &self))?);
//                 let vec_g = seq
//                     .next_element::<Vec<AffinePoint<C>>>()?
//                     .ok_or_else(|| de::Error::invalid_length(2, &self))?
//                     .into_iter()
//                     .map(|each| ProjectivePoint::<C>::from(each))
//                     .collect::<Vec<_>>()
//                     .try_into().map_err(|_| de::Error::custom("invalid data for [Point; MAXN]"))?;
//                 let vec_h = seq
//                     .next_element::<Vec<AffinePoint<C>>>()?
//                     .ok_or_else(|| de::Error::invalid_length(3, &self))?
//                     .into_iter()
//                     .map(|each| ProjectivePoint::<C>::from(each))
//                     .collect::<Vec<_>>()
//                     .try_into().map_err(|_| de::Error::custom("invalid data for [Point; MAXN]"))?;
//                 Ok(IncognitoParams{
//                     g,
//                     h,
//                     vec_g,
//                     vec_h
//                 })
                
//             }

//             fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
//                 where
//                     A: serde::de::MapAccess<'de>, {
//                 let mut g = None;
//                 let mut h = None;
//                 let mut vec_g = None;
//                 let mut vec_h = None;

//                 while let Some(key) = map.next_key::<Field>()? {
//                     match key {
//                         Field::G => {
//                             if g.is_some() {
//                                 return Err(de::Error::duplicate_field("g"))
//                             }
//                             g = Some(ProjectivePoint::<C>::from(map.next_value::<AffinePoint<C>>()?));
//                         },
//                         Field::H => {
//                             if h.is_some() {
//                                 return Err(de::Error::duplicate_field("h"))
//                             }
//                             h = Some(ProjectivePoint::<C>::from(map.next_value::<AffinePoint<C>>()?));
//                         },
//                         Field::VecG => {
//                             if vec_g.is_some() {
//                                 return Err(de::Error::duplicate_field("vec_g"))
//                             }
//                             vec_g = Some(
//                                 map.next_value::<Vec<AffinePoint<C>>>()?.into_iter()
//                                 .map(|each| ProjectivePoint::<C>::from(each))
//                                 .collect::<Vec<_>>()
//                                 .try_into().map_err(|_| de::Error::custom("invalid data for [Point; MAXN]"))?
//                             );
//                         },
//                         Field::VecH => {
//                             if vec_h.is_some() {
//                                 return Err(de::Error::duplicate_field("vec_h"))
//                             }
//                             vec_h = Some(
//                                 map.next_value::<Vec<AffinePoint<C>>>()?.into_iter()
//                                 .map(|each| ProjectivePoint::<C>::from(each))
//                                 .collect::<Vec<_>>()
//                                 .try_into().map_err(|_| de::Error::custom("invalid data for [Point; MAXN]"))?
//                             );
//                         }
//                     }
//                 }

//                 Ok(IncognitoParams{
//                     g: g.ok_or_else(|| de::Error::missing_field("g"))?,
//                     h: h.ok_or_else(|| de::Error::missing_field("h"))?,
//                     vec_g: vec_g.ok_or_else(|| de::Error::missing_field("vec_g"))?,
//                     vec_h: vec_h.ok_or_else(|| de::Error::missing_field("vec_h"))?,
//                 })
//             }

//         }

//         const FIELDS: &'static [&'static str] = &["g", "h", "vec_g", "vec_h"];
//         deserializer.deserialize_struct("IncognitoParams", FIELDS, SignatureVisitor::<C, MAXN>{_phantom1: PhantomData::default()})
//     }
// }

#[cfg(test)]
mod tests {
    use elliptic_curve::Field;
    use k256::{sha2::Sha256, ProjectivePoint, Scalar, Secp256k1};
    use rand::{rngs::ThreadRng, Rng};

    use crate::{incognito::IncognitoSignature, schnorr::SchnorrSignature};

    use super::IncognitoParams;

    #[test]

    fn test_correctness() {
        for n in [1, 2, 4, 8, 16] {
            let i = ThreadRng::default().gen_range(0..n);
            test_correctness_n(n, i);
        }
    }

    fn test_correctness_n(n: usize, index: usize) {
        let mut rng = ThreadRng::default();
        let params = IncognitoParams::<Secp256k1, 256>::new();
        let sks: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let pks: Vec<_> = sks.iter().map(|s| ProjectivePoint::GENERATOR * s).collect();

        let message = [0, 3, 6, 9];
        let signature = SchnorrSignature::<Secp256k1>::sign::<Sha256>(&sks[index], &message);

        signature.verify::<Sha256>(&pks[index], &message).unwrap();

        let incsig = params.convert::<Sha256>(&pks, &message, &signature, index).unwrap();
        params.verify::<Sha256>(&pks, &message, &incsig).unwrap();
    }

    #[test]

    fn test_serialization() {
        let n = 256;
        let index = 128;
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
        assert_eq!(params, params_new);
    }
}