
use halo2_proofs::arithmetic::Field;
use halo2_pse::plonk::Challenge;
use halo2curves::CurveAffine;
use halo2curves::bn256::G1 as Point;
use halo2curves::bn256::G1Affine as PointAffine;
use halo2curves::bn256::Fr as Scalar;
use halo2curves::bn256::Fq as Base;

use halo2curves::ff::PrimeField;
use halo2curves::group::Group;
use rand::CryptoRng;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::halo2::poseidon_hash;

// ============= //

pub fn nk_generator() -> PointAffine {
    PointAffine::from_xy(
        Base::one() ,   // G1_GENERATOR_X
        Base::from_raw([2,0,0,0]), // Fq::from_raw([2, 0, 0, 0]); 
    ).unwrap()
}


// == Key pair == //
pub struct SecretKey(Base);
impl SecretKey {
    pub fn inner(&self) -> Base {
        self.0                      // [WIP] ??
    }

    pub fn random(rng : &mut (impl CryptoRng + RngCore)) -> Self {
        Self(Base::random(rng))
    }
}


// == Signature == //
pub struct PublicKey(Point);
impl PublicKey {
    pub fn inner(&self) -> Point {
        self.0
    }

    pub fn from_secret( s: SecretKey) -> Self {
        let p = nk_generator() * mod_r_p(s.inner());
        Self(p)
    }
}


#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Signature {
    commit : Point,
    response : Scalar,
}

impl Signature {
    // return a dummy identity 'Signature'
    pub fn dummy() -> Self {
        Self { commit : Point::identity(), response : Scalar::zero() }
    }
}

// Trait for secret keys that implements a signature creation
pub trait SchnorrSecret {
    // Sign a given message, using 'rng' as source of randomness
    fn sign(&self, rng: &mut (impl CryptoRng + RngCore), message: &[u8;32]) -> Signature;
}

pub trait SchnorrPublic {
    // Verify a given message is valid given a signature
    fn verify(&self, message: &[u8;32], signature: &Signature) -> bool;
}

// Convert from Base to Scalar (aka $x \pmod{r_\mathbb{P}}$)
// Pallars : This requires no modular reduction because the base field is smaller than the scalar field.
pub fn mod_r_p(x: Base) -> Scalar {
    Scalar::from_repr(x.to_repr()).unwrap()
}

impl SchnorrSecret for SecretKey {
    fn sign(&self, rng: &mut (impl CryptoRng + RngCore), message: &[u8;32]) -> Signature {
        //todo!()
        let mask = Scalar::random(rng);
        let commit = nk_generator() * mask; //  G1Affine (Base??) * Fr (Scalar)

        let message_base = Base::from_bytes(message.into()).unwrap();

        // generate a challenge e
        let challenge = poseidon_hash(vec![commit.x, commit.y, message_base]);
        let response = mask + mod_r_p(challenge) * mod_r_p(self.inner());

        Signature { commit, response }
    }
}

impl SchnorrPublic for PublicKey {
    fn verify(&self, message: &[u8;32], signature: &Signature) -> bool {

        let message_base = Base::from_bytes(message.into()).unwrap();

        let challenge = poseidon_hash(vec![signature.commit.x, signature.commit.y, message_base ]);
        nk_generator() * signature.response - self.inner() * mod_r_p(challenge) == signature.commit
    }
}

#[test]
fn test_schnorr_sig() {
    let secret = SecretKey::random(&mut OsRng);
    let message: &[u8;32] = &[1;32];
    let signature = secret.sign(&mut OsRng, message);
    let public = PublicKey::from_secret(secret);
    assert!(public.verify(message, &signature));
}
