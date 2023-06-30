
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
#[derive(Clone)]
pub struct SecretKey(Scalar);
impl SecretKey {
    pub fn inner(&self) -> Scalar {
        self.0                      // [WIP] ??
    }

    pub fn random(rng : &mut (impl CryptoRng + RngCore)) -> Self {
        Self(Scalar::random(rng))
    }
}


// == Signature == //
pub struct PublicKey(Point);
impl PublicKey {
    pub fn inner(&self) -> Point {
        self.0
    }

    pub fn from_secret( s: SecretKey) -> Self {
        let p = nk_generator() * s.inner();
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

pub struct SharedValue {
    hash_pubs : Base,   // hash value of the public key sets
    challenge : Base,   // challenge e : e = H (R | X | m | index)
}


// Trait for secret keys that implements a signature creation
pub trait SchnorrSecret {
    // Sign a given message, using 'rng' as source of randomness
    fn sign(&self, rng: &mut (impl CryptoRng + RngCore), message: &[u8;32]) -> Signature;
    fn sign_ext(&self, rng: &mut (impl CryptoRng + RngCore), message: &[u8;32], 
                nonce : Scalar, weight_factor : Base, challenge : Base, ) -> Signature;
    
}

pub trait SchnorrPublic {
    // Verify a given message is valid given a signature
    fn verify(&self, message: &[u8;32], signature: &Signature) -> bool;
    fn verify_ext(&self, message: &[u8;32], signature: &Signature, weight_factor : Base, challenge: Base) -> bool;
    
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
        let response = mask + mod_r_p(challenge) * self.inner();

        Signature { commit, response }
    }

    fn sign_ext(&self, rng: &mut (impl CryptoRng + RngCore), message: &[u8;32], 
                nonce : Scalar, weight_factor : Base, challenge : Base, ) -> Signature {
        let commit = nk_generator() * nonce;

        // s_a = r_a + k_a * w_a * e
        let response = nonce + self.0 * mod_r_p(weight_factor) * mod_r_p(challenge);

        Signature { commit, response }
    }



}

impl SchnorrPublic for PublicKey {
    fn verify(&self, message: &[u8;32], signature: &Signature) -> bool {

        let message_base = Base::from_bytes(message.into()).unwrap();

        let challenge = poseidon_hash(vec![signature.commit.x, signature.commit.y, message_base ]);
        nk_generator() * signature.response - self.inner() * mod_r_p(challenge) == signature.commit
    }
    // public_nonce: Base is replaced by commit : nonce * G
    fn verify_ext(&self, message: &[u8;32], signature: &Signature, weight_factor : Base, challenge: Base) -> bool {

        //sG == R + e(wkG) = R + ePw
        nk_generator() * signature.response - (self.inner() * mod_r_p(weight_factor) * mod_r_p(challenge)) == signature.commit 

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

#[test]
fn test_schnorr_sig_ext() {
    // User
    let k_u = SecretKey::random(&mut OsRng);
    let P_u = PublicKey::from_secret(k_u.clone());
    let r_u = SecretKey::random(&mut OsRng).inner();        // random nonce : Scalar
    let R_u = PublicKey::from_secret(SecretKey((r_u))).inner(); // public Nonce : Point

    // Sequencer
    let k_s = SecretKey::random(&mut OsRng);
    let P_s = PublicKey::from_secret(k_s.clone());
    let r_s = SecretKey::random(&mut OsRng).inner();        // random nonce : Scalar
    let R_s = PublicKey::from_secret(SecretKey((r_u))).inner(); // public Nonce : Point

    let R = R_u + R_s;
    let l = poseidon_hash(vec![P_u.inner().x , P_u.inner().y, P_s.inner().x, P_s.inner().y]); // Base Field
    let w_u = poseidon_hash(vec![l , P_u.inner().x, P_u.inner().y ]);
    let w_s = poseidon_hash(vec![l, P_s.inner().x, P_s.inner().y]);
    
    let message: &[u8;32] = &[1;32];
    let message_base = Base::from_bytes(message.into()).unwrap();

    let X = P_u.inner() * mod_r_p(w_u) + P_s.inner() * mod_r_p(w_s);     // w_u * P_u doesn't work!!!
    let e = poseidon_hash(vec![R.x, R.y, X.x, X.y, message_base, Base::from(0)]);

/*
fn sign_ext(&self, rng: &mut (impl CryptoRng + RngCore), message: &[u8;32], 
                nonce : Scalar, weight_factor : Base, challenge : Base, ) -> Signature {
 */
    let signature_u = k_u.sign_ext(&mut OsRng, message, r_u, w_u, e);
    assert!(P_u.verify_ext(message, &signature_u, w_u, e));

    let signature_s = k_s.sign_ext(&mut OsRng, message, r_s, w_s, e);
    assert!(P_s.verify_ext(message, &signature_s, w_s, e));

    // full schnorr signature
    let signature = Signature{
            response : signature_s.response + signature_u.response,    // Scalar - signature
            commit : signature_s.commit + signature_u.commit,
    };

    // The process below should be done in a smart contract..
    // (s - s_u) * G == (R - R_u) + e (X - w_u * P_u)
    let left = nk_generator() * (signature.response - signature_u.response);
    let right = (signature.commit - signature_u.commit) 
                    + (X - P_u.inner() * mod_r_p(w_u)) * mod_r_p(e);
    assert_eq!(left, right)

}
