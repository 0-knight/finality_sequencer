use std::{time::Instant, mem::size_of, ops::Mul};
use halo2_proofs::arithmetic::{Field, CurveAffine};
use rand::{thread_rng, rngs::OsRng};
use rayon::prelude::*;

use halo2curves::{
    bn256::{Fr as Scalar, G1Affine as Affine, G1 as Point}, ff::FromUniformBytes, group::{Group, GroupEncoding},
};
use halo2curves::ff::PrimeField;
use halo2curves::group::Curve;

use halo2_pse::arithmetic::best_multiexp;


pub fn rand_vec_scalar(size: usize) -> Vec<Scalar> {
    let now = Instant::now();
    println! ( "Memory allocation ({} GB)", 
                (size * size_of::<Scalar>()) as f64 / 1.0e9);
    
    let mut result = vec![Scalar::zero(); size];
    println!("Randomizing...");

    result.par_chunks_mut(1024).for_each_init(
        || thread_rng(), 
        |rng, chunk| {
            for point in chunk {
                *point = Scalar::random(&mut *rng);
            }
        }
    );
    println!("Random generation took: {:?}", now.elapsed());
    result

}

pub fn schnorr_sequencer<C:CurveAffine, N: FromUniformBytes<64> + Ord>() {
    
    // Group Generator
    let g = C::generator();
    
    // User side : Private key - public key
    let k_u = <C as CurveAffine>::ScalarExt::random(OsRng);
    let P_u = (g * k_u).to_affine();
    // User side : random nonce and public nonce
    let r_u = <C as CurveAffine>::ScalarExt::random(OsRng);
    let R_u = (g * r_u).to_affine();

    // Sequencer side
        // Private key k_s, public key P_s
    let k_s = <C as CurveAffine>::ScalarExt::random(OsRng);
    let P_s = (g * k_s).to_affine();
        // random nonce r_s, public nonce R_s
    let r_s = <C as CurveAffine>::ScalarExt::random(OsRng);
    let R_s = (g * r_s).to_affine();

    // ==== WIP.. ==== //

        // calculate a challenge e 
        // 1. I = H ( P_u || P_s ), w_u = H ( I || P_u ) , w_s = H ( I || P_s )
    let cor = P_u.coordinates();
    let input_I = vec![P_u, P_s];
    //let I = poseidon_hash::<N>(input_I);
/*        
    let input_w_u = vec![I , P_u];
    let w_u = poseidon_hash(input_w_u);
        
    let input_w_s = vec![I, P_s];
    let w_s = poseidon_hash::<N>(input_w_s); 

        // 2. X = w_u * P_u + w_s * P_s
    let X = w_u * P_u + w_s * P_s;

        // 3. R = R_u + R_s
    let R = R_u + R_s;

        // 4. calculate a challenge e : e = H ( R || X || m || i)
    let index;
    let m;
    let input_challenge = vec![R, X, m, index];
    let e = poseidon_hash::<N>(input_challenge);

    // User side
        // partial signature : s_u = r_u + k_u * w_u * e
    let s_u = r_u + k_u * w_u * e;

    // Sequencer side
        // partial signature : s_s = r_s + k_s * w_s * e
    let s_s = r_s + k_s * w_s * e;

        // Full signature (s,R) = (s_u + s_s , R_u + R_s)
    let s = s_u + s_s;

    // === Smart Contract === //
    // verify the signature
    // check out the commitment to do with the index USING storage proof!!
*/

}


pub fn gen_key_pair<C: CurveAffine>() -> C {
    let g = C::generator();

    // generate a key pair
    let sk = <C as CurveAffine>::ScalarExt::random(OsRng);
    let public_key = (g * sk).to_affine();  // to_affine belongs to "use halo2curves::group::Curve"

    public_key
}



// FromUnitformBytes from halo2curves::ff::FromUniformBytes
pub fn poseidon_hash<N: FromUniformBytes<64> + Ord>(inputs: Vec<N>)
        -> N {
    // use halo2curves::bn256::Fr as BnScalar;
    use poseidon::Poseidon;

    // constants
    const T: usize = 5;
    const RATE: usize = 4;
    const R_F: usize = 8;
    const R_P: usize = 57;

    let mut poseidon = Poseidon::<N, T, RATE>::new(R_F, R_P);
    let number_of_permutation = 5;
    let number_of_input = RATE * number_of_permutation - 1;
/* 
    let inputs = (0..number_of_input)
                                .map(|_| N::random(OsRng))
                                .collect::<Vec<N>>();
*/
    poseidon.update(&inputs[..]);
    let result_0 = poseidon.squeeze();

    result_0
}


#[test]
pub fn test_gen_key() {

    use halo2curves::bn256::Fr as BnScalar;
    use halo2curves::bn256::G1Affine as G1Affine;


    let keys = gen_key_pair::<G1Affine>();
    let key_x = keys.x;
    let key_y = keys.y;
    println!("G1Affine: {:?}, x: {:?}, y: {:?}", keys, key_x, key_y);
}

#[test]
pub fn test_poseidon_hash() {
    
    use halo2curves::bn256::Fr as BnScalar;
    let inputs = (0..2).map(|_| BnScalar::random(OsRng))
                                            .collect::<Vec<BnScalar>>();
    
    let pHash = poseidon_hash(inputs);

    println!("poseidon hash : {:?}", pHash);

}

#[test]
pub fn test_conversion() {

    use halo2curves::bn256::{Fr, Fq};
    use halo2curves::bn256::G1 as Group;

    let fr_val = Fr::random(OsRng);
    let fq_val = Fq::random(OsRng);
    let g1_val = Group::generator();

    let tmp = g1_val * fr_val;
    let tmp_1 = g1_val.to_affine() * fr_val;
    let tmp_fq = Fq::from_repr(fr_val.to_repr()).unwrap();
    let tmp_fr = Fr::from_repr(tmp_fq.to_repr()).unwrap();
    let tmp_verify = g1_val * tmp_fr;

    println!("{:?}", tmp);
    println!("{:?}", tmp_1);
    println!("{:?}", tmp_verify)
}

#[test]
pub fn test_schnorr_sequencer() 
{

    use halo2curves::bn256::{Fr, Fq};
    use halo2curves::bn256::G1 as Group;
    use halo2curves::CurveExt;

    // transaction(message) and its hash!!
    let message_plain = Group::random(OsRng).to_affine();    
    let message = poseidon_hash(vec![message_plain.x, message_plain.y]);

    // Group Generator
    let g = Group::generator();

    // User side : Private key - public key
    //let k_u = <C as CurveAffine>::ScalarExt::random(OsRng);
    let k_u = Fr::random(OsRng);
    let P_u = (g * k_u).to_affine();    // doesn't work with Fq

    // User side : random nonce and public nonce
    let r_u = Fr::random(OsRng);
    let R_u = (g * r_u).to_affine();

    // Sequencer side
        // Private key k_s, public key P_s
    let k_s = Fr::random(OsRng);
    let P_s = (g * k_s).to_affine();
        // random nonce r_s, public nonce R_s
    let r_s = Fr::random(OsRng);
    let R_s = (g * r_s).to_affine();

        // calculate a challenge e 
        // 1. I = H ( P_u || P_s ), w_u = H ( I || P_u ) , w_s = H ( I || P_s )
    let input_I = vec![P_u.x, P_u.y, P_s.x, P_s.y];
    let I = poseidon_hash::<Fq>(input_I);
    
    // User side 
    let input_w_u = vec![I, P_u.x, P_u.y];
    let w_u = poseidon_hash(input_w_u);
    // Sequencer side
    let input_w_s = vec![I, P_s.x, P_s.y];
    let w_s = poseidon_hash(input_w_s);

    // X = w_u * P_u + w_s * P_s
    let X_x = w_s * P_u.x + w_s * P_s.x;
    let X_y = w_s * P_u.y + w_s * P_s.y;    // Is it correct way to multiply field * Group??

    // without to_affine, there's z value in the group
    // X is the weighted public key by the MuSig scheme
    let mut X = Group::generator().to_affine();
    X.x = X_x;
    X.y = X_y;
//    println!("{:?} {:?} {:?}", X_x, X_y, X);

    // Sequencer side
        // 5. Calculate R : R = R_u + R_s 
    let mut R = (R_u + R_s).to_affine();

        // 6. Calculate a challenge e with index i 
        // this means that the sequencer commits the transaction to index i
        // e = H ( R || X || m || i)
    let index = Fq::from(0);
    let input_e = vec![R.x, R.y, X.x, X.y, message, index];
    let e = poseidon_hash(input_e);

        // 7. Sequencer -> User : R_s, P_s, i

    // User side
        // create the partial signature s_u : s_u = r_u + k_u * w_u * e
        //let s_u : Fr = r_u + e * k_u.into() * w_u.into();  // [WIP] need to multiply 'Fr' with 'Fq'
        // r_u, k_u : scalar (Fr)
        // w_u, e : base field. (Fq)
    let w_u_fr = Fr::from_repr(w_u.to_repr()).unwrap(); // Fq -> Fr
    let e_fr = Fr::from_repr(e.to_repr()).unwrap();     // [WIP] Is it correct way to convert it? 
                                                            // even possible from Fr to Fq or either way?!
    //let s_u : Fr = e.mul(k_u.into());  // [WIP] need to multiply 'Fr' with 'Fq' [Done]
    //let s_u = e.mul(<Group as CurveExt>::ScalarExt::from(k_u));
    let s_u = r_u + k_u * w_u_fr * e_fr;
        // User -> Sequencer : s_u, message

    // Sequencer side
        // 8. Verify the partial signature from the user
        // s_u * g = R_u + w_u * P_u * e = r_u * G + w_u * (k_u * G) * e 
                                        // since s_u = r_u + w_u * k_u * e
    let verify_left_val = (g * s_u).to_affine();
    let right_x = R_u.x + (w_u * P_u.x * e);
    let right_y = R_u.y + (w_u * P_u.y * e);    // Is it correct way to multiply field * Group??
    let mut verify_right_val = Group::generator().to_affine();
    verify_right_val.x = right_x;
    verify_right_val.y = right_y;

    // converting into Fr then calculate.. [Result] No different from calculate in Fq type!!
    /*
    let tmp_x = Fr::from_repr(R_u.x.to_repr()).unwrap() + 
                    Fr::from_repr(w_u.to_repr()).unwrap() * Fr::from_repr(P_u.x.to_repr()).unwrap() * Fr::from_repr(e.to_repr()).unwrap();
    let tmp_y = Fr::from_repr(R_u.y.to_repr()).unwrap() + 
                    Fr::from_repr(w_u.to_repr()).unwrap() * Fr::from_repr(P_u.y.to_repr()).unwrap() * Fr::from_repr(e.to_repr()).unwrap();

    let mut tmp = Group::generator().to_affine();
    tmp.x = Fq::from_repr(tmp_x.to_repr()).unwrap();
    tmp.y = Fq::from_repr(tmp_y.to_repr()).unwrap();
    */

    println!("left : {:?}", verify_left_val);
    println!("right : {:?}", verify_right_val);
    // println!("tmp_fr : {:?}", verify_right_val);
    // assert_eq!(verify_left_val, verify_right_val);




        // 9. create the partial signature on the sequencing side.
        // s_s : s_s = r_s + k_s * w_s * e
    let w_s_fr = Fr::from_repr(w_s.to_repr()).unwrap();
    let e_fr = Fr::from_repr(e.to_repr()).unwrap();

    // let s_s = r_s * k_s; // [WIP] need to multiply 'Fr' with 'Fq' [Done]
    let s_s = r_s + k_s * w_s_fr * e_fr;


    //let verify_right_val = (R_u + tmp).to_affine();   // [WIP] need to multiply tmp with e
    //assert!(verify_left_val == verify_right_val);               // [WIP] verify!!

        // 9. create full signature!!
    let full_signature_s = s_u + s_s;
    let full_signature_R = (R_u + R_s).to_affine();

    println!("full signature : s = {:?}, R = {:?}", full_signature_s, full_signature_R);

    // ======== Call API to Smart contract on StarkNet ========//

}

#[test]
pub fn test_curve_feature() {
    use halo2curves::bn256::G1;
    use halo2curves::CurveExt;

    let projective_point = G1::random(OsRng);
    // let affine_point: G::AffineExt = projective_point.into();
    let affine_point: <halo2curves::bn256::G1 as CurveExt>::AffineExt = projective_point.into();

    // Converts this element into its byte encoding. This may or may not support encoding the identity.
    let projective_repr = projective_point.to_bytes();
    let affine_repr = affine_point.to_bytes();

    let projective_point_rec = G1::from_bytes(&projective_repr).unwrap();
    let affine_point_rec = G1::from_bytes_unchecked(&affine_repr).unwrap();

}

#[test]
pub fn test_multiplication() {

    use halo2curves::bn256::G1 as G;
    use halo2curves::CurveExt;

    let s1 = <halo2curves::bn256::G1 as CurveExt>::ScalarExt::random(OsRng);
    //let s1 = G::random(OsRng);
    let s2 = <halo2curves::bn256::G1 as CurveExt>::ScalarExt::random(OsRng);

    let t0 = G::identity() * s1;
    assert!(bool::from(t0.is_identity()));

    let a = G::random(OsRng);
    //let t0 = a * G::ScalarExt::ONE;
    let t0 = a * <halo2curves::bn256::G1 as CurveExt>::ScalarExt::ONE;
    assert_eq!(a, t0);

    let t0 = a * <halo2curves::bn256::G1 as CurveExt>::ScalarExt::ZERO;
    assert!(bool::from(t0.is_identity()));

    let t0 = a * s1 + a * s2;

    let s3 = s1 + s2;
    let t1 = a * s3;

    assert_eq!(t0, t1);

    let mut t0 = a * s1;
    let mut t1 = a * s2;
    t0 += t1;
    let s3 = s1 + s2;
    t1 = a * s3;
    assert_eq!(t0, t1);
}