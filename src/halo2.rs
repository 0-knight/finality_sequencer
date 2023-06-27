use std::{time::Instant, mem::size_of, ops::Mul};
use halo2_proofs::arithmetic::{Field, CurveAffine};
use rand::{thread_rng, rngs::OsRng};
use rayon::prelude::*;

use halo2curves::{
    bn256::{Fr as Scalar, G1Affine as Affine, G1 as Point}, ff::FromUniformBytes, group::Group,
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
pub fn test_schnorr_sequencer() 
{

    use halo2curves::bn256::{Fr, Fq};
    use halo2curves::bn256::G1 as Group;

    // message
    let message = Group::random(OsRng).to_affine();    

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

    // ==== WIP.. ==== //

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
    let input_e = vec![R.x, R.y, X.x, X.y, message.x, message.y, index];
    let e = poseidon_hash(input_e);

        // 7. Sequencer -> User : R_s, P_s, i

    // User side
        // create the partial signature s_u : s_u = r_u + k_u * w_u * e
    let s_u = r_u * k_u;  // [WIP] need to multiply 'Fr' with 'Fq'
        // User -> Sequencer : s_u, message

    // Sequencer side
        // 8. Verify the partial signature from the user
        // s_u * g = R_u + w_u * P_u * e
    let verify_left_val = (g * s_u).to_affine();
    let tmp_x = w_u * P_u.x;
    let tmp_y = w_u * P_u.y;    // Is it correct way to multiply field * Group??
    let mut tmp = Group::generator().to_affine();
    tmp.x = tmp_x;
    tmp.y = tmp_y;
        // 9. create the partial signature on the sequencing side.
        // s_u : s_u = r_u + k_u * w_u * e
    let s_s = r_s * k_s; // [WIP] need to multiply 'Fr' with 'Fq'

    let verify_right_val = (R_u + tmp).to_affine();   // [WIP] need to multiply tmp with e
    //assert!(verify_left_val == verify_right_val);               // [WIP] verify!!

        // 9. create full signature!!
    let full_signature_s = s_u + s_s;
    let full_signature_R = (R_u + R_s).to_affine();

    println!("full signature : s = {:?}, R = {:?}", full_signature_s, full_signature_R);

    // ======== Call API to Smart contract on StarkNet ========//

}