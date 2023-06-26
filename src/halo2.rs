use std::{time::Instant, mem::size_of};
use halo2_proofs::arithmetic::{Field, CurveAffine};
use rand::{thread_rng, rngs::OsRng};
use rayon::prelude::*;

use halo2curves::{
    bn256::{Fr as Scalar, G1Affine as Affine, G1 as Point}, ff::FromUniformBytes,
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
    let input_I = vec![P_u , P_s];
    let I = poseidon_hash::<N>(input_I);
        
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

}


pub fn gen_key_pair<C: CurveAffine>() {
    let g = C::generator();

    // generate a key pair
    let sk = <C as CurveAffine>::ScalarExt::random(OsRng);
    let public_key = (g * sk).to_affine();  // to_affine belongs to "use halo2curves::group::Curve"

    println!("sk:{:?}, pk: {:?}",sk, public_key);
}



#[test]
pub fn test_gen_key() {

    use halo2curves::bn256::Fr as BnScalar;
    use halo2curves::bn256::G1Affine as G1Affine;


    gen_key_pair::<G1Affine>();
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
pub fn test_poseidon_hash() {
    
    use halo2curves::bn256::Fr as BnScalar;
    let inputs = (0..2).map(|_| BnScalar::random(OsRng))
                                            .collect::<Vec<BnScalar>>();
    
    let pHash = poseidon_hash(inputs);

    println!("poseidon hash : {:?}", pHash);

}
