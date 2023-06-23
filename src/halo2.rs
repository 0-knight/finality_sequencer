use std::{time::Instant, mem::size_of};
use halo2_proofs::arithmetic::Field;
use rand::thread_rng;
use rayon::prelude::*;


use halo2curves::{
    bn256::{Fr as Scalar, G1Affine as Affine, G1 as Point},
};


/*
pub fn rand_vec_scalar(size: usize) -> Vec<Scalar> {
    let now = Instant::now();
    println!(
        "Memory allocation ({} GB)",
        (size * size_of::<Scalar>()) as f64 / 1.0e9
    );
    let mut result = vec![Scalar::zero(); size];
    println!("Randomizing...");
    result.par_chunks_mut(1024).for_each_init(
        || thread_rng(),
        |rng, chunk| {
            for point in chunk {
                *point = Scalar::random(&mut *rng);
            }
        },
    );
    println!("Random generation took: {:?}", now.elapsed());
    result
}

 */

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

