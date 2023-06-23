mod halo2;

fn main() {
    println!("Finality sequencer!");

    //=== User side ===//
    // Known parameter : G (elliptic curve group) , tx (transaction to sign), H (hashing algorithm)
    // 1. Generate a private key k_u (random scalar value)
    // 2. Calculate a public key P_u from k_u : P_u = k_u * G
    // 3. Generate a random nonce r_u and public nonce R_u calculated from r_u : R_u = r_u * G

    // === Sequencer side ===//
    // Known parameter : G (elliptic curve group) , H (hashing algorithm) 
    // 1. Generate a private key k_s (random scalar value)
    // 2. Calculate a public key P_s from k_s : P_s = k_s * G
    // 3. Generate a random nonce r_s and public nonce R_s calculated from r_s : R_s = r_s * G
    
    // === User side ===//
    // 4. Calculate a challenge value e using Hashing H : e = H ( R || P_u || m )
    // 5. Calculate a partial schnorr signature s_u
        // s = r_u + k_u * e
    // (Value public to anyone) P_u
    // (Value delivered to Sequencer) s_u, R_u , m
    // (test) Verify the signature
        // 1. s * G = R + e (k * G)
        // 2. s * G = R + e * P
    
    // === Sequencer side ===//
    // 4. Calculate a protection value X
        // I = H ( P || P_s ), w = H ( I || P ) , w_s = H ( I || P_s )
        // X = w * P + w_s * P_s
    // 5. Calculate R : R = R_u + R_s 
    // 6. Calculate a challenge e with index i 
        // this means that the sequencer commits the transaction to index i
        // e = H ( R || X || m || i)
    // 7. Calculate a full schnorr signature s_u : s_u = r_u + k_u * w_u * e
    
    // === User side ===//
    // Claim to the smart contract on StarkNet that the sequencer just lied!!
    // 6. Submit a signature from the sequencer and tx.
    
    // === Smart Contract === //
    // 7. verify the signature
    // 8. check out the commitment to do with the index USING storage proof!!

}

#[test]
fn halo2_test() {
    let vsc = halo2::rand_vec_scalar(3);
    print!("{:?}", vsc);
}
