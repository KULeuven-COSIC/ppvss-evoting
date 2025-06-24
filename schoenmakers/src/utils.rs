use blake3::Hasher;
use common::error::Error;

use curve25519_dalek::{
    Scalar,
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::Identity,
};
use num_bigint::BigUint;

use rayon::prelude::*;
use zeroize::Zeroize;

pub fn verify_encrypted_shares_standalone(
    H: &RistrettoPoint,
    hasher: &mut Hasher,
    buf: &mut [u8; 64],
    encrypted_shares: &(Vec<CompressedRistretto>, Vec<RistrettoPoint>),
    public_keys: &Vec<RistrettoPoint>,
    dealer_commitments: &Vec<RistrettoPoint>,
    proof: (&Scalar, &Vec<Scalar>),
    n: usize,
    t: usize,
) -> Result<bool, Error> {
    let (d, z) = proof;
    let modulus = BigUint::from_bytes_le(&Q);

    let (mut reconstructed_gen_evals, mut a_vals): (
        Vec<CompressedRistretto>,
        Vec<(CompressedRistretto, CompressedRistretto)>,
    ) = (vec![], vec![]);

    (0..n)
        .into_par_iter()
        .zip(
            z.par_iter()
                .zip(public_keys.par_iter())
                .zip(encrypted_shares.1.par_iter()),
        )
        .map(|(i, ((z, public_key), encrypted_share))| {
            let i_m = BigUint::from(i + 1);
            let mut j_m: BigUint;
            let mut bytes: Vec<u8>;

            let mut xi = RistrettoPoint::identity();
            for j in 0..(t + 1) {
                j_m = BigUint::from(j);
                bytes = i_m.modpow(&j_m, &modulus).to_bytes_le();

                let mut tmp_bytes: [u8; 32] = [0u8; 32];

                for i in 0..bytes.len() {
                    tmp_bytes[i] = bytes[i];
                }

                xi += dealer_commitments[j] * Scalar::from_bytes_mod_order(tmp_bytes);
            }
            (
                xi.compress(),
                (
                    ((H * z) + (xi * d)).compress(),
                    ((public_key * z) + encrypted_share * d).compress(),
                ),
            )
        })
        .unzip_into_vecs(&mut reconstructed_gen_evals, &mut a_vals);

    let flat_vec: Vec<u8> = reconstructed_gen_evals
        .par_iter()
        .flat_map(|eval| eval.to_bytes())
        .chain(
            encrypted_shares
                .0
                .par_iter()
                .flat_map(|enc_share| enc_share.to_bytes()),
        )
        .chain(a_vals.par_iter().flat_map(|x| x.0.to_bytes()))
        .chain(a_vals.par_iter().flat_map(|x| x.1.to_bytes()))
        .collect();

    hasher.update(&flat_vec);

    hasher.finalize_xof().fill(buf);

    let reconstructed_d = Scalar::from_bytes_mod_order_wide(buf);

    hasher.reset();
    buf.zeroize();

    Ok(*d == reconstructed_d)
}

/// 2^252  + 27742317777372353535851937790883648493
pub const Q: [u8; 32] = [
    237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 16,
];
