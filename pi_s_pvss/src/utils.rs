use crate::{
    error::{Error, ErrorKind::PointDecompressionError},
    party::Party,
};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    Scalar,
};
use rand_chacha::rand_core::CryptoRngCore;
use rayon::prelude::*;

pub fn decompress_ristretto_point(
    compressed_point: CompressedRistretto,
) -> Result<RistrettoPoint, Error> {
    match compressed_point.decompress() {
        Some(decompressed_point) => Ok(decompressed_point),
        None => Err(Error::from_kind(PointDecompressionError(format!(
            "{compressed_point:?}",
        )))),
    }
}

pub fn batch_decompress_ristretto_points(
    compressed_points: &[CompressedRistretto],
) -> Result<Vec<RistrettoPoint>, Error> {
    compressed_points
        .par_iter()
        .map(|compressed_point| decompress_ristretto_point(*compressed_point))
        .collect()
}

pub fn generate_parties<R>(G: &RistrettoPoint, rng: &mut R, n: usize, t: usize) -> Vec<Party>
where
    R: CryptoRngCore + ?Sized,
{
    (1..=n)
        .map(|i| Party::new(G, rng, n, t, i).unwrap())
        .collect()
}

pub fn generate_public_keys<R>(
    G: &RistrettoPoint,
    rng: &mut R,
    n: usize,
) -> Vec<CompressedRistretto>
where
    R: CryptoRngCore + ?Sized,
{
    (0..n)
        .map(|_| (G * &Scalar::random(rng)).compress())
        .collect()
}

pub fn precompute_lambda(n: usize, t: usize) -> Vec<Scalar> {
    (1..=n)
        .into_par_iter()
        .map(|i| {
            let zq_i = Scalar::from(i as u64);
            let mut lambda_i = Scalar::ONE;
            for j in 1..=(t + 1) {
                if j != i {
                    let zq_j = Scalar::from(j as u64);

                    lambda_i *= zq_j * ((zq_j - zq_i).invert());
                }
            }
            lambda_i
        })
        .collect()
}
