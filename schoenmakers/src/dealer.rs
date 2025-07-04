use blake3::Hasher;
use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    random::random_scalar,
    utils::batch_decompress_ristretto_points,
};
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use zeroize::Zeroize;

pub struct Dealer {
    pub H: RistrettoPoint,
    pub n: usize,
    pub t: usize,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secret: Option<Scalar>,
}

impl Dealer {
    pub fn new(
        H: RistrettoPoint,
        n: usize,
        t: usize,
        public_keys: &[CompressedRistretto],
    ) -> Result<Self, Error> {
        if public_keys.len() != n {
            return Err(CountMismatch(n, "parties", public_keys.len(), "public keys").into());
        }
        match batch_decompress_ristretto_points(public_keys) {
            Ok(pks) => Ok(Self {
                n,
                t,
                public_keys: pks.par_iter().map(|pk| *pk).collect(),
                H,
                secret: None,
            }),
            Err(x) => Err(x),
        }
    }

    pub(crate) fn generate_commitments(&self, f: &Polynomial) -> Vec<CompressedRistretto> {
        f.mul_with_point_compress(&self.H)
    }

    /// Proof of correct construction of encrypted shares
    pub(crate) fn dleq_pol<R>(
        &self,
        evals: &Vec<Scalar>,
        enc_shares: &Vec<CompressedRistretto>,
        hasher: &mut Hasher,
        rng: &mut R,
        buf: &mut [u8; 64],
    ) -> (Scalar, Vec<Scalar>)
    where
        R: CryptoRng + RngCore,
    {
        let randomizer_vals: Vec<Scalar> = (0..self.n).map(|_| random_scalar(rng)).collect();

        let flat: Vec<u8> = evals
            // gen_eval_str
            .par_iter()
            .flat_map(|eval| (self.H * eval).compress().to_bytes())
            // enc_eval_str
            .chain(enc_shares.par_iter().flat_map(|x| x.to_bytes()))
            // a1_str
            .chain(
                randomizer_vals
                    .par_iter()
                    .flat_map(|r| (self.H * r).compress().to_bytes()),
            )
            //a2_str
            .chain(
                randomizer_vals
                    .par_iter()
                    .zip(self.public_keys.par_iter())
                    .flat_map(|(r, public_key)| (public_key * r).compress().to_bytes()),
            )
            .collect();

        hasher.update(&flat);

        hasher.finalize_xof().fill(buf);
        let d = Scalar::from_bytes_mod_order_wide(buf);

        hasher.reset();
        buf.zeroize();

        let z: Vec<Scalar> = randomizer_vals
            .par_iter()
            .zip(evals.par_iter())
            // r_list[i] = w_list[i] - d*evals[i] (but overwriting w_vals in place)
            .map(|(r_i, eval_i)| *r_i - d * eval_i)
            .collect();

        (d, z)
    }

    pub fn deal_secret<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        secret: Scalar,
    ) -> (
        Vec<CompressedRistretto>,
        (Scalar, Vec<Scalar>),
        Vec<CompressedRistretto>,
    )
    where
        R: CryptoRng + RngCore,
    {
        let f = Polynomial::sample_set_f0(self.t, rng, &secret);
        self.secret = Some(secret);

        let commitments = self.generate_commitments(&f);

        // eval [1..n+1], eval_i * pk_i
        let (evals, enc_evals) = f.evaluate_multiply(&self.public_keys, 1);

        let compressed_enc_evals = enc_evals
            .par_iter()
            .map(|enc_eval| enc_eval.compress())
            .collect();

        let (c, r_vals) = self.dleq_pol(&evals, &compressed_enc_evals, hasher, rng, buf);

        (compressed_enc_evals, (c, r_vals), commitments)
    }
}
