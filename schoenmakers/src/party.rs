use blake3::Hasher;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use common::{random::random_scalar, utils::batch_decompress_ristretto_points,
    error::{
        Error,
        ErrorKind::{CountMismatch, InvalidPararmeterSet, InvalidProof, UninitializedValue},
    },
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{
    utils::{verify_encrypted_shares_standalone},
};
use rayon::prelude::*;

#[derive(Clone)]
pub struct Party {
    pub G: RistrettoPoint,
    pub H: RistrettoPoint,

    pub private_key: Scalar,
    pub public_key: (CompressedRistretto, RistrettoPoint),
    pub index: usize,
    pub n: usize,
    pub t: usize,
    pub share_proof: Option<(Scalar, Scalar)>,
    pub encrypted_share: Option<RistrettoPoint>,
    pub decrypted_share: Option<RistrettoPoint>,

    pub dealer_commitments: Option<Vec<RistrettoPoint>>,
    pub dealer_proof: Option<(Scalar, Vec<Scalar>)>,

    pub public_keys: Option<Vec<RistrettoPoint>>,
    pub encrypted_shares: Option<(Vec<CompressedRistretto>, Vec<RistrettoPoint>)>,
    pub decrypted_shares: Option<Vec<RistrettoPoint>>,
    pub share_proofs: Option<Vec<(Scalar, Scalar)>>,
    pub validated_shares: Vec<usize>,
}

impl Party {
    pub fn new<R>(
        G: RistrettoPoint,
        H: RistrettoPoint,
        rng: &mut R,
        n: usize,
        t: usize,
        index: usize,
    ) -> Result<Self, Error>
    where
        R: CryptoRng + RngCore,
    {
        let private_key = random_scalar(rng);
        let public_key = G * private_key;

        if index <= n && t < n && t as f32 == ((n - 1) as f32 / 2.0).floor() {
            Ok(Self {
                G,
                H,
                private_key,
                public_key: (public_key.compress(), public_key),
                index,
                n,
                t,
                dealer_proof: None,
                encrypted_share: None,
                decrypted_share: None,
                share_proof: None,
                share_proofs: None,
                dealer_commitments: None,
                encrypted_shares: None,
                decrypted_shares: None,
                public_keys: None,
                validated_shares: vec![],
            })
        } else {
            Err(InvalidPararmeterSet(n, t as isize, index).into())
        }
    }

    pub fn ingest_encrypted_shares(
        &mut self,
        encrypted_shares: &[CompressedRistretto],
    ) -> Result<(), Error> {
        if encrypted_shares.len() == self.n {
            match batch_decompress_ristretto_points(encrypted_shares) {
                Ok(enc_shares) => {
                    self.encrypted_share = Some(enc_shares[self.index - 1]);
                    self.encrypted_shares = Some((encrypted_shares.to_vec(), enc_shares));
                    Ok(())
                }
                Err(x) => Err(x),
            }
        } else {
            Err(CountMismatch(
                self.n,
                "parties",
                encrypted_shares.len(),
                "encrypted shares",
            )
            .into())
        }
    }
    pub fn ingest_commitments(
        &mut self,
        dealer_commitments: &[CompressedRistretto],
    ) -> Result<(), Error> {
        if dealer_commitments.len() == (self.t + 1) {
            match batch_decompress_ristretto_points(dealer_commitments) {
                Ok(commitments) => {
                    self.dealer_commitments = Some(commitments);
                    Ok(())
                }
                Err(x) => Err(x),
            }
        } else {
            Err(CountMismatch(
                self.n,
                "parties",
                dealer_commitments.len(),
                "encrypted shares",
            )
            .into())
        }
    }
    pub fn ingest_public_keys(&mut self, public_keys: &[CompressedRistretto]) -> Result<(), Error> {
        if public_keys.len() == self.n - 1 {
            match batch_decompress_ristretto_points(public_keys) {
                Ok(mut pks) => {
                    pks.insert(
                        self.index - 1,
                        self.public_key.1.compress().decompress().unwrap(),
                    );
                    self.public_keys = Some(pks);
                    Ok(())
                }
                Err(x) => Err(x),
            }
        } else {
            Err(CountMismatch(self.n, "parties", public_keys.len(), "public_keys").into())
        }
    }

    pub fn ingest_dealer_proof(&mut self, d: Scalar, z: Vec<Scalar>) -> Result<(), Error> {
        if d == Scalar::ZERO {
            Err(InvalidProof(format!("d == {d:?}",)).into())
        } else if z.len() != self.n {
            Err(InvalidProof(format!("z len: {}, t: {}", z.len(), self.n)).into())
        } else {
            self.dealer_proof = Some((d, z));
            Ok(())
        }
    }
    pub fn ingest_decrypted_shares_and_proofs(
        &mut self,
        decrypted_shares: &[CompressedRistretto],
        proofs: Vec<(Scalar, Scalar)>,
    ) -> Result<(), Error> {
        if decrypted_shares.len() == self.n - 1 {
            if proofs.len() == decrypted_shares.len() {
                match batch_decompress_ristretto_points(decrypted_shares) {
                    Ok(mut dec_shares) => match (self.decrypted_share, self.share_proof) {
                        (Some(own_dec_share), Some(own_proof)) => {
                            dec_shares.insert(self.index - 1, own_dec_share);
                            self.decrypted_shares = Some(dec_shares);
                            let mut proofs = proofs;
                            proofs.insert(self.index - 1, own_proof);
                            self.share_proofs = Some(proofs);
                            Ok(())
                        }
                        (None, Some(_)) => Err(UninitializedValue("party.decrypted_share").into()),
                        (Some(_), None) => Err(UninitializedValue("party.share_proof").into()),
                        (None, None) => {
                            Err(UninitializedValue("party.{decrypted_share, share_proof}").into())
                        }
                    },
                    Err(x) => Err(x),
                }
            } else {
                Err(CountMismatch(self.n, "parties", proofs.len(), "proofs").into())
            }
        } else {
            Err(CountMismatch(
                self.n,
                "parties",
                decrypted_shares.len(),
                "decrypted shares",
            )
            .into())
        }
    }

    pub fn verify_encrypted_shares(
        &self,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
    ) -> Result<bool, Error> {
        match (&self.dealer_proof, &self.dealer_commitments) {
            (Some((d, z)), Some(dealer_commitments)) => {
                match (&self.encrypted_shares, &self.public_keys) {
                    (Some(encrypted_shares), Some(public_keys)) => {
                        verify_encrypted_shares_standalone(
                            &self.H,
                            hasher,
                            buf,
                            encrypted_shares,
                            public_keys,
                            dealer_commitments,
                            (d, z),
                            self.n,
                            self.t,
                        )
                    }
                    (Some(_), None) => Err(UninitializedValue("party.public_keys").into()),
                    (None, Some(_)) => Err(UninitializedValue("party.encrypted_shares").into()),
                    (None, None) => {
                        Err(UninitializedValue("party.{encrypted_shares, public_keys}").into())
                    }
                }
            }
            (Some(_), None) => Err(UninitializedValue("party.dealer_commitments").into()),
            (None, Some(_)) => Err(UninitializedValue("party.dealer_proof").into()),
            (None, None) => {
                Err(UninitializedValue("party.{encrypted_shares, dealer_proof}").into())
            }
        }
    }

    pub fn decrypt_share(&mut self) -> Result<(), Error> {
        let inv_private_key = self.private_key.invert();
        match &self.encrypted_share {
            Some(encrypted_share) => {
                self.decrypted_share = Some(encrypted_share * inv_private_key);
                Ok(())
            }
            None => Err(UninitializedValue("party.encrypted_share").into()),
        }
    }
    pub fn dleq_share<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
    ) -> Result<(), Error>
    where
        R: CryptoRng + RngCore,
    {
        match (&self.decrypted_share, &self.encrypted_share) {
            (Some(decrypted_share), Some(encrypted_share)) => {
                let r = random_scalar(rng);

                hasher.update(self.public_key.0.as_bytes());
                hasher.update(encrypted_share.compress().as_bytes());

                hasher.update((self.G * r).compress().as_bytes());
                hasher.update((decrypted_share * r).compress().as_bytes());

                hasher.finalize_xof().fill(buf);

                let d = Scalar::from_bytes_mod_order_wide(buf);
                let z = r + d * self.private_key;

                self.share_proof = Some((d, z));
                
                hasher.reset();
                buf.zeroize();

                Ok(())
            }
            (None, Some(_)) => Err(UninitializedValue("party.decrypted_share").into()),
            (Some(_), None) => Err(UninitializedValue("party.encrypted_shares").into()),
            (None, None) => {
                Err(UninitializedValue("party.{decrypted_share, encrypted_shares}").into())
            }
        }
    }

    pub fn verify_decrypted_shares(&mut self) -> Result<bool, Error> {
        match (&self.public_keys, &self.encrypted_shares) {
            (Some(public_keys), Some(enc_shares)) => {
                match (&self.decrypted_shares, &self.share_proofs) {
                    (Some(dec_shares), Some(proofs)) => {
                        self.validated_shares = dec_shares
                            .par_iter()
                            .zip(
                                proofs
                                    .par_iter()
                                    .zip(public_keys.par_iter().zip(enc_shares.1.par_iter())),
                            )
                            .enumerate()
                            .map_init(
                                ||(blake3::Hasher::new(), [0u8;64]), | (hasher, buf),
                                (i, (dec_share, ((d, z), (public_key, enc_share)))) | {

                                    hasher.update(public_key.compress().as_bytes());
                                    hasher.update(enc_share.compress().as_bytes());

                                    hasher.update(((z * self.G) - (d * public_key)).compress().as_bytes());
                                    hasher.update(((z * dec_share) - (d * enc_share)).compress().as_bytes());
                                    hasher.finalize_xof().fill(buf);

                                    let reconstructed_d = Scalar::from_bytes_mod_order_wide(buf);
                                    
                                    buf.zeroize();
                                    hasher.reset();
                                    
                                    if *d == reconstructed_d {
                                        Some(i)
                                    } else {
                                        None
                                    }
                                },
                            ).filter(Option::is_some).map(|res| res.unwrap()).collect();
                        Ok(self.validated_shares.len() > self.t + 1)
                    }
                    (None, Some(_)) => Err(UninitializedValue("party.decrypted_shares").into()),
                    (Some(_), None) => Err(UninitializedValue("party.share_proofs").into()),
                    (None, None) => {
                        Err(UninitializedValue("party.{decrypted_shares, share_proofs}").into())
                    }
                }
            }
            (None, Some(_)) => Err(UninitializedValue("party.encrypted_shares").into()),
            (Some(_), None) => Err(UninitializedValue("party.public_keys").into()),
            (None, None) => Err(UninitializedValue("party.{public_keys, encrypted_shares}").into()),
        }
    }
    pub fn reconstruct_secret(&self, lambdas: &Vec<Scalar>) -> Result<RistrettoPoint, Error> {
        match &self.decrypted_shares {
            Some(dec_shares) => Ok(self
                .validated_shares
                .par_iter()
                .take(self.t + 1)
                .map(|share_index| lambdas[*share_index] * dec_shares[*share_index])
                .sum()),
                None => Err(UninitializedValue("party.decrypted_shares").into()),
        }
    }
}
pub fn generate_parties<R>(
    G: RistrettoPoint,
    H: RistrettoPoint,
    rng: &mut R,
    n: usize,
    t: usize,
) -> Vec<Party>
where
    R: CryptoRng + RngCore,
{
    (1..=n)
        .map(|i| Party::new(G, H, rng, n, t, i).unwrap())
        .collect()
}
