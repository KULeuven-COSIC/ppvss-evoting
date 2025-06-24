use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};

use common::{
    error::{Error, ErrorKind::UninitializedValue},
    random::random_scalar,
    utils::batch_decompress_ristretto_points,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use rayon::prelude::*;
use schoenmakers::{dealer::Dealer, utils::verify_encrypted_shares_standalone};

pub struct CompressedVoteProof {
    pub(crate) a0: CompressedRistretto,
    pub(crate) a1: CompressedRistretto,
    pub(crate) b0: CompressedRistretto,
    pub(crate) b1: CompressedRistretto,
    pub(crate) d0: Scalar,
    pub(crate) d1: Scalar,
    pub(crate) r0: Scalar,
    pub(crate) r1: Scalar,
}

impl CompressedVoteProof {
    fn new(
        a0: CompressedRistretto,
        a1: CompressedRistretto,
        b0: CompressedRistretto,
        b1: CompressedRistretto,
        d0: Scalar,
        d1: Scalar,
        r0: Scalar,
        r1: Scalar,
    ) -> Self {
        Self {
            a0,
            a1,
            b0,
            b1,
            d0,
            d1,
            r0,
            r1,
        }
    }
    pub fn decompress(self) -> VoteProof {
        VoteProof {
            a0: self.a0.decompress().unwrap(),
            a1: self.a1.decompress().unwrap(),
            b0: self.b0.decompress().unwrap(),
            b1: self.b1.decompress().unwrap(),
            d0: self.d0,
            d1: self.d1,
            r0: self.r0,
            r1: self.r1,
        }
    }
}
#[derive(Clone)]
pub struct VoteProof {
    pub(crate) a0: RistrettoPoint,
    pub(crate) a1: RistrettoPoint,
    pub(crate) b0: RistrettoPoint,
    pub(crate) b1: RistrettoPoint,
    pub(crate) d0: Scalar,
    pub(crate) d1: Scalar,
    pub(crate) r0: Scalar,
    pub(crate) r1: Scalar,
}
impl VoteProof {
    pub fn verify(
        &self,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        G: &RistrettoPoint,
        H: &RistrettoPoint,
        encrypted_vote: &RistrettoPoint,
        c0: &RistrettoPoint,
    ) -> bool {
        hasher.update(encrypted_vote.compress().as_bytes());
        hasher.update(c0.compress().as_bytes());
        hasher.update(self.a0.compress().as_bytes());
        hasher.update(self.b0.compress().as_bytes());
        hasher.update(self.a1.compress().as_bytes());
        hasher.update(self.b1.compress().as_bytes());

        hasher.finalize_xof().fill(buf);

        let c = Scalar::from_bytes_mod_order_wide(buf);
        hasher.reset();
        buf.zeroize();

        c == (self.d0 + self.d1)
            && self.a0 == (H * self.r0) + (c0 * self.d0)
            && self.a1 == (H * self.r1) + (c0 * self.d1)
            && self.b0 == (G * self.r0) + (encrypted_vote * self.d0)
            && self.b1 == (G * self.r1) + ((encrypted_vote - G) * self.d1)
    }
    pub fn compress(&self) -> CompressedVoteProof {
        CompressedVoteProof {
            a0: self.a0.compress(),
            a1: self.a1.compress(),
            b0: self.b0.compress(),
            b1: self.b1.compress(),
            d0: self.d0,
            d1: self.d1,
            r0: self.r0,
            r1: self.r1,
        }
    }
}

pub struct Vote {
    pub(crate) encrypted_vote: RistrettoPoint,
    pub(crate) proof: VoteProof,
}
impl Vote {
    pub fn compress(&self) -> CompressedVote {
        CompressedVote {
            encrypted_vote: self.encrypted_vote.compress(),
            proof: self.proof.compress(),
        }
    }
}

pub struct CompressedVote {
    pub(crate) encrypted_vote: CompressedRistretto,
    pub(crate) proof: CompressedVoteProof,
}

pub struct Voter {
    pub dealer: Dealer,
    G: RistrettoPoint,
    vote: Option<Scalar>,
    encrypted_vote: Option<RistrettoPoint>,
}

impl Voter {
    pub fn new(
        G: &RistrettoPoint,
        H: &RistrettoPoint,
        n: usize,
        t: usize,
        public_keys: &[CompressedRistretto],
    ) -> Result<Self, Error> {
        let dealer = Dealer::new(*H, n, t, public_keys)?;

        Ok(Voter {
            dealer: dealer,
            vote: None,
            G: *G,
            encrypted_vote: None,
        })
    }
    // Returns (encrypted_shares, dealer_proof, dealer_commitments, encrypted_vote, vote_proof)
    pub fn vote<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        choice: bool,
    ) -> Result<
        (
            Vec<(CompressedRistretto, RistrettoPoint)>,
            (Scalar, Vec<Scalar>),
            Vec<RistrettoPoint>,
            CompressedRistretto,
            CompressedVoteProof,
        ),
        Error,
    >
    where
        R: CryptoRng + RngCore,
    {
        let s = random_scalar(rng);

        let (encrypted_shares, (d, z), dealer_commitments) =
            self.dealer.deal_secret(rng, hasher, buf, s.clone());

        let decompressed_shares = batch_decompress_ristretto_points(&encrypted_shares).unwrap();
        let decompressed_commitments =
            batch_decompress_ristretto_points(&dealer_commitments).unwrap();

        let c0 = dealer_commitments[0].decompress().unwrap();

        // generate vote
        self.generate_vote(&s, choice);

        assert!(
            verify_encrypted_shares_standalone(
                &self.dealer.H,
                hasher,
                buf,
                &(encrypted_shares.clone(), decompressed_shares.clone()),
                &self.dealer.public_keys,
                &decompressed_commitments,
                (&d, &z),
                self.dealer.n,
                self.dealer.t,
            )
            .unwrap()
        );

        //dleq_vote
        let vote_proof = self.dleq_vote(rng, &c0, &s, hasher, buf)?;

        let out: Vec<(CompressedRistretto, RistrettoPoint)> = encrypted_shares
            .par_iter()
            .zip(decompressed_shares.par_iter())
            .map(|(a, b)| (*a, *b))
            .collect();
        Ok((
            out,
            (d, z),
            decompressed_commitments,
            self.encrypted_vote.as_ref().unwrap().compress(),
            vote_proof,
        ))
    }

    pub fn generate_vote(&mut self, s: &Scalar, choice: bool) {
        self.vote = Some(match choice {
            true => Scalar::ONE,
            false => Scalar::ZERO,
        });
        self.encrypted_vote = Some(self.G * (s + self.vote.unwrap()));
    }

    pub fn dleq_vote<R>(
        &self,
        rng: &mut R,
        c0: &RistrettoPoint,
        s: &Scalar,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
    ) -> Result<CompressedVoteProof, Error>
    where
        R: CryptoRng + RngCore,
    {
        let G = &self.G;
        let H = &self.dealer.H;
        match (self.vote, self.encrypted_vote) {
            (Some(v), Some(u)) => {
                hasher.update(u.compress().as_bytes());
                hasher.update(c0.compress().as_bytes());

                let w = random_scalar(rng);

                // if vote {proof.d0 = d0t_d1f; proof.d1 = d0f_d1t} else {proof.d0 = d0f_d1t; proof.d1 = d0t_d1f};
                let d0t_d1f = random_scalar(rng);
                let d0f_d1t = -d0t_d1f;

                // if vote {proof.r0 = r0t_r1f} else {proof.r1 = r0t_r1f};
                let r0t_r1f = random_scalar(rng);

                // proof.a0 = vote ? a0t_a1f : a0f_a1t;
                // proof.a1 = vote ? a0f_a1t : a0t_a1f;
                let a0t_a1f = ((r0t_r1f * H) + (d0t_d1f * c0)).compress();
                let a0f_a1t = (w * H).compress();

                // if vote {proof.b0 = b0t; proof.b1 = b0f_b1t} else {proof.b0 = b0f_b1t; proof.b1 = b1f};
                let b0f_b1t = (w * G).compress();

                let b1f = ((r0t_r1f * G) + ((u - G) * d0t_d1f)).compress();
                let b0t = ((r0t_r1f * G) + (u * d0t_d1f)).compress();

                Ok(match v == Scalar::ONE {
                    true => {
                        let mut proof = CompressedVoteProof {
                            a0: a0t_a1f,
                            a1: a0f_a1t,
                            b0: b0t,
                            b1: b0f_b1t,
                            d0: d0t_d1f,
                            d1: d0f_d1t,
                            r0: r0t_r1f,
                            r1: w,
                        };

                        hasher.update(proof.a0.as_bytes());
                        hasher.update(proof.b0.as_bytes());
                        hasher.update(proof.a1.as_bytes());
                        hasher.update(proof.b1.as_bytes());

                        hasher.finalize_xof().fill(buf);

                        proof.d1 += Scalar::from_bytes_mod_order_wide(buf);
                        proof.r1 -= s * proof.d1;

                        hasher.reset();
                        buf.zeroize();

                        proof
                    }
                    false => {
                        let mut proof = CompressedVoteProof {
                            a0: a0f_a1t,
                            a1: a0t_a1f,
                            b0: b0f_b1t,
                            b1: b1f,
                            d0: d0f_d1t,
                            d1: d0t_d1f,
                            r0: w,
                            r1: r0t_r1f,
                        };

                        hasher.update(proof.a0.as_bytes());
                        hasher.update(proof.b0.as_bytes());
                        hasher.update(proof.a1.as_bytes());
                        hasher.update(proof.b1.as_bytes());

                        hasher.finalize_xof().fill(buf);

                        proof.d0 += Scalar::from_bytes_mod_order_wide(buf);
                        proof.r0 -= s * proof.d0;

                        hasher.reset();
                        buf.zeroize();

                        proof
                    }
                })
            }
            (None, None) => Err(UninitializedValue("voter.{vote,encrypted_vote}").into()),
            (None, _) => Err(UninitializedValue("voter.vote").into()),
            (_, None) => Err(UninitializedValue("voter.encrypted_vote").into()),
        }
    }

    pub fn generate_voters(
        G: &RistrettoPoint,
        H: &RistrettoPoint,
        m: usize,
        n: usize,
        t: usize,
        public_keys: &[CompressedRistretto],
    ) -> Vec<Self> {
        (0..m)
            .map(|_| Self::new(G, H, n, t, public_keys).unwrap())
            .collect()
    }
}
