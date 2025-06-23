use blake3::Hasher;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};

use rand_chacha::rand_core::CryptoRngCore;
use zeroize::Zeroize;

use pi_s_ppvss::{
    dealer::Dealer,
    error::{Error, ErrorKind::UninitializedValue},
    polynomial::Polynomial,
    utils::{batch_decompress_ristretto_points, verify_encrypted_shares_standalone},
};
use rayon::prelude::*;
#[derive(Clone)]
pub struct CompressedVoteProof {
    pub(crate) a0: CompressedRistretto,
    pub(crate) a1: CompressedRistretto,
    pub(crate) b0: CompressedRistretto,
    pub(crate) b1: CompressedRistretto,
    pub(crate) c: Scalar,
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
            c: Scalar::ZERO,
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
            c: self.c,
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
    pub(crate) c: Scalar,
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
        encrypted_vote: &RistrettoPoint,
        pk0: &RistrettoPoint,
        y0: &RistrettoPoint,
    ) -> bool {
        hasher.update(encrypted_vote.compress().as_bytes());
        hasher.update(y0.compress().as_bytes());
        hasher.update(self.a0.compress().as_bytes());
        hasher.update(self.b0.compress().as_bytes());
        hasher.update(self.a1.compress().as_bytes());
        hasher.update(self.b1.compress().as_bytes());
        hasher.finalize_xof().fill(buf);

        let c = Scalar::from_bytes_mod_order_wide(buf);

        hasher.reset();
        buf.zeroize();

        c == (self.d0 + self.d1)
            && self.a0 == (pk0 * self.r0) + (y0 * self.d0)
            && self.a1 == (pk0 * self.r1) + (y0 * self.d1)
            && self.b0 == (G * self.r0) + (encrypted_vote * self.d0)
            && self.b1 == (G * self.r1) + ((encrypted_vote - G) * self.d1)
    }
    pub fn compress(&self) -> CompressedVoteProof {
        CompressedVoteProof {
            a0: self.a0.compress(),
            a1: self.a1.compress(),
            b0: self.b0.compress(),
            b1: self.b1.compress(),
            c: self.c,
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
    vote: Option<Scalar>,
    encrypted_vote: Option<RistrettoPoint>,
}

impl Voter {
    pub fn new(
        n: usize,
        t: usize,
        public_keys: &[CompressedRistretto],
        pk0: &RistrettoPoint,
    ) -> Result<Self, Error> {
        let dealer = Dealer::new(n, t, public_keys, pk0)?;

        Ok(Voter {
            dealer: dealer,
            vote: None,
            encrypted_vote: None,
        })
    }
    // Returns (encrypted_shares, dealer_proof, encrypted_vote, vote_proof)
    pub fn vote<R>(
        &mut self,
        G: &RistrettoPoint,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        choice: bool,
    ) -> Result<
        (
            Vec<(CompressedRistretto, RistrettoPoint)>,
            (Scalar, Polynomial),
            CompressedRistretto,
            CompressedVoteProof,
        ),
        Error,
    >
    where
        R: CryptoRngCore + ?Sized,
    {
        let s = Scalar::random(rng);
        let (encrypted_shares, (d, z)) = self.dealer.deal_secret(rng, hasher, buf, &s);

        let decompressed_shares = batch_decompress_ristretto_points(&encrypted_shares).unwrap();

        let y0 = encrypted_shares[0].decompress().unwrap();

        // generate vote
        self.generate_vote(&G, &s, choice);

        assert!(verify_encrypted_shares_standalone(
            &(encrypted_shares.clone(), decompressed_shares.clone()),
            &self.dealer.public_keys,
            (&d, &z),
            hasher,
            buf,
        )
        .unwrap());

        //dleq_vote
        let vote_proof = self.dleq_vote(rng, G, &y0, &s, hasher, buf)?;

        let out: Vec<(CompressedRistretto, RistrettoPoint)> = encrypted_shares
            .par_iter()
            .zip(decompressed_shares.par_iter())
            .map(|(a, b)| (*a, *b))
            .collect();
        Ok((
            out,
            (d, z),
            self.encrypted_vote.as_ref().unwrap().compress(),
            vote_proof,
        ))
    }

    pub fn generate_vote(&mut self, G: &RistrettoPoint, s: &Scalar, choice: bool) {
        self.vote = Some(match choice {
            true => Scalar::ONE,
            false => Scalar::ZERO,
        });
        self.encrypted_vote = Some(G * (s + self.vote.unwrap()));
    }

    pub fn dleq_vote<R>(
        &self,
        rng: &mut R,
        G: &RistrettoPoint,
        y0: &RistrettoPoint,
        s: &Scalar,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
    ) -> Result<CompressedVoteProof, Error>
    where
        R: CryptoRngCore + ?Sized,
    {
        match (self.vote, self.encrypted_vote) {
            (Some(v), Some(u)) => {
                let pk0 = self.dealer.get_pk0();
                hasher.update(u.compress().as_bytes());
                hasher.update(y0.compress().as_bytes());

                let w = Scalar::random(rng);

                // if vote {proof.d0 = d0t_d1f; proof.d1 = d0f_d1t} else {proof.d0 = d0f_d1t; proof.d1 = d0t_d1f};
                let d0t_d1f = Scalar::random(rng);
                let d0f_d1t = -d0t_d1f;

                // if vote {proof.r0 = r0t_r1f} else {proof.r1 = r0t_r1f};
                let r0t_r1f = Scalar::random(rng);

                // proof.a0 = vote ? a0t_a1f : a0f_a1t;
                // proof.a1 = vote ? a0f_a1t : a0t_a1f;
                let a0t_a1f = ((r0t_r1f * pk0) + (d0t_d1f * y0)).compress();
                let a0f_a1t = (w * pk0).compress();

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
                            c: Scalar::ZERO,
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

                        buf.zeroize();
                        hasher.reset();

                        proof
                    }
                    false => {
                        let mut proof = CompressedVoteProof {
                            a0: a0f_a1t,
                            a1: a0t_a1f,
                            b0: b0f_b1t,
                            b1: b1f,
                            c: Scalar::ZERO,
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

                        buf.zeroize();
                        hasher.reset();

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
        m: usize,
        n: usize,
        t: usize,
        public_keys: &[CompressedRistretto],
        pk0: &RistrettoPoint,
    ) -> Vec<Self> {
        (0..m)
            .map(|_| Self::new(n, t, public_keys, pk0).unwrap())
            .collect()
    }
}
