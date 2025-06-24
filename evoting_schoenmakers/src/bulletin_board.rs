use crate::voter::VoteProof;
use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, traits::Identity};
use rayon::prelude::*;
use schoenmakers::utils::verify_encrypted_shares_standalone;

#[derive(Clone)]
pub struct BulletinBoard {
    pub G: RistrettoPoint,
    pub H: RistrettoPoint,
    pub public_keys: Vec<RistrettoPoint>,
    pub n: usize,
    pub t: usize,

    // all below are length m
    pub encrypted_shares: Vec<(bool, Vec<RistrettoPoint>)>,
    pub encrypted_share_proofs: Vec<(Scalar, Vec<Scalar>)>,
    pub encrypted_votes: Vec<(bool, RistrettoPoint)>,
    pub dealer_commitments: Vec<Vec<RistrettoPoint>>,
    pub vote_proofs: Vec<VoteProof>,
}

impl BulletinBoard {
    pub fn new(
        G: &RistrettoPoint,
        H: &RistrettoPoint,
        public_keys: &Vec<RistrettoPoint>,
        m: usize,
        n: usize,
        t: usize,
    ) -> Self {
        Self {
            G: G.clone(),
            H: H.clone(),
            public_keys: public_keys.clone(),
            encrypted_shares: Vec::with_capacity(m),
            encrypted_share_proofs: Vec::with_capacity(m),
            encrypted_votes: Vec::with_capacity(m),
            dealer_commitments: Vec::with_capacity(m),
            vote_proofs: Vec::with_capacity(m),
            n: n,
            t: t,
        }
    }

    pub fn ingest_vote(
        &mut self,
        encrypted_shares: Vec<RistrettoPoint>,
        encrypted_share_proof: (Scalar, Vec<Scalar>),
        encrypted_vote: RistrettoPoint,
        dealer_commitments: Vec<RistrettoPoint>,
        vote_proof: VoteProof,
    ) {
        self.encrypted_shares.push((false, encrypted_shares.into()));
        self.encrypted_share_proofs.push(encrypted_share_proof);
        self.encrypted_votes.push((false, encrypted_vote));
        self.dealer_commitments.push(dealer_commitments);
        self.vote_proofs.push(vote_proof);
    }

    pub fn verify_votes(&mut self) {
        self.vote_proofs
            .par_iter()
            .zip(self.encrypted_votes.par_iter_mut())
            .zip(self.dealer_commitments.par_iter())
            .for_each_init(
                || (Hasher::new(), [0u8; 64]),
                |(hasher, buf), ((proof, encrypted_vote), dealer_commitments)| {
                    (*encrypted_vote).0 = proof.verify(
                        hasher,
                        buf,
                        &self.G,
                        &self.H,
                        &encrypted_vote.1,
                        &dealer_commitments[0],
                    );
                },
            )
    }

    pub fn tally_encrypted_votes(&self) -> RistrettoPoint {
        self.encrypted_votes
            .par_iter()
            .filter(|enc_vote| enc_vote.0 == true)
            .map(|enc_vote| enc_vote.1)
            .sum()
    }

    pub fn verify_encrypted_shares(&mut self) {
        self.encrypted_shares
            .par_iter_mut()
            .zip(self.encrypted_share_proofs.par_iter())
            .zip(self.dealer_commitments.par_iter())
            .for_each_init(
                || (Hasher::new(), [0u8; 64]),
                |(hasher, buf), (((status, enc_shares), (d, z)), dealer_commitments)| {
                    let compressed_shares = enc_shares
                        .par_iter()
                        .map(|share| share.compress())
                        .collect();

                    *status = verify_encrypted_shares_standalone(
                        &self.H,
                        hasher,
                        buf,
                        &(compressed_shares, enc_shares.to_owned()),
                        &self.public_keys,
                        dealer_commitments,
                        (d, z),
                        self.n,
                        self.t,
                    )
                    .unwrap();
                },
            );
    }

    pub fn sum_encrypted_shares(&self) -> Vec<RistrettoPoint> {
        let mut output = vec![RistrettoPoint::identity(); self.n];

        for enc_shares in self
            .encrypted_shares
            .iter()
            .filter(|(status, _)| *status == true)
            .map(|(_, enc_shares)| enc_shares)
        {
            enc_shares
                .into_par_iter()
                .zip(output.par_iter_mut())
                .for_each(|(enc_share, output_slot)| *output_slot += enc_share);
        }
        output
    }

    pub fn count_valid_votes(&self) -> usize {
        self.encrypted_votes
            .par_iter()
            .filter(|(status, _)| *status == true)
            .count()
    }
}
