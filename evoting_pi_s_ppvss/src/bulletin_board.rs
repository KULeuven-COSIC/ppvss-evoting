use crate::voter::VoteProof;
use blake3::Hasher;
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use pi_s_ppvss::{polynomial::Polynomial, utils::verify_encrypted_shares_standalone};
use rayon::prelude::*;

#[derive(Clone)]
pub struct BulletinBoard {
    pub G: RistrettoPoint,
    pub pk0: RistrettoPoint,
    pub public_keys: Vec<RistrettoPoint>,
    // all below are length m
    pub encrypted_shares: Vec<(bool, Vec<RistrettoPoint>)>,
    pub encrypted_share_proofs: Vec<(Scalar, Polynomial)>,
    pub encrypted_votes: Vec<(bool, RistrettoPoint)>,
    pub vote_proofs: Vec<VoteProof>,
}

impl BulletinBoard {
    pub fn new(
        G: &RistrettoPoint,
        pk0: &RistrettoPoint,
        public_keys: &Vec<RistrettoPoint>,
        m: usize,
    ) -> Self {
        Self {
            G: G.clone(),
            pk0: pk0.clone(),
            public_keys: public_keys.clone(),
            encrypted_shares: Vec::with_capacity(m),
            encrypted_share_proofs: Vec::with_capacity(m),
            encrypted_votes: Vec::with_capacity(m),
            vote_proofs: Vec::with_capacity(m),
        }
    }

    pub fn ingest_vote(
        &mut self,
        encrypted_shares: Vec<RistrettoPoint>,
        encrypted_share_proof: (Scalar, Polynomial),
        encrypted_vote: RistrettoPoint,
        vote_proof: VoteProof,
    ) {
        self.encrypted_shares.push((false, encrypted_shares.into()));
        self.encrypted_share_proofs.push(encrypted_share_proof);
        self.encrypted_votes.push((false, encrypted_vote));
        self.vote_proofs.push(vote_proof);
    }

    pub fn verify_votes(&mut self) {
        self.vote_proofs
            .par_iter()
            .zip(
                self.encrypted_shares
                    .par_iter()
                    .map(|(_, enc_shares)| enc_shares[0])
                    .zip(self.encrypted_votes.par_iter_mut()),
            )
            .for_each_init(
                || (Hasher::new(), [0u8; 64]),
                |(hasher, buf), (proof, (y0, encrypted_vote))| {
                    (*encrypted_vote).0 =
                        proof.verify(hasher, buf, &self.G, &encrypted_vote.1, &self.pk0, &y0);
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
        let mut new_pub_keys = self.public_keys.clone();
        new_pub_keys.insert(0, self.pk0);
        self.encrypted_shares
            .par_iter_mut()
            .zip(self.encrypted_share_proofs.par_iter())
            .for_each_init(
                || (Hasher::new(), [0u8; 64]),
                |(hasher, buf), ((status, enc_shares), (d, z))| {
                    let compressed_shares = enc_shares
                        .par_iter()
                        .map(|share| share.compress())
                        .collect();
                    *status = verify_encrypted_shares_standalone(
                        &(compressed_shares, enc_shares.to_owned()),
                        &new_pub_keys,
                        (d, z),
                        hasher,
                        buf,
                    )
                    .unwrap();
                },
            );
    }

    pub fn sum_encrypted_shares(&self) -> Vec<RistrettoPoint> {
        let n = self.public_keys.len();

        let mut output = vec![RistrettoPoint::identity(); n + 1];

        for enc_shares in self
            .encrypted_shares
            .iter()
            .filter(|(status, _)| *status == true)
            .map(|(_, enc_shares)| enc_shares)
        {
            enc_shares
                .into_par_iter()
                .skip(1)
                // this is where we skip y0
                .zip(output.par_iter_mut().skip(1))
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
