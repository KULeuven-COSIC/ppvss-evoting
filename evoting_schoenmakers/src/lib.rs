pub mod bulletin_board;
pub mod tallier;
pub mod voter;

#[cfg(test)]
mod test {
    use crate::{bulletin_board::BulletinBoard, tallier::Tallier, voter::Voter};
    use common::random::random_point;
    use common::utils::precompute_lambda;
    use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
    use rayon::prelude::*;
    use zeroize::Zeroize;

    #[test]
    fn test_verif() {
        let n: usize = 17;
        let t: usize = 8;

        let lambdas = precompute_lambda(n, t);

        let m: usize = 10;
        let false_ratio = 0.7;

        let f_count = (m as f64 * false_ratio) as usize;
        let t_count = m - f_count;

        let mut rng = rand::rng();
        let mut hasher = blake3::Hasher::new();
        let mut buf: [u8; 64] = [0u8; 64];

        let G: RistrettoPoint = random_point(&mut rng);
        let H: RistrettoPoint = random_point(&mut rng);

        let mut talliers = Tallier::generate_talliers(&G, &H, &mut rng, n, t);
        let public_keys: (Vec<CompressedRistretto>, Vec<RistrettoPoint>) = talliers
            .iter()
            .map(|tallier| tallier.party.public_key)
            .collect();

        let mut voters = Voter::generate_voters(&G, &H, m, n, t, &public_keys.0);

        let mut bulletin_board: BulletinBoard = BulletinBoard::new(&G, &H, &public_keys.1, m, n, t);

        voters.iter_mut().enumerate().for_each(|(i, voter)| {
            let (encrypted_shares, (d, z), dealer_commitments, encrypted_vote, vote_proof) = voter
                .vote(&mut rng, &mut hasher, &mut buf, i < t_count)
                .unwrap();

            let decompressed_encrypted_shares: Vec<RistrettoPoint> = encrypted_shares
                .par_iter()
                .map(|enc_share| enc_share.1)
                .collect();

            bulletin_board.ingest_vote(
                decompressed_encrypted_shares,
                (d, z),
                encrypted_vote.decompress().unwrap(),
                dealer_commitments,
                vote_proof.decompress(),
            );
        });

        // voting complete

        let mut decrypted_shares: Vec<CompressedRistretto> = Vec::with_capacity(n);
        let mut decrypted_share_proofs: Vec<(Scalar, Scalar)> = Vec::with_capacity(n);

        for tallier in &mut talliers {
            let mut bb = bulletin_board.clone();

            bb.verify_encrypted_shares();

            bb.verify_votes();

            let public_keys: Vec<CompressedRistretto> = public_keys
                .0
                .iter()
                .filter(|pk| &tallier.party.public_key.0 != *pk)
                .copied()
                .collect();

            tallier.party.ingest_public_keys(&public_keys).unwrap();

            let compressed_shares: Vec<CompressedRistretto> = bb
                .sum_encrypted_shares()
                .par_iter()
                .map(|share| share.compress())
                .collect();

            tallier
                .party
                .ingest_encrypted_shares(&compressed_shares)
                .unwrap();

            tallier.party.decrypt_share().unwrap();
            tallier
                .party
                .dleq_share(&mut rng, &mut hasher, &mut buf)
                .unwrap();

            decrypted_shares.push(tallier.party.decrypted_share.unwrap().compress());
            decrypted_share_proofs.push(tallier.party.share_proof.unwrap());
            tallier.bulletin_board = Some(bb);
        }

        let mut reconstructed_secrets: Vec<RistrettoPoint> = vec![];

        for tallier in &mut talliers {
            let (mut dec_shares, mut share_proofs) =
                (decrypted_shares.clone(), decrypted_share_proofs.clone());

            dec_shares.remove(tallier.party.index - 1);
            share_proofs.remove(tallier.party.index - 1);
            tallier
                .party
                .ingest_decrypted_shares_and_proofs(&dec_shares, share_proofs)
                .unwrap();

            assert!(tallier.party.verify_decrypted_shares().unwrap());

            reconstructed_secrets.push(tallier.party.reconstruct_secret(&lambdas).unwrap());
        }

        let accumulated_encrypted_votes = talliers[0]
            .bulletin_board
            .as_ref()
            .unwrap()
            .tally_encrypted_votes();

        let recon_secret = reconstructed_secrets[0];

        let exp_vote = accumulated_encrypted_votes - recon_secret;

        let mut decrypted_vote = 0.0;

        for i in 0u64..=talliers[0]
            .bulletin_board
            .as_ref()
            .unwrap()
            .count_valid_votes() as u64
        {
            if exp_vote == G * Scalar::from(i) {
                decrypted_vote = i as f64;
                break;
            }
        }

        assert_eq!(decrypted_vote, t_count as f64);
        if decrypted_vote == ((m as f64) / 2.0) {
            println!("Tie");
        } else if decrypted_vote > ((m as f64) / 2.0) {
            println!("Candidate 1 is the Winner");
        } else {
            println!("Candidate 0 is the Winner");
        }

        println!("{decrypted_vote}");
    }
}
