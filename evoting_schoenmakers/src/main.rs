use common::utils::precompute_lambda;
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto, scalar::Scalar};
use evoting_schoenmakers::voter::Voter;
use rand::{SeedableRng, thread_rng};
use zeroize::Zeroize;

fn main() {
    // const N: usize = 33;
    // const T: usize = 16;
    // const M: usize = 100;

    // let mut rng = rand::rng();
    // let mut hasher = blake3::Hasher::new();
    // let mut buf = [0u8; 64];

    // let lambdas = precompute_lambda(T);
    // let G: RistrettoPoint = random_point(&mut rng);
    // let H: RistrettoPoint = random_point(&mut rng);

    // let pk0 = random_point(&mut rng);

    // let mut parties = generate_parties(&G, &H, &mut rng, N, M, T, &pk0);

    // let public_keys: Vec<CompressedRistretto> =
    //     parties.iter().map(|party| party.public_key.0).collect();

    // let mut dealer = Voter::new(N, T, &public_keys, &pk0).unwrap();

    // for party in &mut parties {
    //     let public_keys: Vec<CompressedRistretto> = public_keys
    //         .iter()
    //         .filter(|pk| &party.public_key.0 != *pk)
    //         .copied()
    //         .collect();

    //     party.ingest_public_keys(&public_keys).unwrap();
    // }

    // let (encrypted_shares, (d, z)) = dealer.deal_secret(&mut rng, &mut hasher, &mut buf);

    // for p in &mut parties {
    //     p.ingest_encrypted_shares(&encrypted_shares).unwrap();
    //     p.ingest_dealer_proof(d, z.clone()).unwrap();

    //     let res = p.verify_encrypted_shares(&mut hasher, &mut buf).unwrap();

    //     assert!(res, "encrypted share verification failure");
    // }

    // let (decrypted_shares, share_proofs): (Vec<CompressedRistretto>, Vec<(Scalar, Scalar)>) =
    //     parties
    //         .iter_mut()
    //         .map(|p| {
    //             p.decrypt_share().unwrap();
    //             p.dleq_share(&G, &mut rng, &mut hasher, &mut buf).unwrap();

    //             (
    //                 p.decrypted_share.unwrap().compress(),
    //                 p.share_proof.unwrap(),
    //             )
    //         })
    //         .collect();

    // let mut reconstructed_secrets: Vec<RistrettoPoint> = vec![];
    // for p in &mut parties {
    //     let (mut decrypted_shares, mut share_proofs) =
    //         (decrypted_shares.clone(), share_proofs.clone());

    //     decrypted_shares.remove(p.index - 1);
    //     share_proofs.remove(p.index - 1);
    //     p.ingest_decrypted_shares_and_proofs(&decrypted_shares, share_proofs)
    //         .unwrap();

    //     p.verify_decrypted_shares().unwrap();

    //     reconstructed_secrets.push(p.reconstruct_secret_pessimistic(&lambdas).unwrap());
    // }
}
