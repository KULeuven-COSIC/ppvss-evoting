use common::{
    error::ErrorKind::PointDecompressionError,
    random::{random_point, random_scalar},
    utils::precompute_lambda,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto, scalar::Scalar};
use evoting_pi_s_ppvss::{bulletin_board::BulletinBoard, tallier::Tallier, voter::Voter};
use pi_s_ppvss::party::generate_parties;
use rayon::prelude::*;

// const PARAMSET: [(usize, usize, usize); 4] =
// [(128, 9, 4), (128, 17, 8), (256, 256, 127), (512, 512, 255)];
const PARAMSET: [(usize, usize, usize); 3] =
    [(50_000, 17, 8), (100_000, 17, 8), (1_000_000, 17, 8)];

fn tallying(c: &mut Criterion) {
    for (m, n, t) in PARAMSET {
        let lambdas = precompute_lambda(n, t);

        let false_ratio = 0.6;

        let f_count = (m as f64 * false_ratio) as usize;
        let t_count = m - f_count;

        let mut rng = rand::rng();
        let mut hasher = blake3::Hasher::new();
        let mut buf: [u8; 64] = [0u8; 64];

        let G: RistrettoPoint = random_point(&mut rng);
        let G: RistrettoPoint = random_point(&mut rng);

        // Sample random point
        let pk0 = random_point(&mut rng);

        let mut talliers = Tallier::generate_talliers(&G, &mut rng, n, t, &pk0);
        let public_keys: (Vec<CompressedRistretto>, Vec<RistrettoPoint>) = talliers
            .iter()
            .map(|tallier| tallier.party.public_key)
            .collect();

        let mut bulletin_board: BulletinBoard = BulletinBoard::new(&G, &pk0, &public_keys.1, m);

        let mut voters = Voter::generate_voters(m, n, t, &public_keys.0, &pk0);

        voters.iter_mut().enumerate().for_each(|(i, voter)| {
            let (encrypted_shares, (d, z), encrypted_vote, vote_proof) = voter
                .vote(&G, &mut rng, &mut hasher, &mut buf, i < t_count)
                .unwrap();

            let decompressed_encrypted_shares: Vec<RistrettoPoint> = encrypted_shares
                .par_iter()
                .map(|enc_share| enc_share.1)
                .collect();

            bulletin_board.ingest_vote(
                decompressed_encrypted_shares,
                (d, z),
                encrypted_vote.decompress().unwrap(),
                vote_proof.decompress(),
            );
        });

        // voting complete
        bulletin_board.verify_encrypted_shares();

        let compressed_shares: Vec<CompressedRistretto> = bulletin_board
            .sum_encrypted_shares()
            .par_iter()
            .map(|share| share.compress())
            .collect();

        bulletin_board.verify_votes();

        let mut decrypted_shares: Vec<CompressedRistretto> = Vec::with_capacity(n);
        let mut decrypted_share_proofs: Vec<(Scalar, Scalar)> = Vec::with_capacity(n);

        {
            let mut tallier0 = talliers[0].clone();

            let public_keys: Vec<CompressedRistretto> = public_keys
                .0
                .iter()
                .filter(|pk| &tallier0.party.public_key.0 != *pk)
                .copied()
                .collect();

            tallier0.party.ingest_public_keys(&public_keys).unwrap();

            c.bench_function(
                &format!(
                    "(m: {}, n: {}, t: {}) | Pi_S | Tallier: Sum Encrypted Shares",
                    m, n, t
                ),
                |b| b.iter(|| bulletin_board.sum_encrypted_shares()),
            );

            tallier0
                .party
                .ingest_encrypted_shares(&compressed_shares)
                .unwrap();

            c.bench_function(
                &format!(
                    "(m: {}, n: {}, t: {}) | Pi_S | Tallier: Decrypt Share and Generate Proof",
                    m, n, t
                ),
                |b| {
                    b.iter_batched(
                        || (blake3::Hasher::new(), [0u8; 64]),
                        |(mut hasher, mut buf)| {
                            tallier0.party.decrypt_share().unwrap();
                            tallier0
                                .party
                                .dleq_share(&G, &mut rng, &mut hasher, &mut buf)
                                .unwrap();
                        },
                        BatchSize::PerIteration,
                    )
                },
            );
        }

        for tallier in &mut talliers {
            let public_keys: Vec<CompressedRistretto> = public_keys
                .0
                .iter()
                .filter(|pk| &tallier.party.public_key.0 != *pk)
                .copied()
                .collect();

            tallier.party.ingest_public_keys(&public_keys).unwrap();

            tallier
                .party
                .ingest_encrypted_shares(&compressed_shares)
                .unwrap();

            tallier.party.decrypt_share().unwrap();
            tallier
                .party
                .dleq_share(&G, &mut rng, &mut hasher, &mut buf)
                .unwrap();

            decrypted_shares.push(tallier.party.decrypted_share.unwrap().compress());
            decrypted_share_proofs.push(tallier.party.share_proof.unwrap());
        }

        let (mut dec_shares, mut share_proofs) =
            (decrypted_shares.clone(), decrypted_share_proofs.clone());

        dec_shares.remove(talliers[0].party.index - 1);
        share_proofs.remove(talliers[0].party.index - 1);
        talliers[0]
            .party
            .ingest_decrypted_shares_and_proofs(&dec_shares, share_proofs)
            .unwrap();

        c.bench_function(
            &format!(
                "(m: {}, n: {}, t: {}) | Pi_S | Tallier: Tally Votes and Get Result",
                m, n, t
            ),
            |b| {
                b.iter(|| {
                    assert!(talliers[0].party.verify_decrypted_shares(&G).unwrap());

                    let accumulated_encrypted_votes = bulletin_board.tally_encrypted_votes();

                    let recon_secret = talliers[0]
                        .party
                        .reconstruct_secret_pessimistic(&lambdas)
                        .unwrap();

                    let exp_vote = accumulated_encrypted_votes - recon_secret;

                    let mut decrypted_vote = 0.0;

                    for i in 0u64..=bulletin_board.count_valid_votes() as u64 {
                        if exp_vote == G * Scalar::from(i) {
                            decrypted_vote = i as f64;
                            break;
                        }
                    }

                    assert_eq!(decrypted_vote, t_count as f64)
                })
            },
        );
    }
}

fn ballot_verification(c: &mut Criterion) {
    for (_, n, t) in PARAMSET {
        let mut rng = rand::rng();
        let mut hasher = blake3::Hasher::new();
        let mut buf: [u8; 64] = [0u8; 64];

        let G: RistrettoPoint = random_point(&mut rng);

        // Sample random point
        let pk0 = random_point(&mut rng);

        let talliers = Tallier::generate_talliers(&G, &mut rng, n, t, &pk0);
        let public_keys: (Vec<CompressedRistretto>, Vec<RistrettoPoint>) = talliers
            .iter()
            .map(|tallier| tallier.party.public_key)
            .collect();

        let mut bulletin_board: BulletinBoard = BulletinBoard::new(&G, &pk0, &public_keys.1, 1);

        let mut voter = Voter::new(n, t, &public_keys.0, &pk0).unwrap();

        let (encrypted_shares, (d, z), encrypted_vote, vote_proof) = voter
            .vote(&G, &mut rng, &mut hasher, &mut buf, false)
            .unwrap();

        let decompressed_encrypted_shares: Vec<RistrettoPoint> = encrypted_shares
            .par_iter()
            .map(|enc_share| enc_share.1)
            .collect();

        bulletin_board.ingest_vote(
            decompressed_encrypted_shares,
            (d, z),
            encrypted_vote.decompress().unwrap(),
            vote_proof.decompress(),
        );

        c.bench_function(
            &format!(
                "(n: {}, t: {}) | Pi_S | BulletinBoard: Ballot Verification",
                n, t
            ),
            |b| {
                b.iter(|| {
                    bulletin_board.verify_encrypted_shares();
                    bulletin_board.verify_votes();
                })
            },
        );
    }
}

fn cast_ballot(c: &mut Criterion) {
    for (_, n, t) in PARAMSET {
        let mut rng = rand::rng();

        let G: RistrettoPoint = random_point(&mut rng);

        let pk0 = random_point(&mut rng);

        let parties = generate_parties(&G, &mut rng, n, t, &pk0);
        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        let mut voter = Voter::new(n, t, &public_keys, &pk0).unwrap();

        c.bench_function(
            &format!("(n: {}, t: {}) | Pi_S | Voter: Cast Vote", n, t),
            |b| {
                b.iter_batched(
                    || {
                        (
                            blake3::Hasher::new(),
                            blake3::Hasher::new(),
                            [0u8; 64],
                            [0u8; 64],
                        )
                    },
                    |(mut hasher1, mut hasher2, mut buf1, mut buf2)| {
                        let s = random_scalar(&mut rng);
                        let (encrypted_shares, (_, _)) =
                            voter
                                .dealer
                                .deal_secret(&mut rng, &mut hasher1, &mut buf1, &s);

                        let y0 = encrypted_shares[0].decompress().unwrap();

                        voter.generate_vote(&G, &s, false);

                        voter
                            .dleq_vote(&mut rng, &G, &y0, &s, &mut hasher2, &mut buf2)
                            .unwrap()
                    },
                    BatchSize::PerIteration,
                )
            },
        );
    }
}

fn ristretto_point_bench(c: &mut Criterion) {
    let mut rng = rand::rng();
    let x = random_scalar(&mut rng);

    let gx = RistrettoPoint::mul_base(&x);
    let gx_compressed = gx.compress();

    c.bench_function("Basepoint Multiplication", |b| {
        b.iter(|| RistrettoPoint::mul_base(&x))
    });
    c.bench_function("Point Compression", |b| b.iter(|| gx.compress()));
    c.bench_function("Point Decompression", |b| {
        b.iter(|| gx_compressed.decompress().unwrap())
    });
    c.bench_function("Point Decompression Handled", |b| {
        b.iter(|| match gx_compressed.decompress() {
            Some(point) => Ok(point),
            None => Err(PointDecompressionError),
        })
    });
}

criterion_group!(benches, cast_ballot, ballot_verification, tallying);
// criterion_group!(benches, cast_ballot, ballot_verification);
// criterion_group!(benches, tallying);

criterion_main!(benches);
