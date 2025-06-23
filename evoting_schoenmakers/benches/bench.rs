use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, RistrettoPoint};
use evoting_schoenmakers::{bulletin_board::BulletinBoard, tallier::Tallier, voter::Voter};
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaChaRng;
use rayon::prelude::*;
use schoenmakers::{error::ErrorKind::PointDecompressionError, utils::precompute_lambda};
use zeroize::Zeroize;

const PARAMSET: [(usize, usize, usize); 4] =
    [(128, 9, 4), (128, 17, 8), (256, 256, 127), (512, 512, 255)];
// const PARAMSET: [(usize, usize, usize); 3] =
// [(50_000, 17, 8), (100_000, 17, 8), (1_000_000, 17, 8)];

fn tallying(c: &mut Criterion) {
    for (m, n, t) in PARAMSET {
        let lambdas = precompute_lambda(n, t);

        let false_ratio = 0.6;

        let f_count = (m as f64 * false_ratio) as usize;
        let t_count = m - f_count;

        let mut rng = ChaChaRng::from_rng(thread_rng()).unwrap();
        let mut hasher = blake3::Hasher::new();
        let mut buf: [u8; 64] = [0u8; 64];

        let G: RistrettoPoint = RistrettoPoint::random(&mut rng);
        let H: RistrettoPoint = RistrettoPoint::random(&mut rng);

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
                    "(m: {}, n: {}, t: {}) | Sch | Tallier: Sum Encrypted Shares",
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
                    "(m: {}, n: {}, t: {}) | Sch | Tallier: Decrypt Share and Generate Proof",
                    m, n, t
                ),
                |b| {
                    b.iter_batched(
                        || (blake3::Hasher::new(), [0u8; 64]),
                        |(mut hasher, mut buf)| {
                            tallier0.party.decrypt_share().unwrap();
                            tallier0
                                .party
                                .dleq_share(&mut rng, &mut hasher, &mut buf)
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
                .dleq_share(&mut rng, &mut hasher, &mut buf)
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
                "(m: {}, n: {}, t: {}) | Sch | Tallier: Tally Votes and Get Result",
                m, n, t
            ),
            |b| {
                b.iter(|| {
                    assert!(talliers[0].party.verify_decrypted_shares().unwrap());

                    let recon_secret = talliers[0].party.reconstruct_secret(&lambdas).unwrap();

                    let accumulated_encrypted_votes = bulletin_board.tally_encrypted_votes();

                    let exp_vote = accumulated_encrypted_votes - recon_secret;

                    let mut decrypted_vote = 0.0;

                    for i in 0u64..=bulletin_board.count_valid_votes() as u64 {
                        if exp_vote == G * Scalar::from(i) {
                            decrypted_vote = i as f64;
                            break;
                        }
                    }

                    assert_eq!(decrypted_vote, t_count as f64);
                })
            },
        );
    }
}

fn ballot_verification(c: &mut Criterion) {
    for (_, n, t) in PARAMSET {
        let mut rng = ChaChaRng::from_rng(thread_rng()).unwrap();
        let mut hasher = blake3::Hasher::new();
        let mut buf: [u8; 64] = [0u8; 64];

        let G: RistrettoPoint = RistrettoPoint::random(&mut rng);
        let H: RistrettoPoint = RistrettoPoint::random(&mut rng);

        let talliers = Tallier::generate_talliers(&G, &H, &mut rng, n, t);
        let public_keys: (Vec<CompressedRistretto>, Vec<RistrettoPoint>) = talliers
            .iter()
            .map(|tallier| tallier.party.public_key)
            .collect();

        let mut voter = Voter::new(&G, &H, n, t, &public_keys.0).unwrap();

        let mut bulletin_board: BulletinBoard = BulletinBoard::new(&G, &H, &public_keys.1, 1, n, t);

        let (encrypted_shares, (d, z), dealer_commitments, encrypted_vote, vote_proof) =
            voter.vote(&mut rng, &mut hasher, &mut buf, false).unwrap();

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

        c.bench_function(
            &format!(
                "(n: {}, t: {}) | Sch | BulletinBoard: Ballot Verification",
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
        let mut rng = ChaChaRng::from_rng(thread_rng()).unwrap();

        let G: RistrettoPoint = RistrettoPoint::random(&mut rng);
        let H: RistrettoPoint = RistrettoPoint::random(&mut rng);

        let talliers = Tallier::generate_talliers(&G, &H, &mut rng, n, t);
        let public_keys: (Vec<CompressedRistretto>, Vec<RistrettoPoint>) = talliers
            .iter()
            .map(|tallier| tallier.party.public_key)
            .collect();

        let mut voter = Voter::new(&G, &H, n, t, &public_keys.0).unwrap();

        c.bench_function(
            &format!("(n: {}, t: {}) | Sch | Voter: Cast Vote", n, t),
            |b| {
                b.iter_batched(
                    || (blake3::Hasher::new(), [0u8; 64]),
                    |(mut hasher, mut buf)| {
                        let s = Scalar::random(&mut rng);
                        let (_, (_, _), dealer_commitments) =
                            voter.dealer.deal_secret(&mut rng, &mut hasher, &mut buf, s);

                        let c0 = dealer_commitments[0].decompress().unwrap();

                        voter.generate_vote(&s, false);

                        voter
                            .dleq_vote(&mut rng, &c0, &s, &mut hasher, &mut buf)
                            .unwrap()
                    },
                    BatchSize::PerIteration,
                )
            },
        );
    }
}

fn ristretto_point_bench(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_rng(thread_rng()).unwrap();
    let x = Scalar::random(&mut rng);

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

// criterion_group!(benches, cast_ballot, ballot_verification, tallying);
criterion_group!(benches, cast_ballot, ballot_verification);
criterion_main!(benches);
