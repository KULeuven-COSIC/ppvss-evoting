use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto, scalar::Scalar};
use schoenmakers::{
    dealer::Dealer,
    error::ErrorKind::PointDecompressionError,
    utils::{generate_parties, precompute_lambda},
};

use rand::{SeedableRng, thread_rng};
use rand_chacha::ChaChaRng;

fn pvss(c: &mut Criterion) {
    for (n, t) in [
        (64, 31),
        (128, 63),
        (256, 127),
        (512, 255),
        (1024, 511),
        (2048, 1023),
    ] {
        let mut rng = ChaChaRng::from_rng(thread_rng()).unwrap();

        let secret = Scalar::random(&mut rng);

        let G: RistrettoPoint = RistrettoPoint::mul_base(&Scalar::random(&mut rng));
        let H: RistrettoPoint = RistrettoPoint::mul_base(&Scalar::random(&mut rng));
        assert_ne!(G, H);

        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64];

        let lambdas = precompute_lambda(n, t);

        let mut parties = generate_parties(G, H, &mut rng, n, t);

        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        let mut dealer = Dealer::new(H, n, t, &public_keys).unwrap();

        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        for party in &mut parties {
            let public_keys: Vec<CompressedRistretto> = public_keys
                .iter()
                .filter(|pk| &party.public_key.0 != *pk)
                .copied()
                .collect();

            party.ingest_public_keys(&public_keys).unwrap();
        }

        let (encrypted_shares, (d, z), commitments) =
            dealer.deal_secret(&mut rng, &mut hasher, &mut buf, secret);

        c.bench_function(
            &format!(
                "(n: {}, t: {}) | Sch PPVSS | Sch PPVSS | Dealer: Deal Secret",
                n, t
            ),
            |b| {
                b.iter_batched(
                    || (blake3::Hasher::new(), [0u8; 64]),
                    |(mut hasher, mut buf)| {
                        dealer.deal_secret(&mut rng, &mut hasher, &mut buf, secret)
                    },
                    BatchSize::PerIteration,
                )
            },
        );

        for p in &mut parties {
            p.ingest_encrypted_shares(&encrypted_shares).unwrap();
            p.ingest_dealer_proof(d, z.clone()).unwrap();
            p.ingest_commitments(&commitments).unwrap();

            // let res = p.verify_encrypted_shares(&mut hasher, &mut buf).unwrap();

            // assert!(res, "encrypted share verification failure");
        }

        c.bench_function(
            &format!(
                "(n: {}, t: {}) | Sch PPVSS | Party: Verify Encrypted Shares",
                n, t
            ),
            |b| {
                b.iter_batched(
                    || (blake3::Hasher::new(), [0u8; 64]),
                    |(mut hasher, mut buf)| {
                        assert!(
                            parties[0]
                                .verify_encrypted_shares(&mut hasher, &mut buf)
                                .unwrap()
                        )
                    },
                    BatchSize::PerIteration,
                )
            },
        );
    }
}
// fn pvss(c: &mut Criterion) {
//     for (n, t) in [
//         (64, 31),
//         (128, 63),
//         (256, 127),
//         (512, 255),
//         (1024, 511),
//         (2048, 1023),
//     ] {
//         let mut rng = ChaChaRng::from_rng(thread_rng()).unwrap();
//         let mut hasher = blake3::Hasher::new();
//         let mut buf: [u8; 64] = [0u8; 64];

//         let G: RistrettoPoint = RistrettoPoint::mul_base(&Scalar::random(&mut rng));
//         let H: RistrettoPoint = RistrettoPoint::mul_base(&Scalar::random(&mut rng));

//         let mut parties = generate_parties(G, H, &mut rng, n, t);

//         let public_keys: Vec<CompressedRistretto> =
//             parties.iter().map(|party| party.public_key.0).collect();
//         let mut dealer = Dealer::new(G, n, t, &public_keys).unwrap();

//         let public_keys: Vec<CompressedRistretto> =
//             parties.iter().map(|party| party.public_key.0).collect();

//         for party in &mut parties {
//             let public_keys: Vec<CompressedRistretto> = public_keys
//                 .iter()
//                 .filter(|pk| &party.public_key.0 != *pk)
//                 .copied()
//                 .collect();

//             party.ingest_public_keys(&public_keys).unwrap();
//         }

//         let secret = Scalar::random(&mut rng);

//         let (encrypted_shares, (d, z), commitments) =
//             dealer.deal_secret(&mut rng, &mut hasher, &mut buf, secret);

//         c.bench_function(
//             &format!("(n: {}, t: {}) | Sch PPVSS | Dealer: Deal Secret", n, t),
//             |b| {
//                 b.iter_batched(
//                     || (blake3::Hasher::new(), [0u8; 64]),
//                     |(mut hasher, mut buf)| {
//                         dealer.deal_secret(&mut rng, &mut hasher, &mut buf, secret)
//                     },
//                     BatchSize::PerIteration,
//                 )
//             },
//         );

//         for p in &mut parties {
//             p.ingest_encrypted_shares(&encrypted_shares).unwrap();
//             p.ingest_dealer_proof(d, z.clone()).unwrap();
//             p.ingest_commitments(&commitments).unwrap();

//             let res = p.verify_encrypted_shares(&mut hasher, &mut buf).unwrap();

//             assert!(res, "encrypted share verification failure");
//         }

//         c.bench_function(
//             &format!("(n: {}, t: {}) | Sch PPVSS | Party: Verify Encrypted Shares", n, t),
//             |b| {
//                 b.iter_batched(
//                     || (blake3::Hasher::new(), [0u8; 64]),
//                     |(mut hasher, mut buf)| {
//                         assert!(parties[0]
//                             .verify_encrypted_shares(&mut hasher, &mut buf)
//                             .unwrap())
//                     },
//                     BatchSize::PerIteration,
//                 )
//             },
//         );

//         let (decrypted_shares, share_proofs): (Vec<CompressedRistretto>, Vec<(Scalar, Scalar)>) =
//             parties
//                 .iter_mut()
//                 .map(|p| {
//                     p.decrypt_share().unwrap();
//                     p.dleq_share(&mut rng, &mut hasher, &mut buf).unwrap();
//                     (
//                         p.decrypted_share.unwrap().compress(),
//                         p.share_proof.unwrap(),
//                     )
//                 })
//                 .collect();

//         c.bench_function(
//             &format!("(n: {}, t: {}) | Sch PPVSS | Party: Decrypt Share", n, t),
//             |b| b.iter(|| parties[0].decrypt_share().unwrap()),
//         );

//         c.bench_function(
//             &format!("(n: {}, t: {}) | Sch PPVSS | Party: Generate Proof", n, t),
//             |b| {
//                 b.iter_batched(
//                     || (blake3::Hasher::new(), [0u8; 64]),
//                     |(mut hasher, mut buf)| {
//                         parties[0]
//                             .dleq_share(&mut rng, &mut hasher, &mut buf)
//                             .unwrap()
//                     },
//                     BatchSize::PerIteration,
//                 )
//             },
//         );

//         for p in &mut parties {
//             let (mut decrypted_shares, mut share_proofs) =
//                 (decrypted_shares.clone(), share_proofs.clone());

//             decrypted_shares.remove(p.index - 1);
//             share_proofs.remove(p.index - 1);
//             p.ingest_decrypted_shares_and_proofs(&decrypted_shares, share_proofs)
//                 .unwrap();
//         }

//         c.bench_function(
//             &format!("(n: {}, t: {}) | Sch PPVSS | Party: Verify Decrypted Shares", n, t),
//             |b| {
//                 b.iter(|| {
//                     parties[0].verify_decrypted_shares().unwrap();
//                 })
//             },
//         );

//         let lambdas = precompute_lambda(t);

//         c.bench_function(
//             &format!("(n: {}, t: {}) | Sch PPVSS | Party: Reconstruct Secret", n, t),
//             |b| {
//                 b.iter(|| {
//                     parties[0].reconstruct_secret(&lambdas).unwrap();
//                 })
//             },
//         );
//     }
// }

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

// criterion_group!(benches, pvss, ristretto_point_bench,);
criterion_group!(benches, pvss,);
criterion_main!(benches);
