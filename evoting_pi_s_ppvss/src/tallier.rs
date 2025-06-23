use curve25519_dalek::{RistrettoPoint, Scalar};
use pi_s_ppvss::{
    error::{Error, ErrorKind::InvalidPararmeterSet},
    party::Party,
};
use rand_chacha::rand_core::CryptoRngCore;

use crate::bulletin_board::BulletinBoard;

#[derive(Clone)]
pub struct Tallier {
    pub party: Party,
    pub bulletin_board: Option<BulletinBoard>,
}

impl Tallier {
    pub fn new<R>(
        G: &RistrettoPoint,
        rng: &mut R,
        n: usize,
        t: usize,
        index: usize,
        pk0: RistrettoPoint,
    ) -> Result<Self, Error>
    where
        R: CryptoRngCore + ?Sized,
    {
        let private_key = Scalar::random(rng);
        let public_key = G * &private_key;

        if index <= n && t < n && t as f32 == ((n - 1) as f32 / 2.0).floor() {
            Ok(Self {
                party: Party {
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
                    encrypted_shares: None,
                    decrypted_shares: None,
                    public_keys: None,
                    validated_shares: vec![],
                    pk0: pk0,
                },
                bulletin_board: None,
            })
        } else {
            Err(InvalidPararmeterSet(n, t as isize, index).into())
        }
    }

    pub fn generate_talliers<R>(
        G: &RistrettoPoint,
        rng: &mut R,
        n: usize,
        t: usize,
        pk0: &RistrettoPoint,
    ) -> Vec<Self>
    where
        R: CryptoRngCore + ?Sized,
    {
        (1..=n)
            .map(|i| Self {
                party: Party::new(G, rng, n, t, i, pk0.clone()).unwrap(),
                bulletin_board: None,
            })
            .collect()
    }
}
