use common::{
    error::{Error, ErrorKind::InvalidPararmeterSet},
    random::random_scalar,
};
use curve25519_dalek::RistrettoPoint;
use rand::{CryptoRng, RngCore};
use schoenmakers::party::Party;

use crate::bulletin_board::BulletinBoard;

#[derive(Clone)]
pub struct Tallier {
    pub party: Party,
    pub bulletin_board: Option<BulletinBoard>,
}

impl Tallier {
    pub fn new<R>(
        G: &RistrettoPoint,
        H: &RistrettoPoint,
        rng: &mut R,
        n: usize,
        t: usize,
        index: usize,
    ) -> Result<Self, Error>
    where
        R: CryptoRng + RngCore,
    {
        let private_key = random_scalar(rng);
        let public_key = G * &private_key;

        if index <= n && t < n && t as f32 == ((n - 1) as f32 / 2.0).floor() {
            Ok(Self {
                party: Party {
                    G: *G,
                    H: *H,
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
                    dealer_commitments: None,
                    public_keys: None,
                    validated_shares: vec![],
                },
                bulletin_board: None,
            })
        } else {
            Err(InvalidPararmeterSet(n, t as isize, index).into())
        }
    }

    pub fn generate_talliers<R>(
        G: &RistrettoPoint,
        H: &RistrettoPoint,
        rng: &mut R,
        n: usize,
        t: usize,
    ) -> Vec<Self>
    where
        R: CryptoRng + RngCore,
    {
        (1..=n)
            .map(|i| Self {
                party: Party::new(*G, *H, rng, n, t, i).unwrap(),
                bulletin_board: None,
            })
            .collect()
    }
}
