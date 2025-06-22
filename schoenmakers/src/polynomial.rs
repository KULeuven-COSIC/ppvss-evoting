use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto, scalar::Scalar};
use rand_chacha::rand_core::CryptoRngCore;

use rayon::prelude::*;

#[derive(Clone)]
pub struct Polynomial {
    pub(crate) coefficients: Vec<Scalar>,
}

impl Polynomial {
    pub(crate) fn len(&self) -> usize {
        self.coefficients.len()
    }

    pub(crate) fn coef_at(&self, index: usize) -> Option<Scalar> {
        if index < self.len() {
            Some(self.coefficients[index])
        } else {
            None
        }
    }
    pub(crate) fn sample<R>(degree: usize, rng: &mut R) -> Self
    where
        R: CryptoRngCore + ?Sized,
    {
        let coefs_1 = (0..=degree).map(|_| Scalar::random(rng)).collect();

        Polynomial {
            coefficients: coefs_1,
        }
    }
    pub(crate) fn sample_set_f0<R>(degree: usize, rng: &mut R, f0: &Scalar) -> Self
    where
        R: CryptoRngCore + ?Sized,
    {
        let mut coefs: Vec<Scalar> = (0..=degree).map(|_| Scalar::random(rng)).collect();
        coefs[0] = *f0;

        Polynomial {
            coefficients: coefs,
        }
    }
    pub(crate) fn evaluate(&self, x: usize) -> Scalar {
        let mut x_powers: Vec<Scalar> = vec![Scalar::ONE, Scalar::from(x as u64)];

        for i in 2..self.coefficients.len() {
            x_powers.push(x_powers[1] * x_powers[i - 1]);
        }

        self.coefficients
            .par_iter()
            .zip(x_powers)
            .map(|(coef, x_pow)| coef * x_pow)
            .sum()
    }

    pub(crate) fn evaluate_multiply(
        &self,
        points: &Vec<RistrettoPoint>,
    ) -> (Vec<Scalar>, Vec<CompressedRistretto>) {
        points
            .par_iter()
            .enumerate()
            .map(|(i, point)| {
                // (i = 0 => 1st party (x = 1))
                // i is the index of the party
                // i+1 here means start evaluating at x=1
                // x_powers[0] <= constant term multiplier
                // x_powers[1] = x(^1)
                let mut x_powers: Vec<Scalar> = vec![Scalar::ONE, Scalar::from((i + 1) as u64)];

                // x_powers[2] = x_powers[1] * x_powers[2-1] == x_powers[1] * x_powers[1] = x * x = x^2
                // x_powers[3] = x_powers[1] * x_powers[3-1] == x_powers[1] * x_powers[2] = x * x^2 == x^3
                // ...
                // i+1 here means start evaluating at till x = 32
                for j in 2..self.coefficients.len() {
                    x_powers.push(x_powers[1] * x_powers[j - 1]);
                }

                let f_val = self
                    .coefficients
                    .iter()
                    .zip(x_powers)
                    .fold(Scalar::ZERO, |acc_f, (coef_f, x_pow)| {
                        acc_f + coef_f * x_pow
                    });

                (f_val, (f_val * point).compress())
            })
            .unzip()
    }

    pub(crate) fn sum(&self, p: &Polynomial) -> Self {
        Self {
            coefficients: self
                .coefficients
                .par_iter()
                .zip(p.coefficients.par_iter())
                .map(|(a, b)| a + b)
                .collect(),
        }
    }

    pub(crate) fn coef_op(&self, f: fn(Scalar, Scalar) -> Scalar, x: &Scalar) -> Self {
        Self {
            coefficients: self
                .coefficients
                .par_iter()
                .map(|coef| f(*coef, *x))
                .collect(),
        }
    }
    pub(crate) fn coef_op_in_place(&mut self, f: fn(Scalar, Scalar) -> Scalar, x: &Scalar) {
        self.coefficients
            .par_iter_mut()
            .for_each(|coef| *coef = f(*coef, *x));
    }
}

impl std::fmt::Display for Polynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.coefficients
                .par_iter()
                .map(|coef| format!("{:x?}", coef.as_bytes()))
                .collect::<Vec<String>>()
                .join(",")
        )
    }
}
