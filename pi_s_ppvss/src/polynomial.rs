use common::random::random_scalar;
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto, scalar::Scalar};
use rand::{CryptoRng, RngCore};

use rayon::prelude::*;

#[derive(Clone)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    pub(crate) fn len(&self) -> usize {
        self.coefficients.len()
    }

    pub(crate) fn sample_two_set_f0<R>(degree: usize, f0: &Scalar, rng: &mut R) -> (Self, Self)
    where
        R: CryptoRng + RngCore,
    {
        let (mut coefs_1, coefs_2): (Vec<Scalar>, Vec<Scalar>) = (0..=degree)
            .map(|_| (random_scalar(rng), random_scalar(rng)))
            .collect();

        coefs_1[0] = *f0;

        (
            Polynomial {
                coefficients: coefs_1,
            },
            Polynomial {
                coefficients: coefs_2,
            },
        )
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

    pub(crate) fn evaluate_multiply(&self, points: &Vec<RistrettoPoint>) -> Vec<RistrettoPoint> {
        points
            .par_iter()
            .enumerate()
            .map(|(i, point)| {
                let mut x_powers: Vec<Scalar> = vec![Scalar::ONE, Scalar::from((i) as u64)];

                for j in 2..self.coefficients.len() {
                    x_powers.push(x_powers[1] * x_powers[j - 1]);
                }
                point
                    * self
                        .coefficients
                        .iter()
                        .zip(x_powers)
                        .fold(Scalar::ZERO, |acc, (coef, x_pow)| acc + coef * x_pow)
            })
            .collect()
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

    pub(crate) fn sum_in_place(&mut self, p: &Polynomial) {
        self.coefficients
            .par_iter_mut()
            .zip(p.coefficients.par_iter())
            .for_each(|(a, b)| *a += b);
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
    pub(crate) fn mul_sum(&mut self, mul_val: &Scalar, p2: &Self) {
        self.coefficients
            .par_iter_mut()
            .zip(p2.coefficients.par_iter())
            .for_each(|(p1_coef, p2_coef)| {
                *p1_coef *= mul_val;
                *p1_coef += p2_coef
            });
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
