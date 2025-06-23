# Pre-Constructed Publicly Verifiable Secret Sharing and Applications

This repository supplements the paper titled: [Pre-Constructed Publicly Verifiable Secret Sharing and Applications](https://eprint.iacr.org/2025/576).

## Contents
The Rust workspace contains the following crates:

- (P)PVSS Schemes:
	- `pi_s_pvss`: A reference implementation of the $\Pi_{s}$ PVSS scheme from Baghery's [Π: A Unified Framework for Computational Verifiable Secret Sharing](https://eprint.iacr.org/2023/1669)
	- `schoenmakers`: A reference implementation of Schoenmakers' [A Simple Publicly Verifiable Secret Sharing Scheme and Its Application to Electronic Voting](https://doi.org/10.1007/3-540-48405-1_10)
	- `pi_s_ppvss`: An extension of $\Pi_{s}$, into a PPVSS.
- E-Voting Schemes:
	- `evoting_pi_s_ppvss`: An e-voting scheme based on `pi_s_ppvss`.
	- `evoting_schoenmakers`: An e-voting scheme based on `schoenmakers`.

## Implementation Notes

- These crates may be used independently. They were all implemented using a similar API and optimization techniques for a fair comparison.
- We use Blake3 as our hash function and Curve25519 for discrete logarithm operations.
- Example end-to-end usage is provided under `main.rs` inside each crate.

## Running and Benchmarking
The only requirement to run this code is installing a Rust toolchain (Edition 2024). For reference: [Rust Website](https://www.rust-lang.org/tools/install).

The following commands may be executed in the workspace root for all crates at once, or inside each crate's root individually.

To run benchmarks:
```
cargo bench
```

To run the example end-to-end execution:
```
cargo run --release
```

## License
The contents of this repository are licensed under the MIT License OR Apache-2.0 License.

