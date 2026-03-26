//! Parameter generation and MSIS matrix sampling for commitments.

use crate::commitment::AjtaiParams;
use crate::params::SymphonyParams;

/// Generate Ajtai commitment parameters from the global Symphony parameters.
pub fn generate_ajtai_params(params: &SymphonyParams) -> AjtaiParams {
    AjtaiParams::setup(params.kappa, params.n(), params.q)
}

/// Structured MSIS matrix for two-layer folding (Section 8):
/// A = [r_1 · A', r_2 · A', ..., r_ℓ · A']
/// where A' is shared and r_i are random ring elements.
pub fn generate_structured_ajtai_params(
    params: &SymphonyParams,
    num_blocks: usize,
) -> (AjtaiParams, Vec<crate::ring::RingElement>) {
    use rand::RngExt;

    let block_size = params.n() / num_blocks;
    let a_prime = AjtaiParams::setup(params.kappa, block_size, params.q);

    let mut rng = rand::rng();
    let q = params.q;
    let scalars: Vec<crate::ring::RingElement> = (0..num_blocks)
        .map(|_| {
            let mut coeffs = [0i64; crate::params::D];
            for c in coeffs.iter_mut() {
                let v: u64 = rng.random_range(0..q);
                *c = if v > q / 2 { v as i64 - q as i64 } else { v as i64 };
            }
            crate::ring::RingElement { coeffs }
        })
        .collect();

    // Construct the full matrix A = [r_1·A', ..., r_ℓ·A']
    let mut full_a = Vec::with_capacity(params.kappa);
    for i in 0..params.kappa {
        let mut row = Vec::with_capacity(params.n());
        for (_block_idx, r) in scalars.iter().enumerate().take(num_blocks) {
            for j in 0..block_size {
                row.push(a_prime.a[i][j].mul(r, q));
            }
        }
        full_a.push(row);
    }

    let full_params = AjtaiParams {
        a: full_a,
        kappa: params.kappa,
        n: params.n(),
        q,
    };

    (full_params, scalars)
}
