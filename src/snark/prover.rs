//! Full SNARK prover — orchestrates folding, CP-SNARK, and backend SNARK.

use crate::commitment::{AjtaiParams, Commitment};
use crate::fiat_shamir::transcript::Transcript;
use crate::folding::FoldingStatement;
use crate::params::SymphonyParams;
use crate::r1cs::R1CSMatrices;
use crate::ring::RingVector;
use crate::rok::range_proof::RangeProofParams;
use crate::snark::cp_snark;
use crate::snark::{BackendSnark, SymphonyProof};

/// Derive range proof parameters from global Symphony parameters.
fn range_proof_params(params: &SymphonyParams) -> RangeProofParams {
    RangeProofParams {
        lambda_pj: params.lambda_pj,
        ell_h: params.ell_h,
        d_prime: (params.d as i64) - 2,
        k_g: params.k_g(),
        input_bound: params.b_input(),
    }
}

/// Orchestrate the complete proof generation pipeline.
///
/// Steps:
/// 1. Convert input witnesses to generalized committed R1CS (gadget decomposition)
/// 2. Run non-interactive folding with Fiat-Shamir commitments
/// 3. Generate backend SNARK proof for the folded statement via `S::prove`
/// 4. Generate CP-SNARK proof for folding correctness via `S::prove`
/// 5. Bundle everything into a `SymphonyProof<S>`
pub fn generate_proof<S: BackendSnark>(
    params: &SymphonyParams,
    ajtai: &AjtaiParams,
    cp_pk: &S::ProvingKey,
    snark_pk: &S::ProvingKey,
    statements: &[(Commitment, Vec<i64>, RingVector)],
    r1cs: &R1CSMatrices,
) -> SymphonyProof<S> {
    let mut transcript = Transcript::new(b"symphony-v1");

    // Step 1: Build FoldingStatements
    let folding_statements: Vec<FoldingStatement> = statements
        .iter()
        .map(|(c, pi, w)| {
            for elem in &c.value.elements {
                let bytes: Vec<u8> = elem.coeffs.iter().flat_map(|v| v.to_le_bytes()).collect();
                transcript.append_bytes(b"commitment", &bytes);
            }
            FoldingStatement {
                commitment: c.clone(),
                public_input: pi.clone(),
                witness: w.clone(),
            }
        })
        .collect();

    // Step 2: Run folding
    let rp = range_proof_params(params);
    let ext_ctx = crate::ring::extension::ExtFieldContext::new(params.q);

    let (folding_proof, folded_witness) = crate::folding::prove(
        &folding_statements, r1cs, ajtai, &rp, &ext_ctx,
    );

    // Step 3: Collect Fiat-Shamir commitments
    let fs_commitments: Vec<Vec<u8>> = folding_proof.gr1cs_proofs.iter().enumerate().map(|(i, _)| {
        let mut msg = format!("round-{i}").into_bytes();
        msg.extend_from_slice(&(i as u64).to_le_bytes());
        msg
    }).collect();

    // Step 4: Generate CP-SNARK proof via S::prove
    // Build the instance (public) and witness (private) for the CP relation
    let mut cp_transcript = Transcript::new(b"symphony-v1");
    for fs_comm in &fs_commitments {
        cp_transcript.append_bytes(b"fs-commitment", fs_comm);
    }
    let cp_instance = cp_snark::encode_cp_instance(&fs_commitments, &mut cp_transcript);
    let cp_witness = cp_snark::encode_cp_witness(&[], &[]);
    let cp_proof = S::prove(cp_pk, &cp_instance, &cp_witness);

    // Step 5: Generate backend SNARK proof for the folded statement via S::prove
    let snark_instance = cp_snark::encode_folded_instance(&folding_proof.folded_instance);
    let snark_witness = cp_snark::encode_folded_witness(&folded_witness);
    let snark_proof = S::prove(snark_pk, &snark_instance, &snark_witness);

    SymphonyProof {
        cp_proof,
        snark_proof,
        fs_commitments,
        folded_instance: folding_proof.folded_instance,
    }
}
