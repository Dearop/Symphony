//! Two-layer folding extension (Section 8).
//!
//! For extremely large statement counts, use depth-2 folding:
//! 1. Layer 1: Fold ℓ_np packed statements → one folded statement
//! 2. Split: Decompose into ℓ smaller linear statements using A = [r₁·A', ..., r_ℓ·A']
//! 3. Decompose: Gadget decomposition → ℓ·k_b statements
//! 4. Layer 2: Fold the ℓ·k_b statements (simpler: no Hadamard since already linear)
//! 5. Compile: Two CP-SNARK proofs + one SNARK proof

use crate::commitment::AjtaiParams;
use crate::decomposition;
use crate::folding::{FoldedInstance, FoldedWitness, FoldingProof, FoldingStatement};
use crate::r1cs::R1CSMatrices;
use crate::ring::extension::ExtFieldContext;
use crate::ring::{RingElement, RingVector};
use crate::rok::range_proof::RangeProofParams;

/// Parameters for two-layer folding.
#[derive(Debug, Clone)]
pub struct TwoLayerParams {
    /// Number of blocks ℓ for splitting the folded instance.
    pub num_blocks: usize,
    /// Gadget decomposition base for the second layer.
    pub decomp_base: i64,
    /// Gadget decomposition factor for the second layer.
    pub k_b: usize,
    /// Random scalars r_i for structured MSIS matrix A = [r_1·A', ..., r_ℓ·A'].
    pub block_scalars: Vec<RingElement>,
}

/// Complete two-layer folding proof.
#[derive(Debug, Clone)]
pub struct TwoLayerProof {
    /// Layer 1 folding proof.
    pub layer1_proof: FoldingProof,
    /// Layer 1 folded instance.
    pub layer1_instance: FoldedInstance,
    /// Layer 2 folding proof (simpler: no Hadamard needed).
    pub layer2_proof: FoldingProof,
    /// The final folded instance.
    pub final_instance: FoldedInstance,
    /// Number of variables in the Layer 2 R1CS (needed by verifier).
    pub layer2_n: usize,
}

/// Split a folded witness into ℓ blocks using the structured MSIS matrix.
///
/// Given f* and A = [r_1·A', ..., r_ℓ·A'], decompose f* into ℓ blocks
/// of size n/ℓ each.
fn split_witness(witness: &RingVector, num_blocks: usize) -> Vec<RingVector> {
    assert!(num_blocks > 0, "num_blocks must be positive");
    let block_size = witness.len() / num_blocks;
    let mut blocks = Vec::with_capacity(num_blocks);
    for b in 0..num_blocks {
        let start = b * block_size;
        let end = (start + block_size).min(witness.len());
        blocks.push(RingVector {
            elements: witness.elements[start..end].to_vec(),
        });
    }
    blocks
}

/// Gadget-decompose each block to reduce norms.
fn decompose_blocks(blocks: &[RingVector], base: i64, k_b: usize, _q: u64) -> Vec<RingVector> {
    let mut decomposed = Vec::with_capacity(blocks.len() * k_b);
    for block in blocks {
        // For each ring element in the block, decompose each coefficient
        let n = block.len();
        let mut layers: Vec<Vec<RingElement>> = vec![Vec::with_capacity(n); k_b];

        for elem in &block.elements {
            for (j, coeff) in elem.coeffs.iter().enumerate() {
                let digits = decomposition::decompose(*coeff, base, k_b);
                for (layer, &_digit) in layers.iter_mut().zip(digits.iter()) {
                    if layer.len() <= j / crate::params::D {
                        layer.push(RingElement::zero());
                    }
                }
            }
        }

        // Simpler approach: decompose element-wise
        for layer_idx in 0..k_b {
            let mut layer_elems = Vec::with_capacity(n);
            for elem in &block.elements {
                let mut new_coeffs = [0i64; crate::params::D];
                for (j, &coeff) in elem.coeffs.iter().enumerate() {
                    let digits = decomposition::decompose(coeff, base, k_b);
                    new_coeffs[j] = digits[layer_idx];
                }
                layer_elems.push(RingElement { coeffs: new_coeffs });
            }
            decomposed.push(RingVector {
                elements: layer_elems,
            });
        }
    }
    decomposed
}

/// Run two-layer folding.
pub fn prove_two_layer(
    statements: &[FoldingStatement],
    r1cs: &R1CSMatrices,
    ajtai: &AjtaiParams,
    range_params: &RangeProofParams,
    two_layer_params: &TwoLayerParams,
    ctx: &ExtFieldContext,
) -> (TwoLayerProof, FoldedWitness) {
    let q = ctx.q;

    // Layer 1: Standard high-arity fold
    let (layer1_proof, layer1_witness) =
        crate::folding::prove(statements, r1cs, ajtai, range_params, ctx);
    let layer1_instance = layer1_proof.folded_instance.clone();

    // Split the folded witness into ℓ blocks
    let blocks = split_witness(&layer1_witness.witness, two_layer_params.num_blocks);

    // Decompose each block via gadget decomposition → ℓ·k_b blocks
    let decomposed_blocks = decompose_blocks(
        &blocks,
        two_layer_params.decomp_base,
        two_layer_params.k_b,
        q,
    );

    // Create statements for Layer 2 (linear only, no Hadamard)
    let layer2_n = if decomposed_blocks.is_empty() {
        1
    } else {
        decomposed_blocks[0].len()
    };
    let layer2_ajtai = AjtaiParams::setup(ajtai.kappa, layer2_n, ajtai.q);

    let mut layer2_statements = Vec::with_capacity(decomposed_blocks.len());
    for block in &decomposed_blocks {
        let (c, _) = layer2_ajtai.commit(block);
        layer2_statements.push(FoldingStatement {
            commitment: c,
            public_input: Vec::new(),
            witness: block.clone(),
        });
    }

    // Layer 2: Fold the linear statements
    let layer2_r1cs = R1CSMatrices::new(1, layer2_n, 0);

    let (layer2_proof, layer2_witness) = crate::folding::prove(
        &layer2_statements,
        &layer2_r1cs,
        &layer2_ajtai,
        range_params,
        ctx,
    );
    let final_instance = layer2_proof.folded_instance.clone();

    let proof = TwoLayerProof {
        layer1_proof,
        layer1_instance,
        layer2_proof,
        final_instance: final_instance.clone(),
        layer2_n,
    };

    (proof, layer2_witness)
}

/// Verify a two-layer folding proof.
pub fn verify_two_layer(
    proof: &TwoLayerProof,
    public_inputs: &[Vec<i64>],
    r1cs: &R1CSMatrices,
    ajtai: &AjtaiParams,
    range_params: &RangeProofParams,
    _two_layer_params: &TwoLayerParams,
    ctx: &ExtFieldContext,
) -> Result<FoldedInstance, TwoLayerError> {
    // Verify Layer 1
    let layer1_result = crate::folding::verify(
        &proof.layer1_proof,
        public_inputs,
        r1cs,
        ajtai,
        range_params,
        ctx,
    )
    .map_err(|_| TwoLayerError::Layer1Failed)?;

    // Cross-layer consistency: the Layer 1 folded instance must match the
    // claimed layer1_instance in the proof.
    if layer1_result.commitment.value.elements != proof.layer1_instance.commitment.value.elements {
        return Err(TwoLayerError::SplitFailed);
    }

    // Verify Layer 2
    let empty_inputs: Vec<Vec<i64>> = (0..proof.layer2_proof.gr1cs_proofs.len())
        .map(|_| Vec::new())
        .collect();
    let layer2_r1cs = R1CSMatrices::new(1, proof.layer2_n, 0);

    let layer2_ajtai = AjtaiParams::setup(ajtai.kappa, proof.layer2_n, ajtai.q);
    let _layer2_result = crate::folding::verify(
        &proof.layer2_proof,
        &empty_inputs,
        &layer2_r1cs,
        &layer2_ajtai,
        range_params,
        ctx,
    )
    .map_err(|_| TwoLayerError::Layer2Failed)?;

    Ok(proof.final_instance.clone())
}

#[derive(Debug)]
pub enum TwoLayerError {
    Layer1Failed,
    SplitFailed,
    Layer2Failed,
}
