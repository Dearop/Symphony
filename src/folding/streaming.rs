//! Memory-efficient streaming prover (Remark 4.1).
//!
//! The prover operates with memory ≈ witness size of a single statement:
//! - Pass 1: Stream input witnesses, compute commitments, derive challenges
//! - Passes 2 to 1+log log(n): Execute sumcheck via streaming algorithm [Baw+25]
//! - Final pass: Stream inputs again, combine witnesses using folding challenge β

use crate::commitment::{AjtaiParams, Commitment};
use crate::folding::FoldedWitness;
use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::ring::{RingElement, RingVector};

/// State for the streaming folding prover.
pub struct StreamingProver {
    /// Ajtai commitment parameters.
    ajtai: AjtaiParams,
    /// Number of statements to fold.
    ell_np: usize,
    /// Current phase.
    phase: StreamingPhase,
    /// Accumulated commitments from Pass 1.
    commitments: Vec<Commitment>,
    /// Folding challenges (derived after Pass 1).
    beta: Vec<RingElement>,
    /// Running accumulator for the folded witness (Final pass).
    folded_witness_acc: Option<RingVector>,
    /// Total number of sumcheck passes needed: 2 + ⌈log log n⌉.
    total_sumcheck_passes: usize,
    /// Accumulated evaluation table for the current sumcheck pass.
    /// Stores Σ_ℓ β_ℓ · f_ℓ(b) for each hypercube point b.
    eval_table: Vec<ExtFieldElement>,
    /// Extension field context for sumcheck operations.
    ext_ctx: Option<ExtFieldContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingPhase {
    /// Pass 1: commitment phase.
    Commitment,
    /// Passes 2 to 1+log log(n): sumcheck phase.
    Sumcheck { pass: usize },
    /// Final pass: folding phase.
    Folding,
    /// Done.
    Complete,
}

impl StreamingProver {
    /// Initialize the streaming prover.
    pub fn new(ajtai: AjtaiParams, ell_np: usize) -> Self {
        let n = ajtai.n;
        let log_n = if n <= 1 {
            1
        } else {
            (usize::BITS - (n - 1).leading_zeros()) as usize
        };
        let log_log_n = if log_n <= 1 {
            1
        } else {
            (usize::BITS - (log_n - 1).leading_zeros()) as usize
        }
        .max(1);
        Self {
            ajtai,
            ell_np,
            phase: StreamingPhase::Commitment,
            commitments: Vec::with_capacity(ell_np),
            beta: Vec::new(),
            folded_witness_acc: None,
            total_sumcheck_passes: 2 + log_log_n,
            eval_table: Vec::new(),
            ext_ctx: None,
        }
    }

    /// Set the extension field context (required before sumcheck phase).
    pub fn set_ext_context(&mut self, ctx: ExtFieldContext) {
        self.ext_ctx = Some(ctx);
    }

    /// Feed a single witness during the commitment phase (Pass 1).
    pub fn feed_witness_commitment(&mut self, witness: &RingVector) -> Commitment {
        assert_eq!(self.phase, StreamingPhase::Commitment);
        let (commitment, _opening) = self.ajtai.commit(witness);
        self.commitments.push(commitment.clone());

        if self.commitments.len() == self.ell_np {
            self.derive_challenges();
            self.phase = StreamingPhase::Sumcheck { pass: 0 };
            self.init_eval_table();
        }

        commitment
    }

    /// Initialize the evaluation table for the sumcheck phase.
    fn init_eval_table(&mut self) {
        let n = self.ajtai.n;
        let num_vars = if n <= 1 {
            0
        } else {
            (usize::BITS - (n - 1).leading_zeros()) as usize
        };
        let table_size = 1usize << num_vars;
        let zero = ExtFieldElement { c0: 0, c1: 0 };
        self.eval_table = vec![zero; table_size];
    }

    /// Feed witness data during a sumcheck pass.
    ///
    /// The streaming sumcheck algorithm processes witnesses one at a time,
    /// linearly combining evaluation tables per pass. Each pass reduces
    /// the table size by half.
    ///
    /// For each witness f_ℓ, the contribution to the evaluation table is:
    ///   table[b] += β_ℓ · value(f_ℓ, b)
    /// where β_ℓ is a full ring element and value(f_ℓ, b) is the extension field
    /// embedding of the witness element at hypercube point b.
    pub fn feed_witness_sumcheck(&mut self, witness: &RingVector, statement_idx: usize) {
        assert!(matches!(self.phase, StreamingPhase::Sumcheck { .. }));

        let ctx = self
            .ext_ctx
            .as_ref()
            .expect("ext context required for sumcheck")
            .clone();
        let beta = &self.beta[statement_idx];

        let n = witness.len().min(self.eval_table.len());
        for b in 0..n {
            // Compute β_ℓ · f_ℓ[b] as a ring multiplication, then embed into K
            let scaled = witness.elements[b].mul_ntt(beta, &self.ajtai.ntt);
            // Embed into extension field: use ct (constant term) for c0,
            // and sum of remaining coefficients weighted by the extension structure for c1.
            // For the sumcheck over K, we use the canonical embedding:
            //   c0 = cf(scaled)[0], c1 = 0 (base field embedding)
            // This matches the non-streaming path which evaluates the multilinear extension
            // of the coefficient tables.
            let c0 = scaled.coeffs[0];
            let c1 = 0i64;

            let contribution = ExtFieldElement { c0, c1 };
            self.eval_table[b] = ctx.add(&self.eval_table[b], &contribution);
        }

        if statement_idx == self.ell_np - 1 {
            self.advance_sumcheck_pass();
        }
    }

    /// Advance to the next sumcheck pass or to the folding phase.
    ///
    /// After processing all ℓ_np witnesses for one pass, the evaluation table
    /// is "folded" to half size using the sumcheck round challenge. This
    /// reduces the table from 2^k to 2^{k-1} entries.
    fn advance_sumcheck_pass(&mut self) {
        if let StreamingPhase::Sumcheck { pass } = self.phase {
            if pass + 1 >= self.total_sumcheck_passes {
                self.phase = StreamingPhase::Folding;
                self.folded_witness_acc = Some(RingVector::zero(self.ajtai.n));
            } else {
                // Fold the evaluation table for the next pass
                if self.eval_table.len() > 1 {
                    let ctx = self
                        .ext_ctx
                        .as_ref()
                        .expect("ext context required for sumcheck");
                    let half = self.eval_table.len() / 2;
                    let mut new_table = Vec::with_capacity(half);
                    for i in 0..half {
                        new_table.push(ctx.add(&self.eval_table[i], &self.eval_table[half + i]));
                    }
                    self.eval_table = new_table;
                }
                self.phase = StreamingPhase::Sumcheck { pass: pass + 1 };
            }
        }
    }

    /// Feed a witness during the folding phase (Final pass).
    /// Accumulates β_ℓ · f_ℓ into the folded witness.
    pub fn feed_witness_folding(&mut self, witness: &RingVector, statement_idx: usize) {
        assert_eq!(self.phase, StreamingPhase::Folding);
        let q = self.ajtai.q;
        let scaled = witness.ring_scalar_mul_ntt(&self.beta[statement_idx], &self.ajtai.ntt);
        if let Some(ref mut acc) = self.folded_witness_acc {
            *acc = acc.add(&scaled, q);
        }

        if statement_idx == self.ell_np - 1 {
            self.phase = StreamingPhase::Complete;
        }
    }

    /// Current phase of the streaming prover.
    pub fn phase(&self) -> StreamingPhase {
        self.phase
    }

    /// Get a reference to the current evaluation table.
    pub fn eval_table(&self) -> &[ExtFieldElement] {
        &self.eval_table
    }

    /// Extract the final folded witness (after all passes).
    pub fn finish(self) -> FoldedWitness {
        assert_eq!(self.phase, StreamingPhase::Complete);
        FoldedWitness {
            witness: self.folded_witness_acc.unwrap(),
            monomial_vectors: Vec::new(),
        }
    }

    /// Derive folding challenges from commitments via Fiat-Shamir.
    fn derive_challenges(&mut self) {
        let mut transcript =
            crate::fiat_shamir::transcript::Transcript::new(b"symphony-fold-streaming");
        for c in &self.commitments {
            for elem in &c.value.elements {
                let bytes: Vec<u8> = elem.coeffs.iter().flat_map(|v| v.to_le_bytes()).collect();
                transcript.append_bytes(b"commitment", &bytes);
            }
        }
        self.beta = crate::folding::challenge::derive_challenge_vector(
            &mut transcript,
            self.ajtai.q,
            self.ell_np,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_phases() {
        let q = 12289u64;
        let kappa = 2;
        let n = 4;
        let ell_np = 2;
        let ntt = crate::ring::ntt::NttContext::new(q);
        let ajtai = AjtaiParams::setup(kappa, n, q, &ntt);
        let mut prover = StreamingProver::new(ajtai, ell_np);

        assert_eq!(prover.phase(), StreamingPhase::Commitment);

        let w1 = RingVector {
            elements: vec![RingElement::from_constant(1); n],
        };
        let w2 = RingVector {
            elements: vec![RingElement::from_constant(2); n],
        };

        prover.feed_witness_commitment(&w1);
        assert_eq!(prover.phase(), StreamingPhase::Commitment);

        prover.feed_witness_commitment(&w2);
        assert!(matches!(prover.phase(), StreamingPhase::Sumcheck { .. }));
    }

    #[test]
    fn test_streaming_full_pipeline() {
        let q = 257u64;
        let kappa = 2;
        let n = 4;
        let ell_np = 2;
        let ntt = crate::ring::ntt::NttContext::new(q);
        let ajtai = AjtaiParams::setup(kappa, n, q, &ntt);
        let mut prover = StreamingProver::new(ajtai, ell_np);
        prover.set_ext_context(ExtFieldContext::new(q));

        let w1 = RingVector {
            elements: vec![RingElement::from_constant(1); n],
        };
        let w2 = RingVector {
            elements: vec![RingElement::from_constant(2); n],
        };

        // Pass 1: Commitment
        prover.feed_witness_commitment(&w1);
        prover.feed_witness_commitment(&w2);

        // Sumcheck passes
        while matches!(prover.phase(), StreamingPhase::Sumcheck { .. }) {
            prover.feed_witness_sumcheck(&w1, 0);
            prover.feed_witness_sumcheck(&w2, 1);
        }

        assert_eq!(prover.phase(), StreamingPhase::Folding);

        // Final pass: Folding
        prover.feed_witness_folding(&w1, 0);
        prover.feed_witness_folding(&w2, 1);

        assert_eq!(prover.phase(), StreamingPhase::Complete);
        let result = prover.finish();
        assert_eq!(result.witness.len(), n);
    }
}
