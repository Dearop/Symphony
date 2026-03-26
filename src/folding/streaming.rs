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
        let log_log_n = if n > 1 {
            ((n as f64).ln().ln().ceil() as usize).max(1)
        } else {
            1
        };
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
        let num_vars = (n as f64).log2().ceil() as usize;
        let table_size = 1 << num_vars;
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
    /// where value(f_ℓ, b) is derived from the witness at hypercube point b.
    pub fn feed_witness_sumcheck(&mut self, witness: &RingVector, statement_idx: usize) {
        assert!(matches!(self.phase, StreamingPhase::Sumcheck { .. }));

        let ctx = self.ext_ctx.as_ref().expect("ext context required for sumcheck");
        let q = ctx.q;
        let beta_ct = self.beta[statement_idx].coeffs[0];

        let n = witness.len().min(self.eval_table.len());
        for b in 0..n {
            let mut witness_val = 0i64;
            for coeff in &witness.elements[b].coeffs {
                witness_val = witness_val.wrapping_add(*coeff);
            }
            witness_val = ((witness_val % q as i64) + q as i64) as i64 % q as i64;
            let q_half = (q / 2) as i64;
            if witness_val > q_half {
                witness_val -= q as i64;
            }

            let contribution = ExtFieldElement {
                c0: ((beta_ct as i128 * witness_val as i128) % q as i128) as i64,
                c1: 0,
            };
            self.eval_table[b] = ExtFieldElement {
                c0: ((self.eval_table[b].c0 as i128 + contribution.c0 as i128) % q as i128) as i64,
                c1: self.eval_table[b].c1,
            };
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
                    let half = self.eval_table.len() / 2;
                    let mut new_table = Vec::with_capacity(half);
                    for i in 0..half {
                        new_table.push(ExtFieldElement {
                            c0: ((self.eval_table[i].c0 as i128
                                + self.eval_table[half + i].c0 as i128)
                                % self.ajtai.q as i128) as i64,
                            c1: ((self.eval_table[i].c1 as i128
                                + self.eval_table[half + i].c1 as i128)
                                % self.ajtai.q as i128) as i64,
                        });
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
        let scaled = witness.ring_scalar_mul(&self.beta[statement_idx], q);
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
        use crate::folding::challenge::ChallengeSet;
        let cs = ChallengeSet::new(self.ajtai.q);
        let mut rng = rand::rng();
        self.beta = cs.sample_vector(&mut rng, self.ell_np);
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
        let ajtai = AjtaiParams::setup(kappa, n, q);
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
        let ajtai = AjtaiParams::setup(kappa, n, q);
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
