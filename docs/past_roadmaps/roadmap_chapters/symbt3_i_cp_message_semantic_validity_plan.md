# SYMBT3-I: CP Message Semantic Validity

## Summary

Add the next cumulative non-authoritative SYMBT3 profile: prove that the
committed CP round-message oracles actually feed the algebraic folding relation.

> **Current status (2026-05-20): implemented and refined by I2.** The message
> semantic layout exists as `Symbt3MessageSemanticLayout` under
> `src/modular/batched_cp/`. Current cumulative relation descriptions require
> `BatchedCpSymbt3ConstraintFamily::RoundMessageLayoutValidity`,
> `RoundChallengePrefixBinding`, `NativeMessageOracleViews`,
> `SumcheckRoundClaimTransition`, `SumcheckFinalLocalClaimBinding`, and
> `FoldingMessageBoundaryConsistency` through `has_symbt3_i_families()`.
>
> The original I profile's dense `MessageToTraceColumnBinding` copy path exists
> as historical/baseline machinery, but the live default was refined by
> `SYMBT3-I2`: trace values that are typed coordinates of `M_r(T,U)` are
> consumed as native message-oracle views instead of duplicate trace columns
> with per-coordinate copy constraints. Current benchmark and report language
> should prefer `symbt3_i2_vs_k` for the live message-semantic profile.
>
> Product `verify_public` remains the authoritative monolithic WHIR typed-CP
> route and does not route through I/I2 directly. I/I2/SYMBT3 development
> profiles remain `NonAuthoritativeDevelopment` / `NonZkDevelopment` unless
> selected by explicit NonZK accumulator routes such as K6a or N8.

SYMBT3-H anchored the source columns to the batch manifest. The original
SYMBT3-I plan anchored the message oracles to the algebraic transcript and
folding checks.

The goal is to move from:

```text
source columns are manifest-bound;
algebraic columns are internally consistent;
message roots are transcript-bound.
```

to:

```text
the committed message oracles are the semantic folding messages consumed by
the SYMBT3 algebraic checks.
```

The original I/I2 line preserved:

- `NonAuthoritativeDevelopment`
- `NonZkDevelopment`
- one top-level WHIR proof object
- zero `family_columnar_subproofs`
- one backend table
- `RelationDescription::num_constraints == 0`
- no appended typed CP R1CS
- no witness-side verifier checks
- no byte transcript/hash/opening reconstruction
- no product `verify_public` routing change

This is exactly the Symphony boundary: the verifier derives Fiat-Shamir
challenges outside the proven relation, while the CP proof proves that the
committed messages form a valid folding proof. Symphony's CP compiler explicitly
avoids embedding Fiat-Shamir circuits and commitment-opening checks inside the
SNARK statement; it instead proves the folding algebra against committed prover
messages.

## One-Sentence Definition

SYMBT3-I is the cumulative non-authoritative SYMBT3 profile that proves the
committed CP round-message oracles are semantically consistent with the
sumcheck/folding/algebra columns used by SYMBT3, without proving byte encodings,
Fiat-Shamir hash construction, or commitment openings as ordinary circuit logic.

## 1. What SYMBT3-I Should Prove

For each CP/folding round `r`, there is a committed message oracle:

```text
M_r(T, U_r)
```

where:

- `T` is the batch item or product-domain row.
- `U_r` is the typed coordinate within the round-`r` message.

SYMBT3-I should prove that the algebraic trace columns already used by A-H are
derived from these message oracles.

At a high level, it should prove:

1. Each round message oracle `M_r` has the expected typed layout.
2. Transcript challenges `r_i` are derived externally from the correct prefix of
   message roots and input-side public data.
3. Algebraic columns used in folded-output, GR1CS, Ajtai, norm/range, and
   manifest checks are read from or derived from the committed `M_r` oracles.
4. Sumcheck-style round messages satisfy the expected claim-transition
   equations.
5. The final sumcheck/local evaluation claims are consistent with the existing
   SYMBT3 residual/evaluator families.

It should not prove:

- Poseidon byte transcript construction
- canonical message-section reconstruction
- FS opening bytes
- digest-body equality tables
- Merkle path verification as an in-relation circuit

The message roots are the CP commitment boundary. WHIR/BCS already handles
oracle commitments and openings at the proof-system layer; SYMBT3-I should
prove semantic equations over the committed oracle values.

## 2. New Constraint Families

Add a versioned family set such as:

```rust
BatchedCpSymbt3ConstraintFamily::RoundMessageLayoutValidity
BatchedCpSymbt3ConstraintFamily::RoundChallengePrefixBinding
BatchedCpSymbt3ConstraintFamily::NativeMessageOracleViews
BatchedCpSymbt3ConstraintFamily::SumcheckRoundClaimTransition
BatchedCpSymbt3ConstraintFamily::SumcheckFinalLocalClaimBinding
BatchedCpSymbt3ConstraintFamily::FoldingMessageBoundaryConsistency
```

Keep these under one generalized WHIR relation, not as separate backend proofs.

Family meanings:

- `RoundMessageLayoutValidity`: each `M_r` uses the expected typed algebraic
  layout.
- `RoundChallengePrefixBinding`: challenge `r_r` is the verifier-derived
  challenge from the correct prefix transcript. This checks challenge values as
  public constants, not hash bytes.
- `NativeMessageOracleViews`: algebra columns used by SYMBT3 are sourced from
  typed coordinates read from `M_r` without materializing duplicate copy
  columns in the default I2 profile.
- `SumcheckRoundClaimTransition`: round message polynomials/evaluations satisfy
  the normal sumcheck transition equations.
- `SumcheckFinalLocalClaimBinding`: final claim from message transcript agrees
  with the local residual/evaluator claim already checked by D/E/F/G/H.
- `FoldingMessageBoundaryConsistency`: folded output / accumulator boundary
  coordinates exposed in the public statement match the committed message
  transcript semantics.

The first I profile used the denser `MessageToTraceColumnBinding` copy path.
The current I2 profile keeps the same semantic boundary while replacing that
copy path with native message-oracle views:

- `RoundMessageLayoutValidity`
- `RoundChallengePrefixBinding`
- `NativeMessageOracleViews`
- `SumcheckRoundClaimTransition`
- `SumcheckFinalLocalClaimBinding`
- `FoldingMessageBoundaryConsistency`

Conceptually, I is the message-semantics gate.

## 3. New Layouts

Add:

```rust
pub struct Symbt3MessageSemanticLayoutV1 {
    pub version_marker: [u8; 8], // e.g. b"SYMBT3I\0"

    pub round_count: usize,
    pub round_layouts: Vec<Symbt3RoundMessageLayoutV1>,

    pub challenge_schedule: Symbt3ChallengeScheduleV1,

    pub message_oracle_layout_digest: Digest,
    pub algebra_law_digest: Digest,
    pub gr1cs_layout_digest: Digest,
    pub ajtai_layout_digest: Digest,
    pub norm_range_layout_digest: Digest,
    pub manifest_layout_digest: Digest,

    pub selector_evaluator: Symbt3SelectorEvaluatorId,
    pub padding_policy: Symbt3PaddingPolicy,

    pub semantic_mode: Symbt3MessageSemanticMode,
}
```

Round layout:

```rust
pub struct Symbt3RoundMessageLayoutV1 {
    pub round_index: usize,
    pub message_root: Digest,

    pub coordinate_axis: AxisLayout,
    pub section_axis: AxisLayout,

    pub sections: Vec<Symbt3MessageSectionLayoutV1>,

    pub source_column_bindings: Vec<Symbt3MessageColumnBindingV1>,
    pub trace_column_bindings: Vec<Symbt3MessageColumnBindingV1>,
}
```

Message section layout:

```rust
pub struct Symbt3MessageSectionLayoutV1 {
    pub section_kind: Symbt3MessageSectionKind,
    pub coordinate_len: usize,
    pub algebra_type: Symbt3MessageAlgebraType,
    pub visibility: Symbt3MessageVisibility,
    pub binding_mode: Symbt3MessageBindingMode,
}
```

Suggested section kinds:

```rust
pub enum Symbt3MessageSectionKind {
    SumcheckRoundPolynomial,
    SumcheckClaimValue,
    EvaluationPoint,
    EvaluationValue,
    FoldedOutputCoordinate,
    FoldedGr1csCoordinate,
    AjtaiOpeningCoordinate,
    AjtaiCommitmentCoordinate,
    ProjectionCoordinate,
    RangeWitnessCoordinate,
    BoundaryDigestCoordinate,
}
```

Do not include byte sections such as:

- `HeaderBytes`
- `DigestBodyBytes`
- `FsOpeningBytes`
- `CanonicalMessageBytes`
- `PoseidonTraceBytes`

That would regress toward SYMBT2F.

## 4. Transcript Schedule

Keep the current split:

- `folding_protocol_id`
- `proof_relation_id`
- `proof_public_statement_digest`

### `folding_protocol_id`

Bind semantic message structure:

- `shape_id`
- batch-size policy
- active-count policy
- input public-boundary layout
- batch manifest layout
- source column layout
- message oracle layout
- message semantic layout
- Ajtai/R1CS/GR1CS shape digests
- `Symbt3AlgebraLaw` digest
- Ajtai norm/range policy digest
- folding challenge schedule version

### `folding_transcript_digest`

Bind input-side data only:

```text
folding_transcript_digest = H(
    "SYMBT3-FOLDING-TRANSCRIPT",
    folding_protocol_id,
    input_public_boundary_digest,
    batch_manifest_root,
    source_assignment_roots,
    source_ajtai_commitment_digest,
    message_oracle_roots,
    batch_size,
    active_count
)
```

Then challenges are derived prefix-wise:

```text
r_i = H(
    "SYMBT3-ROUND-CHALLENGE",
    folding_protocol_id,
    input_public_boundary_digest,
    batch_manifest_root,
    message_oracle_roots[0..=i],
    prior_challenge_digest,
    i
)
```

or whatever exact schedule the folding protocol uses. The important invariant is:

```text
round challenge i depends only on input-side transcript data and the correct
message-root prefix;
it does not depend on folded output, proof oracle roots, or later messages.
```

### Proof-Checking Challenges

The random challenges used to check message-semantics constraints are different:

```text
rho_msg = H(
    "SYMBT3-I-MESSAGE-SEMANTICS",
    proof_relation_id,
    proof_public_statement_digest,
    message_semantic_layout_digest,
    symbt3_i_oracle_root,
    WHIR params digest
)
```

Those are sampled after proof oracles and output-side statement data are bound.

So:

```text
folding challenges:
    input-side protocol randomness

rho_msg / sumcheck verifier randomness:
    proof-checking randomness
```

## 5. Public Statement Changes

Extend the SYMBT3 development public statement with message-semantic digests:

```rust
pub struct BatchedCpSymbt3PublicStatement {
    pub folding_protocol_id: Digest,
    pub proof_relation_id: Digest,

    pub input_public_boundary_digest: Digest,
    pub batch_manifest_root: Digest,
    pub batch_manifest_layout_digest: Digest,
    pub source_column_layout_digest: Digest,

    pub source_assignment_roots: Vec<Digest>,
    pub message_oracle_roots: Vec<Digest>,
    pub message_semantic_layout_digest: Digest,

    pub source_ajtai_commitment_digest: Digest,

    pub folded_output_boundary_digest: Digest,
    pub folded_gr1cs_boundary_digest: Digest,
    pub folded_ajtai_commitment_digest: Digest,
    pub folded_ajtai_opening_digest: Digest,

    pub proof_public_statement_digest: Digest,

    pub batch_size: usize,
    pub active_count: usize,

    pub dev_status: Symbt3DevStatus,
}
```

Do not include:

- raw CP message bytes
- message openings
- source witness values
- Ajtai opening values
- Fiat-Shamir byte transcripts
- Poseidon digest bodies
- canonical message sections

## 6. Core Relations

### 6.1 Message-to-Trace Binding

For each typed binding:

```text
M_r(T, U) -> TraceColumn(T, K, C)
```

prove:

```text
Trace(T,K,C) = M_r(T,U)
```

over the active product domain.

As a zero-check:

```text
sum_{T,K,C}
    eq((T,K,C), rho)
    * sel(T,K,C)
    * (Trace(T,K,C) - M_r(T,U(T,K,C))) = 0
```

This is an algebraic/oracle equality, not byte equality.

### 6.2 Challenge-to-Message Binding

If a trace column uses a challenge-derived value, prove it equals the
verifier-derived challenge constant:

```text
ChallengeTrace(r,T,C) = ChallengeConst(r,C)
```

Do not prove the hash computation. The verifier recomputes the challenge and
supplies it as public/checking data.

### 6.3 Sumcheck Round Transition

For a sumcheck transcript with round polynomial `g_i(X)`, previous claim
`s_{i-1}`, and challenge `r_i`, enforce:

```text
g_i(0) + g_i(1) = s_{i-1}
```

and:

```text
s_i = g_i(r_i)
```

The coefficients of `g_i` and claim values `s_i` are read from the committed
message oracle.

For higher-degree round polynomials, use the declared degree bound in the
layout.

### 6.4 Final Local Claim Binding

At the end of the transcript, bind the final sumcheck claim to the local
expression already present in the SYMBT3 algebraic families:

```text
final claim = folded-output / GR1CS / Ajtai / range local evaluator expression
```

This prevents the message transcript from being self-consistent but disconnected
from the actual residual checks.

### 6.5 Boundary Consistency

If a message round outputs folded boundary coordinates, prove those message
coordinates match the development public folded boundary fields:

```text
M_r(folded-boundary,C) = Y_fold(C)
```

This should use typed algebra coordinates, not serialized bytes.

## 7. Prover Algorithm

`prove_symbt3_i_batched_cp(statement, witness)`:

1. Build `Symbt3MessageSemanticLayoutV1`.
   - Bind round count, message sections, typed column bindings, challenge
     schedule, and padding policy.
2. Build or reuse CP message oracles `M_r(T,U_r)`.
   - These are the CP committed message objects.
3. Compute `message_oracle_roots`.
4. Build `folding_protocol_id`.
   - Include message semantic layout.
5. Derive folding challenges from input-side transcript and message roots.
6. Build cumulative SYMBT3 trace:
   - all prior H columns;
   - typed message columns;
   - challenge trace columns if present;
   - sumcheck claim columns;
   - message-to-trace binding residuals.
7. Commit to the same single SYMBT3-I proof oracle/table.
8. Derive proof-checking challenges after:
   - `proof_relation_id`;
   - `proof_public_statement_digest`;
   - message semantic layout digest;
   - SYMBT3-I oracle root;
   - WHIR params
   are bound.
9. Prove:
   - message-to-trace binding;
   - challenge-to-message binding;
   - sumcheck round transitions;
   - final local claim binding;
   - folded boundary consistency.
10. Emit one top-level SYMBT3-I development proof.

## 8. Verifier Algorithm

`verify_symbt3_i_batched_cp(public_statement, proof)`:

1. Parse SYMBT3-I marker/version.
2. Reject unless:
   - `NonAuthoritativeDevelopment`;
   - `NonZkDevelopment`;
   - `top_level_backend_proof_count == 1`;
   - `family_columnar_subproofs == 0`;
   - `backend_table_count == 1`;
   - `RelationDescription::num_constraints == 0`.
3. Recompute:
   - message semantic layout digest;
   - `folding_protocol_id`;
   - `folding_transcript_digest`;
   - round challenges;
   - `proof_relation_id`;
   - `proof_public_statement_digest`.
4. Verify transcript separation:
   - message roots affect folding challenges;
   - folded/output-side data does not affect folding challenges;
   - proof oracle roots do not affect folding challenges;
   - proof oracle roots do affect proof-checking challenges.
5. Verify the single WHIR/PCS proof.
6. Verify message-to-trace binding constraints.
7. Verify sumcheck round transition constraints.
8. Verify final local claim binding.
9. Accept iff every enabled cumulative SYMBT3-I family verifies.

The verifier must not:

- call `CpFieldRelation::check`;
- inspect witness bundles;
- open full message oracles;
- construct appended typed CP R1CS rows;
- verify independent per-message/table proofs;
- perform byte transcript/hash reconstruction;
- route product `verify_public` through SYMBT3-I.

WHIR is the right backend shape here because its constrained Reed-Solomon
framework can express sumcheck-like constraints and rich queries to multilinear
polynomials, which is exactly what message-semantic validity should become.

## 9. What SYMBT3-I Proves

If `verify_symbt3_i_dev` accepts, then under the current development soundness
assumptions:

1. all prior SYMBT3-H checks pass;
2. the source columns are manifest-bound;
3. the CP message roots are input-side transcript-bound;
4. the algebraic columns used by SYMBT3 are bound to typed coordinates in the
   committed CP message oracles;
5. sumcheck/folding message transitions are valid under verifier-derived
   challenges;
6. final message claims connect to the actual SYMBT3 local residual/evaluator
   expressions;
7. all of this remains inside one top-level WHIR proof object.

This is a major authority step because it connects:

```text
committed CP messages
    -> algebraic folding transcript
    -> folded output / residual checks
```

without reintroducing byte transcript verification.

## 10. What SYMBT3-I Still Does Not Prove

SYMBT3-I still does not complete authority. It does not yet prove:

- production monomial embedding / full lattice range authority;
- zero-knowledge/masking;
- final WHIR/Sigma-IOP soundness profile;
- authority-profile parameterization;
- product proof envelope migration;
- product `verify_public` routing through SYMBT3.

Depending on how strong G currently is, the production range upgrade may be J
or G2.

## 11. Tests

### Metadata and Transcript Tests

- `message_semantic_layout_digest` changes when:
  - round count changes;
  - message section list changes;
  - section coordinate length changes;
  - message-to-trace binding changes;
  - challenge schedule changes;
  - padding policy changes;
  - semantic mode changes.
- `folding_protocol_id` changes when:
  - message semantic layout changes;
  - message oracle root changes;
  - input boundary changes;
  - batch manifest root changes;
  - active count changes.
- Round challenge digest changes when the corresponding message-root prefix
  changes.
- Round challenge digest does not change when:
  - folded output changes;
  - folded GR1CS boundary changes;
  - folded Ajtai data changes;
  - proof oracle root changes;
  - later message roots beyond the prefix change, if the protocol is
    prefix-ordered.

### Message Binding Tests

- honest `k=1` SYMBT3-I verifies;
- honest `k=2` SYMBT3-I verifies;
- tampering message oracle root rejects;
- tampering message coordinate used by folded-output trace rejects;
- tampering message coordinate used by GR1CS trace rejects;
- tampering message coordinate used by Ajtai trace rejects;
- tampering message coordinate used by range/projection trace rejects;
- tampering trace column without changing message coordinate rejects;
- tampering message section layout rejects.

### Sumcheck Semantic Tests

- wrong round polynomial coefficients reject;
- wrong `g_i(0) + g_i(1)` claim rejects;
- wrong next claim `s_i = g_i(r_i)` rejects;
- wrong final claim rejects;
- wrong final local evaluator binding rejects;
- wrong challenge value rejects;
- wrong challenge schedule version rejects.

### Anti-Regression Tests

- no canonical message bytes in SYMBT3-I public statement;
- no FS opening bytes;
- no digest-body tables;
- no Poseidon transcript reconstruction;
- no `CpFieldRelation::check`;
- no appended typed CP R1CS;
- one top-level WHIR proof object;
- zero `family_columnar_subproofs`;
- one backend table.

### Cross-Proof Rejection Tests

- SYMBT2F proof rejected as SYMBT3-I;
- SYMBT2C proof rejected as SYMBT3-I;
- SYMBTC1/SYMBTC2 proof rejected as SYMBT3-I;
- monolithic typed CP proof rejected as SYMBT3-I;
- independent WHIR table proof rejected as SYMBT3-I;
- SYMBT3-H proof rejected as SYMBT3-I if I families are required.

## 12. Benchmarks

Add:

```text
symbt3_i_vs_k
```

Current live code also registers:

```text
symbt3_i2_vs_k
```

Use `symbt3_i_vs_k` only when intentionally measuring the historical dense
message-to-trace copy baseline. Use `symbt3_i2_vs_k` for the current native
message-oracle-view profile, where `message_to_trace_binding_count = 0` and
message coordinates are consumed as typed oracle views.

Run:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench \
  --bench whir_scaling --features whir -- "symbt3_i_vs_k"
```

Report:

- `k`
- proof bytes
- prove mean
- verify mean
- `num_vars`
- sumcheck rounds
- top-level backend proof count
- family-columnar subproof count
- backend table count
- message round count
- message coordinate count
- message-to-trace binding count
- sumcheck transition count
- opened field elements
- WHIR/PCS openings

Interpretation:

```text
SYMBT3-I is not expected to be faster than H.
The success criterion is CP-message semantic coverage while preserving the
one-proof architecture.
```

## 13. Acceptance Criteria

SYMBT3-I is complete when:

1. `Symbt3MessageSemanticLayoutV1` exists and is canonically serialized/digested.
2. Message oracle roots are treated as the CP message commitment boundary.
3. Round challenges are derived externally from the correct input-side
   transcript and message-root prefixes.
4. Message-to-trace binding proves that algebraic SYMBT3 trace columns are
   sourced from committed message oracles.
5. Sumcheck/folding round transitions are checked algebraically.
6. Final message claims are bound to existing SYMBT3 local residual/evaluator
   expressions.
7. No byte transcript/hash/opening machinery is reintroduced.
8. The proof still has one top-level WHIR object, zero
   `family_columnar_subproofs`, one backend table, and no appended typed CP R1CS.
9. Product `verify_public` remains on authoritative monolithic typed CP.
10. Docs label SYMBT3-I as `NonAuthoritativeDevelopment` and
    `NonZkDevelopment`.

## 14. Suggested Implementation Order

1. Add `Symbt3MessageSemanticLayoutV1`.
2. Add round-message section kinds and typed binding descriptors.
3. Add canonical digesting and layout tests.
4. Bind message semantic layout into `folding_protocol_id` and
   `proof_relation_id`.
5. Add message-to-trace binding as the first I family.
6. Add external round-challenge prefix schedule tests.
7. Add sumcheck round transition checks.
8. Add final local claim binding.
9. Add proof-shape and anti-byte-regression tests.
10. Add `symbt3_i_vs_k` benchmark.
11. Update docs with precise invariant and caveats.
