# SYMBT3-D2: Direct Folded GR1CS Product Residual Zero-Check

## Summary

Add the missing direct folded GR1CS product-residual check to the SYMBT3
development path.

> **Current status (2026-05-20): implemented historical milestone, superseded
> by later cumulative profiles.** The D2 family exists in code as
> `BatchedCpSymbt3ConstraintFamily::FoldedGr1csProductResidualZeroCheck`, with
> product columns
> `BatchedCpSymbt3AlgebraicColumnKind::{FoldedGr1csProductLeft,
> FoldedGr1csProductRight,FoldedGr1csProductOutput}` and layout
> `Symbt3FoldedGr1csProductResidualLayout` under `src/modular/batched_cp/`.
> The WHIR side derives the D2 product sumcheck transcript in
> `src/snark/whir/symbt3_columns.rs`.
>
> The current default SYMBT3 development relation is cumulative and already
> includes later H/I/J/K2-family work. The product-residual check is no longer
> a standalone implementation target, and the current live Criterion targets
> start at `symbt3_e_vs_k` / `symbt3_f_vs_k` and continue through
> `symbt3_h_vs_k`, `symbt3_i_vs_k`, `symbt3_i2_vs_k`, and `symbt3_j_vs_k`.
> Historical docs record a first `symbt3_d2_vs_k` run, but that target is not
> currently registered in `benches/whir_scaling.rs`.
>
> Product `verify_public` remains the authoritative monolithic WHIR typed-CP
> route and does not route through D2. D2/SYMBT3 development proofs remain
> `NonAuthoritativeDevelopment` / `NonZkDevelopment` unless selected by the
> explicit K6a or N8 NonZK accumulator APIs.

In the original D2 plan, SYMBT3-D proved source R1CS residual validity and
beta-linear folded GR1CS boundary consistency, but the folded GR1CS side did
not yet directly expose/check the multiplicative product-triple residual:

```text
L_fold * R_fold - O_fold = 0
```

SYMBT3-D2 added this as a structured algebraic WHIR block, still under the same
safety posture:

- `NonAuthoritativeDevelopment`
- `NonZkDevelopment`
- one top-level WHIR proof object
- zero `family_columnar_subproofs`
- no appended typed CP R1CS
- no witness-side verifier checks
- no byte transcript/hash/opening reconstruction
- no product routing change

The goal is not yet full CP authority. The goal is to make the folded GR1CS
residual semantically real inside the SYMBT3 algebraic path.

## Existing Context

SYMBT3-D already has:

- `CommittedSourceR1csResidualValidity`
- `FoldedGr1csResidualValidity`
- `Symbt3R1csEvaluatorLayoutV1`
- `Symbt3Gr1csResidualLayoutV1`
- source assignment roots
- folded GR1CS boundary digests
- one top-level WHIR proof object

But its folded GR1CS residual check currently means:

```text
beta-linear folded evaluation boundary consistency
```

not:

```text
direct folded product-triple residual validity
```

SYMBT3-D2 adds the direct product check.

## New Constraint Family

Historical plan item, now implemented under the `BatchedCp*` names:

```rust
BatchedCpSymbt3ConstraintFamily::FoldedGr1csProductResidualZeroCheck
```

This family proves that the committed folded GR1CS triple columns satisfy the
product residual on the Boolean GR1CS row/equation domain.

Conceptually, for every valid folded GR1CS product coordinate `g`:

```text
E_prod(g) = L_fold(g) * R_fold(g) - O_fold(g) = 0
```

If the layout has padding coordinates, use a public/succinct selector:

```text
E_prod(g) = sel(g) * (L_fold(g) * R_fold(g) - O_fold(g))
```

where `sel(g) = 1` for valid product coordinates and `0` for padded
coordinates.

## Critical Algebraic Form

Do not implement D2 as:

```text
L_fold(z) * R_fold(z) - O_fold(z) = 0
```

That is not the correct low-degree extension of the pointwise Boolean-domain
residual.

Instead, define the Boolean-domain residual table:

```text
E(g) = sel(g) * (L(g) * R(g) - O(g)) for g in {0,1}^m_g.
```

Then prove:

```text
E(g) = 0 for all g in {0,1}^m_g.
```

The verifier samples a random point `rho`, and the prover proves:

```text
E(rho) = sum_{g in {0,1}^m_g} eq(g, rho) * sel(g) * (L(g) * R(g) - O(g)) = 0.
```

This is the correct sumcheck-style zero-check.

At the end of the sumcheck, the verifier obtains a final point `alpha` and
checks the final local expression using WHIR/PCS openings:

```text
v_final = eq(alpha, rho) * sel(alpha) * (L(alpha) * R(alpha) - O(alpha)).
```

The final sumcheck value must equal this expression.

This is the core of SYMBT3-D2.

## New Layout

Add a versioned product-residual layout:

```rust
pub struct Symbt3FoldedGr1csProductResidualLayoutV1 {
    pub product_domain_log_size: usize,
    pub equation_kind_axis: AxisLayout,
    pub row_axis: AxisLayout,

    pub l_fold_column: ColumnId,
    pub r_fold_column: ColumnId,
    pub o_fold_column: ColumnId,

    pub selector_evaluator: Symbt3SelectorEvaluatorId,
    pub product_law: Symbt3ProductLawId,

    pub padding_policy: Symbt3PaddingPolicy,
    pub check_field: Symbt3CheckField,
    pub soundness_profile: Symbt3DevSoundnessProfile,
}
```

The `product_law` must be explicit and bound into the relation id. Examples:

```rust
pub enum Symbt3ProductLawId {
    FieldCoordinateMulV1,
    RingCoefficientMulV1,
    NegacyclicConvolutionV1,
    ModuleProductEvaluatorV1,
}
```

For the first implementation, this document allowed:

```rust
FieldCoordinateMulV1
```

Current code carries both `FieldCoordinateMulV1` and
`RqNegacyclicConvolutionV1`, and the default algebra law uses
`RqNegacyclicConvolutionV1` with `RingCoefficientActionV1`. The older D2
field-coordinate phrasing should therefore be read as the initial scaffold:

```text
SYMBT3-D2 currently checks field-coordinate product residuals.
Full ring/module beta and product semantics remain a later authority concern.
```

If the real folded GR1CS product is ring/module multiplication, the layout must
eventually move to a product evaluator that computes the correct
convolution/module product, not coordinatewise field multiplication.

## Relation-Id Binding

D2 should bind the new semantic layout into the proof relation id:

```text
relation_id binds:
    SYMBT3 version marker
    enabled constraint family list
    Symbt3R1csEvaluatorLayoutV1 digest
    Symbt3Gr1csResidualLayoutV1 digest
    Symbt3FoldedGr1csProductResidualLayoutV1 digest
    WHIR parameter digest
    Ajtai digest
    R1CS digest
    oracle layout digest
    algebraic trace layout digest
    challenge schedule version
```

One improvement to strongly consider now is splitting the folding challenge
identity from the proof relation identity.

Use:

```text
folding_protocol_id:
    shape id
    batch-size policy
    active-count policy
    CP message oracle layout
    commitment scheme digest
    Ajtai/R1CS shape digests
    folding challenge schedule version
```

and:

```text
proof_relation_id:
    folding_protocol_id
    enabled SYMBT3 constraint families
    WHIR params
    proof oracle layout
    semantic evaluator layouts
```

Then derive beta from:

```text
folding_transcript_digest = H(
    "SYMBT3-FOLDING-TRANSCRIPT",
    folding_protocol_id,
    input_public_boundary_digest,
    source_assignment_roots,
    message_oracle_roots,
    batch_size,
    active_count
)
```

not from the full proof family list.

This matters because the folding beta should be a protocol challenge, not
something that changes merely because the development proof enabled D2 instead
of D. Symphony's compiler derives folding challenges from the input and message
commitments, then checks the CP proof against those challenges; the proof
relation should not make Fiat-Shamir depend on the output or on
implementation-only proof-family choices.

For a minimal implementation, the current `relation_id` behavior can remain if
it is already wired, but it must be documented as development-only. For the
cleaner long-term path, introduce `folding_protocol_id` in D2.

## Transcript Order

D2 needs two separate randomness schedules.

### 1. Folding Beta

Beta is input-side only.

```text
beta = ChallengeToBeta(H("SYMBT3-BETA", folding_transcript_digest))
```

This digest binds:

- `folding_protocol_id`
- input/public-boundary digest
- source assignment roots
- message oracle roots
- WHIR parameter digest, if part of the committed CP backend identity
- batch size
- active count

It must not bind:

- folded GR1CS boundary
- folded output fields
- folded residual output
- D2 proof oracle roots
- sumcheck messages

### 2. Product-Residual Proof Challenges

The product-residual zero-check challenges are proof-checking challenges. They
are sampled after all D2 proof data is bound.

```text
rho_prod = H(
    "SYMBT3-D2-PROD-RHO",
    proof_relation_id,
    proof_public_statement_digest,
    folded_gr1cs_boundary_digest,
    folded_output_digest,
    symbt3_d2_oracle_root,
    enabled_family_digest
)
```

Then the sumcheck challenges are derived sequentially from:

- `rho_prod`
- sumcheck round messages
- `proof_relation_id`
- `proof_public_statement_digest`
- `symbt3_d2_oracle_root`

The final WHIR/PCS opening challenge is bound to the whole sumcheck transcript.

## Public Statement Changes

Extend the SYMBT3 public/development statement with D2-specific digests, not raw
witness data:

```rust
pub struct BatchedCpSymbt3PublicStatement {
    // Existing fields.
    pub folding_protocol_id: Digest,
    pub proof_relation_id: Digest,

    pub input_public_boundary_digest: Digest,
    pub source_assignment_roots: Vec<Digest>,
    pub message_oracle_roots: Vec<Digest>,

    pub folded_output_boundary_digest: Digest,
    pub folded_gr1cs_boundary_digest: Digest,

    // New for D2.
    pub folded_gr1cs_product_layout_digest: Digest,
    pub proof_public_statement_digest: Digest,

    pub batch_size: usize,
    pub active_count: usize,
}
```

The public statement must not include:

- source assignment values
- folded witness values
- message bytes
- FS openings
- canonical message-section bytes
- digest-body tables
- residual witness columns

The folded GR1CS boundary remains output-side. It changes
`proof_public_statement_digest`, not beta.

## Trace/Oracle Columns

D2 should add typed columns to the existing SYMBT3 proof oracle, not a new table
forest.

Required folded product columns:

- `L_fold(g)`
- `R_fold(g)`
- `O_fold(g)`

Optional debug columns:

- `E_product_debug(g)`

If a debug residual column exists, it must be constrained to:

```text
E_debug(g) = L(g) * R(g) - O(g).
```

The verifier must never trust debug residual columns directly.

The canonical D2 trace domain is:

```text
g = (equation_kind, row_or_evaluation_coordinate)
```

or, more explicitly:

```text
G = EquationKindAxis x Gr1csRowAxis x ProductCoordinateAxis
```

depending on how the existing `Symbt3Gr1csResidualLayoutV1` represents folded
evaluation triples.

The proof should still use one backend table/oracle family. Do not create:

- one proof per equation kind
- one proof per row
- one proof per `L`/`R`/`O` column
- one proof per residual family

## Core D2 Relation

For every valid Boolean-domain product coordinate `g`:

```text
L_fold(g) * R_fold(g) = O_fold(g).
```

Equivalently:

```text
E_prod(g) = 0.
```

D2 proves this with a sumcheck-style claim:

```text
sum_{g in {0,1}^m_g} eq(g, rho) * sel(g) * (L(g) * R(g) - O(g)) = 0.
```

The verifier checks the sumcheck transcript and one final local product
expression using opened values of `L`, `R`, and `O` at the final sumcheck point.

This is the direct folded GR1CS product-triple residual.

## Prover Algorithm

`prove_symbt3_d2_batched_cp(statement, witness)`:

1. Build or reuse the cumulative SYMBT3-D trace:
   - source assignment columns;
   - folded boundary columns;
   - beta columns, if present;
   - folded GR1CS `L`/`R`/`O` columns.
2. Derive beta from input-side `folding_transcript_digest` only.
3. Compute folded GR1CS product columns:
   - `L_fold(g)`
   - `R_fold(g)`
   - `O_fold(g)`
4. Commit to the single SYMBT3-D2 proof oracle/table.
5. Derive `rho_prod` after the following are bound:
   - `proof_relation_id`;
   - `proof_public_statement_digest`;
   - folded GR1CS boundary digest;
   - D2 oracle root;
   - WHIR params;
   - enabled family digest.
6. Run the product-residual sumcheck for:

   ```text
   sum_g eq(g, rho_prod) * sel(g) * (L(g) * R(g) - O(g)) = 0.
   ```

7. Produce WHIR/PCS openings for the final sumcheck point:
   - `L_fold(alpha)`
   - `R_fold(alpha)`
   - `O_fold(alpha)`
   - any additional columns required by `ProductLaw`.
8. Package one top-level SYMBT3-D2 WHIR proof object.

The prover may compute linearly in the trace size. The public verifier should
not.

## Verifier Algorithm

`verify_symbt3_d2_batched_cp(public_statement, proof)`:

1. Parse and domain-check the SYMBT3-D2 marker/version.
2. Reject unless:
   - `NonAuthoritativeDevelopment` path is explicitly requested;
   - product public routing is not using this proof;
   - `top_level_backend_proof_count == 1`;
   - `family_columnar_subproofs == 0`;
   - `RelationDescription::num_constraints == 0`.
3. Recompute:
   - `folding_protocol_id`;
   - `proof_relation_id`;
   - `folding_transcript_digest`;
   - beta;
   - `proof_public_statement_digest`.
4. Check that folded/output-side fields do not affect beta.
5. Bind D2 oracle root and derive `rho_prod`.
6. Verify the product-residual sumcheck transcript:
   - initial claimed sum is `0`;
   - round consistency checks pass;
   - final challenge `alpha` is transcript-derived.
7. Verify WHIR/PCS openings at `alpha`.
8. Compute the final expression:

   ```text
   eq(alpha, rho_prod)
   * sel_hat(alpha)
   * (L_hat(alpha) * R_hat(alpha) - O_hat(alpha))
   ```

   or the `ProductLaw`-specific equivalent.

9. Accept iff the sumcheck final value equals the computed final expression and
   all existing enabled SYMBT3-D families also verify.

The verifier must not:

- call `CpFieldRelation::check`
- open full private witness bundles
- inspect source assignments outside committed openings
- construct appended typed CP R1CS rows
- verify independent per-table WHIR proofs
- perform byte transcript/hash reconstruction

## Cumulative D2 Profile

The default benchmark/profile should be cumulative, not product-only.

Enabled families for the default D2 profile:

- `ChallengeToBeta`
- `FoldedOutputVectorIdentity`
- `CommittedSourceR1csResidualValidity`
- `FoldedGr1csResidualBoundaryConsistency`
- `FoldedGr1csProductResidualZeroCheck`

A product-only unit test profile is fine for local testing, but docs should not
describe it as D2 semantic coverage.

The D2 invariant should be:

```text
If verify_symbt3_d2_dev accepts, then, under the committed SYMBT3 source/folded
columns, the source R1CS residual checks, folded boundary linear-consistency
checks, and direct folded GR1CS product-residual zero-check all pass, except
with the current development soundness error.
```

It is still not full CP authority.

## What D2 Proves

D2 proves:

```text
the folded GR1CS L/R/O product triple is multiplicatively consistent
over the committed folded GR1CS product domain.
```

More concretely:

```text
for all g in G_valid: L_fold(g) * R_fold(g) - O_fold(g) = 0.
```

Together with D, it also keeps:

- source R1CS residual checks;
- folded evaluation boundary beta-linearity;
- input-side beta derivation;
- one structured proof object.

## What D2 Does Not Prove

D2 still does not prove:

- Ajtai opening validity;
- Ajtai norm/range constraints;
- CP message semantic validity;
- manifest membership for all source columns;
- that every committed source column is exactly the product-boundary item;
- zero knowledge;
- final production soundness;
- full Symphony CP authority;
- product public routing correctness.

Those remain later milestones.

This is important because Symphony's CP compiler relies on the CP proof to show
that committed messages form a valid folding proof while keeping Fiat-Shamir
and commitment-opening checks out of the proven statement. D2 adds an essential
algebraic part of that proof, but it is not yet the full CP proof.

## Soundness Status

For D2 development, a single base-field sumcheck/random zero-check is acceptable
if clearly labeled:

```text
NonAuthoritativeDevelopment
```

For authority, the plan must later specify at least one of:

- extension-field challenges;
- multiple independent repetitions;
- a WHIR/Sigma-IOP soundness bound for the exact combined relation;
- a backend-provided constrained-code soundness theorem.

WHIR's verifier is designed to achieve small query complexity and fast
verification for constrained Reed-Solomon/Sigma-IOP-style relations. After BCS,
each proof still incurs Merkle-path checks, which is why keeping one top-level
proof object remains essential.

## Tests

### Metadata and Transcript Tests

`relation_id` changes when:

- enabled family list changes;
- D2 product layout changes;
- `ProductLaw` changes;
- selector layout changes;
- R1CS/GR1CS evaluator layout changes;
- WHIR params change;
- challenge schedule version changes.

`folding_protocol_id` / beta digest changes when:

- input public boundary digest changes;
- source assignment root changes;
- message oracle root changes;
- batch size changes;
- active count changes;
- folding challenge schedule changes.

Beta digest does not change when:

- folded GR1CS boundary changes;
- folded output boundary changes;
- D2 product residual oracle root changes;
- D2 proof transcript changes.

If `folding_protocol_id` is not introduced yet, add a test documenting the
current dev-only behavior and a TODO to split it before authority.

### Algebraic Correctness Tests

- honest `k=1` D2 verifies;
- honest `k=2` D2 verifies;
- honest cumulative D2 verifies with all prior D families enabled;
- tampering `L_fold` at an active valid coordinate rejects;
- tampering `R_fold` at an active valid coordinate rejects;
- tampering `O_fold` at an active valid coordinate rejects;
- tampering folded GR1CS boundary digest rejects;
- tampering `ProductLaw` id rejects;
- tampering selector layout rejects;
- tampering valid-coordinate padding policy rejects;
- tampering beta trace rejects if beta trace columns are enabled;
- tampering active count rejects;
- tampering residual/debug columns alone cannot make an invalid `L`/`R`/`O`
  pass.

For probabilistic invalid-witness tests, either use a deterministic transcript
fixture where the chosen residual is known to be nonzero at the sampled check
point, or corrupt committed/opened values after proof generation so the verifier
must reject deterministically.

### Sumcheck-Specific Tests

- wrong initial claimed sum rejects;
- wrong sumcheck round polynomial rejects;
- wrong final `alpha` transcript binding rejects;
- wrong final `L` opening rejects;
- wrong final `R` opening rejects;
- wrong final `O` opening rejects;
- wrong `eq(alpha, rho_prod)` computation rejects;
- wrong selector evaluation rejects.

### Proof-Shape Tests

- `top_level_backend_proof_count == 1`
- `family_columnar_subproofs == 0`
- `backend_table_count == 1`
- `RelationDescription::num_constraints == 0`

Reject if proof contains:

- per-row proof;
- per-coordinate proof;
- per-column proof;
- per-family proof;
- SYMBT2F proof;
- SYMBT2C proof;
- SYMBTC1/SYMBTC2 proof;
- monolithic typed CP proof;
- independent WHIR table proof.

### Routing Tests

- product `verify_public` remains green;
- product `verify_public` does not route through SYMBT3-D2;
- SYMBT3-D2 cannot be accepted as authoritative CP;
- authority flags unchanged;
- public proof envelope unchanged.

## Benchmarks

Historical target:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench \
  --bench whir_scaling --features whir -- "symbt3_d2_vs_k"
```

Current `benches/whir_scaling.rs` no longer registers `symbt3_d2_vs_k`.
Measure the live cumulative code with the registered SYMBT3 targets:
`symbt3_f_vs_k`, `symbt3_h_vs_k`, `symbt3_i2_vs_k`, `symbt3_j_vs_k`, and the
explicit accumulator routes such as `symbt3_accumulator_authority_vs_k` or
`symbt3_n8_integrated_authority_vs_k`.

Report:

- `k`
- proof bytes
- prove mean
- verify mean
- `num_vars`
- top-level backend proof count
- `family_columnar_subproof` count
- backend table count
- sumcheck rounds
- number of WHIR/PCS openings
- opened field elements
- hash/Merkle path count if available

Interpret the benchmark carefully:

```text
SYMBT3-D2 is not comparable to full authoritative typed CP yet.
It is a proof-shape and algebraic-coverage benchmark.
```

The key success condition is not just speed. It is:

```text
adding direct folded product residuals keeps one top-level proof object
and grows much slower than the monolithic typed CP baseline.
```

## Acceptance Criteria

D2 is complete when:

1. `FoldedGr1csProductResidualZeroCheck` is implemented as a sumcheck-style
   Boolean-domain zero-check, not as `L_hat(z) * R_hat(z) - O_hat(z)`.
2. D2 verifies honest `k=1` and `k=2` cumulative traces.
3. Tampering `L`/`R`/`O` folded product columns rejects.
4. Tampering folded GR1CS boundary changes `proof_public_statement_digest` and
   rejects, but does not alter beta.
5. Source roots and message roots are bound before beta derivation.
6. Folded/output-side data remains outside beta derivation.
7. `ProductLaw`, selector layout, and GR1CS product layout are bound into the
   proof relation id.
8. The proof has one top-level WHIR object, zero `family_columnar_subproofs`,
   and no appended typed CP R1CS.
9. `verify_public` remains on monolithic authoritative typed CP.
10. Docs label D2 as `NonAuthoritativeDevelopment` and `NonZkDevelopment`.
