# SYMBT3-H: Manifest / Source-Column Membership

## Summary

Add the next non-authoritative SYMBT3 semantic block: prove that the source
columns used by the SYMBT3 algebraic checks are bound to the batch manifest /
product-boundary source data.

> **Current status (2026-05-20): implemented historical milestone, now part of
> the cumulative SYMBT3 relation.** The manifest/source layout and families
> exist under `src/modular/batched_cp/` as `Symbt3BatchManifestLayout`,
> `Symbt3ManifestComponentLayout`, `Symbt3SourceColumnLayout`,
> `BatchedCpSymbt3ConstraintFamily::BatchManifestRootBinding`, and
> `BatchedCpSymbt3ConstraintFamily::SourceManifestColumnMembership`.
> The current `has_symbt3_h_families()` gate also requires
> `ManifestEvaluationClaim`, `SourceAssignmentRootManifestBinding`, and
> `SourceMessageRootManifestBinding`.
>
> Later K1/K1e.2 work compressed the manifest/source public boundary further:
> the verifier no longer reconstructs full manifest rows as public data, and
> manifest/source membership is handled through root/layout/public-boundary
> evaluator checks rather than dense manifest/source backend columns. The live
> benchmark target `symbt3_h_vs_k` still exists, but current reportable
> performance status should prefer the later cumulative `symbt3_i2_vs_k`,
> `symbt3_j_vs_k`, K6a, and N8 route benchmarks where appropriate.
>
> Product `verify_public` remains the authoritative monolithic WHIR typed-CP
> route and does not route through H directly. H/SYMBT3 development profiles
> remain `NonAuthoritativeDevelopment` / `NonZkDevelopment` unless selected by
> explicit NonZK accumulator routes.

The original SYMBT3-H plan preserved:

- `NonAuthoritativeDevelopment`
- `NonZkDevelopment`
- one top-level WHIR proof object
- zero `family_columnar_subproofs`
- one backend table
- `RelationDescription::num_constraints == 0`
- no appended typed CP R1CS
- no witness-side verifier checks
- no byte transcript/hash reconstruction
- no product `verify_public` routing change

The goal is to move from:

```text
The committed SYMBT3 columns are algebraically self-consistent.
```

to:

```text
The committed SYMBT3 source columns are the columns committed by the
batch manifest / product boundary.
```

This is still not authority, but it closes the "free source columns" gap.

## One-Sentence Definition

SYMBT3-H is the cumulative non-authoritative SYMBT3 profile that adds
manifest/source-column membership checks, proving that the public-input,
commitment, evaluation, accumulator-boundary, assignment-root, and Ajtai-source
coordinates used by SYMBT3 are bound to the batch manifest and input-side public
boundary, while preserving the one-proof WHIR architecture and no product-route
promotion.

## 1. What H Should Prove

Let:

```text
Manifest(T, K, C)
```

be a committed product-domain manifest oracle, where:

- `T` is the batch item index;
- `K` is the source component kind;
- `C` is the coordinate within that component kind.

Let:

```text
Source(T, K, C)
```

be the SYMBT3 source column family already used by the algebraic blocks.

SYMBT3-H proves, for active rows:

```text
Source(T, K, C) = Manifest(T, K, C)
```

for all source component kinds that are supposed to come from the product
boundary.

The enabled component kinds should include at least:

- `PublicInput`
- `SourceCommitmentCoordinate`
- `SourceEvaluationCoordinate`
- `SourceAccumulatorBoundaryCoordinate`
- `SourceAjtaiCommitmentCoordinate`
- `SourceAssignmentRootCoordinate`
- `SourceMessageRootCoordinate`

The exact list should be versioned and layout-bound.

Private witness/opening values should not become public manifest data. For
private source columns, H should prove binding to committed-oracle roots or
layout digests, not expose the values.

## 2. New Constraint Families

Historical suggested names:

- `Symbt3ConstraintFamily::BatchManifestRootBinding`
- `Symbt3ConstraintFamily::SourcePublicInputManifestMembership`
- `Symbt3ConstraintFamily::SourceCommitmentManifestMembership`
- `Symbt3ConstraintFamily::SourceEvaluationManifestMembership`
- `Symbt3ConstraintFamily::SourceAccumulatorBoundaryManifestMembership`
- `Symbt3ConstraintFamily::SourceAjtaiCommitmentManifestMembership`
- `Symbt3ConstraintFamily::SourceAssignmentRootManifestBinding`
- `Symbt3ConstraintFamily::SourceMessageRootManifestBinding`

Current code uses the `BatchedCpSymbt3ConstraintFamily` namespace. It did not
create one membership family per component kind; it uses
`SourceManifestColumnMembership` plus root/claim binding families.

For the first implementation, this plan combined the coordinate equalities
under one generalized family:

```rust
BatchedCpSymbt3ConstraintFamily::SourceManifestColumnMembership
```

with a typed component-kind axis. Current code keeps root/digest binding checks
as separate families and additionally requires the K1 manifest-evaluation
claim:

- `BatchManifestRootBinding`
- `SourceAssignmentRootManifestBinding`
- `SourceMessageRootManifestBinding`
- `ManifestEvaluationClaim`

This avoids creating one proof family per source component.

## 3. New Layouts

Add a versioned manifest layout.

```rust
pub struct Symbt3BatchManifestLayoutV1 {
    pub version_marker: [u8; 8], // e.g. b"SYMBT3H\0"

    pub batch_size: usize,
    pub active_policy: Symbt3ActivePolicy,

    pub manifest_oracle_layout: Symbt3ManifestOracleLayoutV1,
    pub source_column_layout: Symbt3SourceColumnLayoutV1,

    pub component_kinds: Vec<Symbt3ManifestComponentLayoutV1>,

    pub commitment_scheme_id: Symbt3CommitmentSchemeId,
    pub manifest_root_policy: Symbt3ManifestRootPolicy,

    pub selector_evaluator: Symbt3SelectorEvaluatorId,
    pub padding_policy: Symbt3PaddingPolicy,
}
```

Component layout:

```rust
pub struct Symbt3ManifestComponentLayoutV1 {
    pub kind: Symbt3ManifestComponentKind,
    pub coordinate_len: usize,
    pub source_column_id: ColumnId,
    pub manifest_column_id: ColumnId,

    pub visibility: Symbt3ManifestVisibility,
    pub membership_mode: Symbt3MembershipMode,

    pub padding_policy: Symbt3PaddingPolicy,
}
```

Suggested enums:

```rust
pub enum Symbt3ManifestComponentKind {
    PublicInput,
    SourceCommitmentCoordinate,
    SourceEvaluationCoordinate,
    SourceAccumulatorBoundaryCoordinate,
    SourceAjtaiCommitmentCoordinate,
    SourceAssignmentRootCoordinate,
    SourceMessageRootCoordinate,
}

pub enum Symbt3ManifestVisibility {
    PublicBoundaryCoordinate,
    CommittedPrivateRoot,
    CommittedPrivateColumn,
}

pub enum Symbt3MembershipMode {
    CoordinateEquality,
    RootDigestEquality,
    LayoutDigestEquality,
}
```

Important rule:

```text
Byte encodings, Poseidon digest bodies, Fiat-Shamir openings, and canonical
message-section bytes must not be added as manifest component kinds.
```

The manifest is a typed algebraic/oracle boundary, not a byte transcript replay.

## 4. ID and Transcript Binding

Keep the split:

- `folding_protocol_id`
- `proof_relation_id`
- `proof_public_statement_digest`

### `folding_protocol_id`

Bind source/manifest semantics if they affect folding challenges:

```text
folding_protocol_id binds:
    shape_id
    batch-size policy
    active-count policy
    input public-boundary layout
    batch manifest layout digest
    source column layout digest
    message-oracle layout digest
    source assignment root policy
    Ajtai/R1CS/GR1CS shape digests
    Symbt3AlgebraLaw digest
    Ajtai norm/range policy digest
    folding challenge schedule version
```

### `folding_transcript_digest`

Beta remains input-side only:

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

Then:

```text
beta = ChallengeToBeta(H("SYMBT3-BETA", folding_transcript_digest))
```

This means manifest/source changes affect beta, because they are input-side data.

Folded outputs, folded GR1CS boundary, folded Ajtai commitment/opening,
projection/range witnesses, and proof oracle roots must not affect beta.

### `proof_relation_id`

Bind proof/evaluator implementation details:

```text
proof_relation_id = H(
    "SYMBT3-PROOF-RELATION",
    folding_protocol_id,
    enabled_constraint_families,
    WHIR params digest,
    SYMBT3 proof oracle layout digest,
    Symbt3BatchManifestLayoutV1 digest,
    selector layout digest,
    membership-check schedule version
)
```

### `proof_public_statement_digest`

Bind output and development statement data:

```text
proof_public_statement_digest = H(
    "SYMBT3-PUBLIC-STATEMENT",
    proof_relation_id,
    folding_transcript_digest,
    folded_output_boundary_digest,
    folded_gr1cs_boundary_digest,
    folded_ajtai_commitment_digest,
    folded_ajtai_opening_digest,
    norm_range_public_digest,
    batch_manifest_root,
    manifest_layout_digest,
    development boundary fields
)
```

## 5. Public Statement Changes

Extend the SYMBT3 development public statement with short manifest data only:

```rust
pub struct BatchedCpSymbt3PublicStatement {
    pub folding_protocol_id: Digest,
    pub proof_relation_id: Digest,

    pub input_public_boundary_digest: Digest,

    // New for H.
    pub batch_manifest_root: Digest,
    pub batch_manifest_layout_digest: Digest,
    pub source_column_layout_digest: Digest,

    // Existing input-side roots.
    pub source_assignment_roots: Vec<Digest>,
    pub message_oracle_roots: Vec<Digest>,
    pub source_ajtai_commitment_digest: Digest,

    // Existing output-side data.
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

The public statement must not contain:

- raw manifest rows
- source witness values
- source assignment values
- Ajtai opening values
- CP message bytes
- Fiat-Shamir openings
- canonical message-section bytes
- digest-body reconstruction tables

## 6. Core Relation

For active rows and valid coordinates:

```text
sel(T, K, C) * (Source(T, K, C) - Manifest(T, K, C)) = 0.
```

Equivalently, prove the Boolean-domain zero-check:

```text
sum_{T,K,C} eq((T,K,C), rho)
    * sel(T,K,C)
    * (Source(T,K,C) - Manifest(T,K,C)) = 0.
```

The challenge `rho` is sampled after:

- `proof_relation_id`
- `proof_public_statement_digest`
- `batch_manifest_root`
- SYMBT3-H oracle root
- WHIR params
- enabled family digest

are bound.

This is a product-domain equality check, not a byte table.

Because WHIR is designed to prove constrained Reed-Solomon / Sigma-IOP-style
sumcheck relations, this is the right backend shape for H: a single structured
constraint over committed columns, not separate table proofs.

## 7. Root-Binding Semantics

There are two kinds of H checks.

### 7.1 Coordinate Membership

For algebraic public data:

- public inputs
- source commitments
- evaluation coordinates
- accumulator boundary coordinates
- Ajtai commitment coordinates

prove coordinate equality:

```text
Source(T, K, C) = Manifest(T, K, C).
```

### 7.2 Root / Digest Binding

For private or external-oracle data:

- source assignment roots
- message oracle roots
- private opening roots

do not open the values. Instead prove/bind:

```text
manifest row contains the same root/digest that the SYMBT3 public statement
uses as the CP commitment boundary.
```

This may be done as public metadata equality if both roots are public, or as a
coordinate equality against manifest root columns if the manifest root columns
are committed.

Do not prove Poseidon/FS hash computation inside H. The root is a boundary
object.

This keeps H consistent with Symphony's CP-SNARK idea: the CP proof is supposed
to prove folding correctness against commitments, while avoiding Fiat-Shamir/hash
and commitment-opening checks as ordinary circuit logic.

## 8. Active Policy

For H, keep the same prefix policy:

```text
T < active_count      => active
T >= active_count     => inactive / dummy
```

The manifest layout must bind:

- `batch_size`
- `active_count`
- padding policy
- dummy policy
- component lengths
- component order

Inactive rows:

- do not contribute to algebraic membership checks;
- may contain arbitrary dummy data unless `DummyRowCanonicality` is explicitly enabled;
- must not be counted as active by the selector.

Do not add arbitrary active-mask semantics yet.

## 9. Prover Algorithm

`prove_symbt3_h_batched_cp(statement, witness)`:

1. Build `Symbt3BatchManifestLayoutV1`.
   - Bind component kinds, coordinate lengths, source-column mapping,
     manifest-column mapping, active policy, and padding policy.
2. Build / load the batch manifest oracle.
   - Contains typed per-item input/source data.
   - Contains roots/digests for private source columns and message oracles.
   - Does not contain raw private witness values unless explicitly committed as
     private columns.
3. Compute `batch_manifest_root`.
4. Build `folding_protocol_id`.
   - Include manifest/source layout semantics.
5. Derive `folding_transcript_digest` and beta.
   - Beta uses input-side manifest/source roots.
   - Beta does not use folded/output-side data.
6. Build the cumulative SYMBT3 trace:
   - all prior G columns;
   - source columns;
   - manifest columns or manifest openings needed for membership;
   - selector columns for valid active manifest coordinates.
7. Commit to the same single SYMBT3-H oracle/table.
8. Derive membership challenge `rho` after public statement, manifest root, and
   proof oracle root are bound.
9. Prove the source-manifest equality zero-check:

```text
sum_{T,K,C} eq((T,K,C), rho)
    * sel(T,K,C)
    * (Source(T,K,C) - Manifest(T,K,C)) = 0
```

10. Run the cumulative WHIR proof for:
    - `ChallengeToBeta`
    - `FoldedOutputVectorIdentity`
    - `SourceR1CSResidualValidity`
    - `FoldedGR1CSBoundaryConsistency`
    - `FoldedGR1CSProductResidualZeroCheck`
    - `FoldedAjtaiOpeningLinearIdentity`
    - `FoldedAjtaiCommitmentLinearIdentity`
    - `FoldedAjtaiMapConsistency`
    - `FoldedAjtaiProjectionConsistency`
    - `FoldedAjtaiProjectedRangeBound`
    - `SourceManifestColumnMembership`
11. Emit one top-level SYMBT3-H development proof.

## 10. Verifier Algorithm

`verify_symbt3_h_batched_cp(public_statement, proof)`:

1. Parse SYMBT3-H marker/version.
2. Reject unless:
   - `NonAuthoritativeDevelopment`;
   - `NonZkDevelopment`;
   - `top_level_backend_proof_count == 1`;
   - `family_columnar_subproofs == 0`;
   - `backend_table_count == 1`;
   - `RelationDescription::num_constraints == 0`.
3. Recompute:
   - manifest layout digest;
   - source column layout digest;
   - `folding_protocol_id`;
   - `folding_transcript_digest`;
   - beta;
   - `proof_relation_id`;
   - `proof_public_statement_digest`.
4. Check transcript separation:
   - manifest/source roots affect beta;
   - folded/output-side data does not affect beta;
   - folded/output-side data affects `proof_public_statement_digest`.
5. Bind `batch_manifest_root` and SYMBT3-H oracle root.
6. Derive membership challenge `rho`.
7. Verify the single WHIR/PCS proof.
8. Verify the source-manifest membership zero-check.
9. Accept iff every enabled cumulative SYMBT3-H family verifies.

The verifier must not:

- call `CpFieldRelation::check`;
- inspect witness bundles;
- open full private manifest/source columns;
- construct appended typed CP R1CS rows;
- verify independent per-table WHIR proofs;
- perform byte transcript/hash reconstruction;
- route product `verify_public` through SYMBT3-H.

## 11. What H Proves

If `verify_symbt3_h_dev` accepts, then under the current development soundness
assumptions:

1. beta is derived from input-side transcript data only;
2. all SYMBT3-G algebra/range checks still pass;
3. source columns used by SYMBT3 are bound to the batch manifest according to
   `Symbt3BatchManifestLayoutV1`;
4. source public inputs, commitments, evaluations, accumulator boundary
   coordinates, and Ajtai commitment coordinates match their manifest entries;
5. source assignment roots and message roots are bound as input-side CP
   commitment boundary data;
6. the entire cumulative check remains inside one top-level WHIR proof object.

This is the first step where SYMBT3 starts to become externally anchored, not
merely internally self-consistent.

## 12. What H Does Not Prove

SYMBT3-H still does not prove:

- CP message semantic validity beyond existing algebraic slices;
- full monomial embedding range authority;
- full integer/mod-q lattice range authority;
- zero-knowledge/masking;
- final production soundness;
- product `verify_public` correctness under SYMBT3;
- public proof envelope migration.

So H remains:

- `NonAuthoritativeDevelopment`
- `NonZkDevelopment`

## 13. Tests

### Metadata and Transcript Tests

`manifest_layout_digest` changes when:

- component kind list changes;
- component order changes unless canonicalized;
- coordinate length changes;
- source-column mapping changes;
- manifest-column mapping changes;
- active policy changes;
- padding policy changes;
- root policy changes;
- commitment scheme id changes.

`folding_protocol_id` changes when:

- manifest layout changes;
- input public boundary digest changes;
- batch manifest root changes;
- source assignment root changes;
- message oracle root changes;
- source Ajtai commitment digest changes;
- batch size changes;
- active count changes.

Beta digest changes when:

- batch manifest root changes;
- source assignment root changes;
- message root changes;
- input boundary changes;
- active count changes.

Beta digest does not change when:

- folded output changes;
- folded GR1CS boundary changes;
- folded Ajtai commitment/opening changes;
- range witness changes;
- proof oracle root changes.

### Manifest Layout Tests

- manifest component layout roundtrips canonically;
- component-kind reorder either canonicalizes or changes relation id deterministically;
- wrong component-kind label rejects;
- wrong coordinate length rejects;
- duplicate component kind rejects unless explicitly allowed;
- missing component kind rejects;
- cryptographic roots cannot be registered as linearly folded algebraic coordinates;
- byte-section / FS-opening / digest-body components reject.

### Membership Tests

- honest `k=1` SYMBT3-H verifies;
- honest `k=2` SYMBT3-H verifies;
- tampering manifest public input coordinate rejects;
- tampering source public input coordinate rejects;
- tampering source commitment coordinate rejects;
- tampering source evaluation coordinate rejects;
- tampering source accumulator-boundary coordinate rejects;
- tampering source Ajtai commitment coordinate rejects;
- tampering source assignment root rejects;
- tampering message root rejects;
- tampering `batch_manifest_root` rejects;
- tampering active count rejects.

### Inactive Row Tests

- inactive rows do not affect membership checks;
- inactive-row values may vary unless bound by public digest or dummy canonicality;
- turning an inactive row active changes `active_count`/beta and rejects stale proof.

### Proof-Shape Tests

- `top_level_backend_proof_count == 1`
- `family_columnar_subproofs == 0`
- `backend_table_count == 1`
- `RelationDescription::num_constraints == 0`
- no appended typed CP R1CS
- no `CpFieldRelation::check`
- no product `verify_public` routing

### Rejection Tests

- SYMBT2F proof rejected as SYMBT3-H;
- SYMBT2C proof rejected as SYMBT3-H;
- SYMBTC1/SYMBTC2 proof rejected as SYMBT3-H;
- monolithic typed CP proof rejected as SYMBT3-H;
- independent WHIR table proof rejected as SYMBT3-H;
- proof built under one manifest layout rejected under another.

## 14. Benchmarks

Add:

```text
symbt3_h_vs_k
```

Run:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench \
  --bench whir_scaling --features whir -- "symbt3_h_vs_k"
```

Report:

- `k`
- proof bytes
- prove mean
- verify mean
- `num_vars`
- sumcheck rounds
- top-level backend proof count
- `family_columnar_subproof` count
- backend table count
- manifest component count
- manifest coordinate count
- membership challenge count
- opened field elements
- WHIR/PCS openings

Interpretation:

```text
SYMBT3-H is not expected to be faster than G.
The success criterion is manifest/source binding while preserving one-proof
architecture and much-slower-than-linear scaling.
```

## 15. Acceptance Criteria

SYMBT3-H is complete when:

1. `Symbt3BatchManifestLayoutV1` exists and is canonically serialized/digested.
2. Batch manifest root and source-column layout are bound into the correct
   transcript/public-statement paths.
3. `SourceManifestColumnMembership` proves typed coordinate equality between
   source columns and manifest columns.
4. Source assignment roots and message roots are bound as input-side CP
   commitment boundary data.
5. Manifest/source changes affect beta.
6. Folded/output-side changes do not affect beta.
7. Tampering any active manifest/source coordinate rejects.
8. The proof still has one top-level WHIR object, zero
   `family_columnar_subproofs`, one backend table, and no appended typed CP
   R1CS.
9. Product `verify_public` remains on authoritative monolithic typed CP.
10. Docs label SYMBT3-H as `NonAuthoritativeDevelopment` and
    `NonZkDevelopment`.

## 16. Suggested Implementation Order

1. Add `Symbt3BatchManifestLayoutV1` and component layout types.
2. Add manifest/source component-kind enum.
3. Add canonical digesting and layout tests.
4. Add `batch_manifest_root` and layout digests to the SYMBT3 public statement.
5. Bind manifest layout into `folding_protocol_id` and `proof_relation_id`.
6. Add `SourceManifestColumnMembership` as one generalized component-kind
   equality family.
7. Extend the single SYMBT3 table/oracle with manifest columns or manifest
   membership openings.
8. Implement the source-manifest equality zero-check.
9. Add root-binding checks for source assignment roots and message roots.
10. Add negative tests for manifest/source tampering.
11. Add proof-shape guards.
12. Add `symbt3_h_vs_k` benchmark.
13. Update docs with exact invariant and caveats.
