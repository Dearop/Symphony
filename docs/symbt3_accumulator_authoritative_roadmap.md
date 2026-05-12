# SYMBT3 Accumulator-Authoritative Roadmap

## Central Rule

Do not make SYMBT3 authoritative by restoring monolithic typed-CP logic into
the verifier or into byte/table gadgets. Make it authoritative by proving the
missing commitment/evaluation links succinctly inside the CP-aware WHIR
relation.

---

## Target Theorem

`verify_symbt3_accumulator_authoritative(profile, public_statement, proof) = true`
implies there exist committed source columns, CP message oracles, openings,
folded witness data, and accumulator witness data such that:

1. All active batch rows are included in the committed manifest.
2. The source columns used by SYMBT3 are exactly the manifest-bound source data.
3. CP round-message oracles are exactly the committed folding messages.
4. Fiat-Shamir / beta challenges are derived from input-side data only.
5. Folded outputs and folded accumulator objects are beta-linear combinations
   under the declared ring/module law.
6. Source and folded GR1CS/R1CS residual checks hold.
7. Ajtai commitment/opening algebra holds.
8. Folded Ajtai opening satisfies the declared norm/range policy.
9. `old_accumulator + batch` produces the declared `new_accumulator`.
10. The proof satisfies the declared WHIR/Σ-IOP soundness profile.

For a full CP-SNARK/zkSNARK claim, add:

11. The proof is zero-knowledge / masked for all private witness-bearing columns.

For a research soundness-only accumulator, item 11 is explicitly out of scope.

---

## Three-Gate Policy Model

Three authority tiers exist and must be maintained:

**DevVerify** — non-authoritative development mode.
- Useful for testing individual SYMBT3 blocks.
- No soundness guarantees. Development-only field and range policies allowed.
- `authority_status = NonAuthoritativeDevelopment`
- `routing_status = ResearchOnly`, `product_eligible = false`

**ResearchAuthorityCandidateV0** — current non-ZK research path.
- Current J2/K0 proofs pass this gate.
- Does NOT require `ManifestEvaluationClaim` or `AccumulatorTransitionConsistency`.
- `authority_status = AuthorityCandidateV1`, `soundness_status = SoundnessCandidate`
- `routing_status = ResearchOnly`, `product_eligible = false`
- `zk_status = NonZkDevelopment`

**AccumulatorSoundnessAuthorityCandidateV1** — K1 + K2 + K3 required.
- Replaces the old `ResearchAuthorityCandidate` for accumulator-authoritative proofs.
- Requires `ManifestEvaluationClaim` and `AccumulatorTransitionConsistency`.
- Requires production norm/range families. Rejects all dev-only modes.
- `authority_status = AuthorityCandidateV1`, `soundness_status = SoundnessCandidate`
- `routing_status = ResearchOnly`, `product_eligible = false`
- `zk_status = NonZkDevelopment`

**ProductAuthority** — strict gate for production/product routing (K6).
- Do not weaken. Only reachable after K1 + K2 + K3 + K4 pass.
- In this implementation run, product route is NonZK integrity mode only.
  Full ProductAuthority for zkSNARK/CP-SNARK semantics remains blocked until K5.
- `routing_status = ProductAuthority`, `product_eligible = true`

The distinction between `ResearchAuthorityCandidateV0` and
`AccumulatorSoundnessAuthorityCandidateV1` must be tracked by a
`semantic_profile_version` field or equivalent discriminant so that old J2/K0
proofs do not ambiguously "pass research authority" after K1/K2 are added.

---

## Semantic-to-Implementation Family Mapping

Roadmap names are semantic requirements. They do not correspond one-to-one
with `BatchedCpSymbt3ConstraintFamily` enum variants. The authority profile
checks semantic requirements; a semantic requirement may be satisfied by one
variant, several variants, or a versioned layout/profile field.

**Rule**: do not rename existing enum variants. Enum names remain stable. The
mapping table below is the canonical reference.

| Roadmap semantic family | Implementation enum variant(s) / status |
|---|---|
| `ChallengeToBeta` | `ChallengeToBeta` ✓ |
| `FoldedOutputVectorIdentity` | `FoldedPublicInputLinearIdentity` + `FoldedCommitmentLinearIdentity` + `FoldedEvaluationLinearIdentity` + `FoldedAccumulatorBoundaryIdentity` ✓ |
| `CommittedSourceR1csResidualValidity` | `CommittedSourceR1csResidualValidity` ✓ |
| `FoldedGr1csBoundaryConsistency` | `FoldedGr1csResidualValidity` (verify current enum spelling) ✓ |
| `FoldedGr1csProductResidualZeroCheck` | `FoldedGr1csProductResidualZeroCheck` ✓ |
| `RingModuleAlgebraLaw` | Not a standalone family — enforced by layout/profile fields: `Symbt3AlgebraLaw`, `RqNegacyclicConvolutionV1`, `RingCoefficientActionV1`, `RingBetaAction` / beta-action layout ✓ |
| `FoldedAjtaiOpeningLinearIdentity` | `FoldedAjtaiOpeningLinearIdentity` ✓ |
| `FoldedAjtaiCommitmentLinearIdentity` | `FoldedAjtaiCommitmentLinearIdentity` ✓ |
| `FoldedAjtaiMapConsistency` | `FoldedAjtaiMapConsistency` ✓ |
| `ProductionNormRange` | `FoldedAjtaiProjectionConsistency` + `FoldedAjtaiProjectedRangeBound` + `FoldedAjtaiMonomialEmbeddingConsistency` + `ProjectedOpeningRepresentativeValidity` ✓ |
| `MessageOracleSemanticViews` | `NativeMessageOracleViews` (I2 native-view family) ✓ |
| `CompressedManifestSourceMembership` | `ManifestEvaluationClaim` — **new K1 family** |
| `AccumulatorTransitionConsistency` | `AccumulatorTransitionConsistency` — **new K2 family** |

Special notes:
- `RingModuleAlgebraLaw` is a layout/profile requirement, not a single constraint
  family.
- `ProductionNormRange` is a bundle: all four variants must be present.
- `FoldedOutputVectorIdentity` is a bundle over typed component kinds (public
  inputs, commitments, evaluations, accumulator coordinates).
- `CompressedManifestSourceMembership` and `AccumulatorTransitionConsistency` are
  new authority requirements added by K1 and K2 respectively.

---

## Current State

The codebase (`src/modular/batched_cp.rs`, `src/snark/whir/mod.rs`) has:

- 33 constraint families in `BatchedCpSymbt3ConstraintFamily`
- 3-tier authority profile: development / research-candidate / authority-candidate
- K0/J3 compact evaluator + public-boundary performance fix: verifier binds
  `batch_manifest_root` without reconstructing all manifest rows; proof path has
  one WHIR proof, zero columnar subproofs, one backend table
- Production norm/range families: `StructuredBlockProjectionV1`,
  `MonomialEmbeddingRangeV1`
- WHIR backend integration with Poseidon2/BabyBear

**Current soundness gaps:**

1. `SourceManifestColumnMembership` is root-binding only. No polynomial
   evaluation proof links source columns to `batch_manifest_root`. (Fixed by K1.)

2. `AccumulatorTransitionConsistency` does not exist. Old/new accumulator values
   are raw `Vec<i64>` with no formal transition constraint. (Fixed by K2.)

3. No `Symbt3AccumulatorInstance` / `Symbt3AccumulatorWitness` typed structs.
   (Fixed by K2.)

4. Higher authority profiles do not yet require `ManifestEvaluationClaim` or
   `AccumulatorTransitionConsistency`. (Fixed by K3.)

5. `Symbt3AuthorityProfile` is missing policy digest fields and soundness
   accounting fields. (Fixed by K3.)

---

## Milestone Order

```
K1 → K2 → K3 → K4 → K4.5/K3b → K4.6 → K6
              (K5 ZK: deferred)
```

M0/M1/M2 from the product integration design are merged into K4 (M0, M1) and
K6 (M2). No separate M-milestones.

### Implementation Sub-Steps (ordered)

Implement in this exact order. Each step must leave all existing tests green
before the next step begins.

1. **K1a — Root policy enum/digest**
   Add `ManifestCommitmentPolicy::DigestOfLayoutAndOracleRootV1`. Wire into
   `Symbt3AuthorityProfile::manifest_commitment_policy_digest`. Verifier
   recomputes and checks `batch_manifest_root` from `manifest_oracle_root` +
   `manifest_layout_digest`. Negative test: wrong root → verifier rejects.
   **Status: implemented.** The SYMBT3 research public statement now exposes
   `manifest_oracle_root`, the product-level `batch_manifest_root` is linked by
   the K1a policy digest, and verifier-side root/layout tampering rejects.

2. **K1b — `ManifestEvaluationClaim` family**
   Add enum variant, manifest oracle commitment, `manifest_membership_challenge`
   timing (after proof oracle roots, distinct from `beta_challenge`), evaluation
   equality constraint, and all K1 negative tests. Manifest oracle stays inside
   the top-level proof object.
   **Status: implemented as research single-table K1b.** The SYMBT3 relation
   now includes `ManifestEvaluationClaim`, the public statement binds
   `manifest_eval_claim`, and verifier-side proof checks reject stale or
   tampered manifest/source membership evaluations. Current code keeps the
   manifest/source evaluation openings in the one top-level SYMBT3 WHIR table.

3. **K1c — Streaming verifier source evaluation**
   Remove verifier-side full manifest row reconstruction from the K1
   membership check. The verifier derives the source-side evaluation directly
   from the compressed public statement in canonical item/component/coordinate
   order and compares it to the opened source membership value. Prover-side
   full-row checks remain sanity checks.
   **Status: implemented.** `symbt3_manifest_source_eval_claim_for_statement`
   computes the verifier-side claim without materializing manifest rows, and
   tests assert it matches the manifest-oracle evaluation claim.

4. **K1d — Authoritative manifest-root/source binding**
   The verifier recomputes the canonical `manifest_oracle_root` from the
   compressed public source boundary using the same streaming order as K1c, then
   requires that root before transcript and claim derivation.
   **Status: implemented.** A root-linked but non-canonical
   `manifest_oracle_root` now fails `matches_relation` and SYMBT3 verification.
   This preserves `top_level_whir_proof_count = 1`,
   `family_columnar_subproof_count = 0`, and `backend_table_count = 1`.

5. **K1e — Succinct manifest evaluation binding**
   Replace the dense manifest-oracle-in-main-table path with a public canonical
   manifest view evaluator. The verifier recomputes `canonical_manifest_root`
   and `ManifestView(zeta)` from compressed public boundary data, then checks
   virtual `SourceView(zeta)` from the same public-boundary layout against that
   value without committing a dense source-view column.
   **Status: implemented.** `ManifestCommitmentPolicy::PublicCanonicalManifestViewV1`
   is profile-bound, private manifest components are rejected by authority
   profile metadata, `manifest_eval_claim` is no longer trusted as a public
   fact, and the backend table has no manifest oracle/value/residual columns or
   source-view column. `source_view_backend_column_count`,
   `source_view_materialized_coordinate_count`,
   `manifest_backend_column_count`, and
   `manifest_materialized_coordinate_count` are all zero.
   This preserves one top-level WHIR proof, zero family subproofs, one backend
   table, and `message_to_trace_binding_count = 0`.

6. **K2a — Typed accumulator structs**
   Add `Symbt3AccumulatorInstance`, `Symbt3AccumulatorWitness` (with
   `Symbt3TypedMessageOracle`), `digest()`, and `to_public_statement()`. Add
   `old_accumulator_digest` / `new_accumulator_digest` to public statement.
   Digest stability test.
   **Status: implemented structurally.** The public statement now binds
   `old_accumulator_digest` and `new_accumulator_digest`, typed accumulator
   instance/witness wrappers exist, and `Symbt3AccumulatorInstance::digest()`
   plus `to_public_statement()` round-trip tests are covered. This does not yet
   prove `old_accumulator -> new_accumulator`; transition soundness remains K2b.
   The digests are intentionally excluded from folding beta derivation and are
   bound through the public-statement/proof transcript plus accumulator instance
   digest. K2b's `rho_acc` challenge will own accumulator-update binding.

7. **K2b — Option B accumulator transition**
   Add `AccumulatorTransitionConsistency` family. Squeeze `rho_acc` from
   transcript after `old_accumulator_digest` and `folded_output_boundary_digest`.
   Verify `new_acc_coords == FoldAcc(old_acc_coords, folded_batch_coords; rho_acc)`.
   All K2 negative tests (verifier rejects wrong `old_acc`, wrong `new_acc`, etc.).
   **Status: implemented.** `AccumulatorTransitionConsistency` is now a
   relation family and the authority profile binds
   `symbt3_accumulator_transition_profile_digest`. The transition law is
   explicitly `new[i] = rho_acc * old[i] + (1 - rho_acc) * folded_batch[i]`
   over BabyBear coordinates, with `rho_acc` derived under
   `SYMBT3_ACC_TRANSITION` from shape/relation metadata, the transition
   profile, `old_accumulator_digest`, and the folded batch boundary. Folding
   beta remains input-side and does not include old/new accumulator digests.
   The verifier checks the transition over the accumulator boundary only, so
   `accumulator_transition_claims = 1` and does not scale with `k`.

8. **K3 — Authority profile hardening**
   Add policy digest fields, `semantic_profile_version`, soundness accounting
   (union bound), `accumulator_soundness_authority_candidate_from_relation()`
   factory, and `profile_meets_accumulator_soundness_authority()` gate. All K3
   negative tests (dev range/projection modes rejected, soundness bits gate).

   **Status: implemented.** `semantic_profile_version = 0` remains the
   research-only authority-candidate profile, while
   `semantic_profile_version = 1` is the research-only
   `AccumulatorSoundnessAuthorityCandidateV1` gate. `Symbt3AuthorityProfile`
   now binds the challenge schedule, Fiat-Shamir domains, ring/module law,
   Ajtai policy, norm/range policy, manifest policy, message-oracle policy, and
   accumulator-transition policy digests. Effective soundness is computed by a
   union bound over declared failure-probability terms, not by summing bit
   contributions. The K3 gate requires K1 `ManifestEvaluationClaim`, K2
   `AccumulatorTransitionConsistency`, public-canonical manifest binding,
   production-shaped structured projection/range families, populated policy
   digests, non-development soundness status, and sufficient effective
   soundness. It rejects development range/projection modes, identity-shaped
   projection layouts, zeroed policy digests, low soundness bits, and stale
   proofs under changed norm/range table policy. ProductAuthority still rejects
   the current NonZK profile; product `verify_public` is unchanged. Any K3
   verifier helper still consumes the existing SYMBT3 public statement and
   proof, so it is not K4 completion. K4 remains the named public accumulator
   API milestone and must accept a `Symbt3AccumulatorInstance` boundary
   directly.

9. **K4 — Research public accumulator API**
   Add `prove/verify_public_symbt3_accumulator_research_non_zk(...)`.
   `// NonZK:` doc annotation. Integration test for k=4 batch. All K4 acceptance
   criteria including scaling ratio gate.

10. **K4.5 / K3b — Verifier-side evaluator compression**
   Compress verifier-side source R1CS residual evaluation work. The logical
   `source_r1cs_residual_claims` may remain present for auditability, but the
   verifier must batch them into one or a few challenge evaluations so verifier
   work is `O(1)` or `O(log k)`, not `O(k)` and not `64 * k` separate residual
   checks. This is a performance/succinctness mini-milestone after the K4 API
   boundary exists; it is not required to call K3 profile hardening implemented,
   and it does not by itself complete K4.

11. **K4.6 — Compressed public accumulator boundary**
    Replace public-boundary serialization of expanded per-item accumulator data
    with digest commitments while preserving expanded construction/debug data
    outside the canonical public instance.

12. **K6 — Product route promotion (only after K1–K4.6 green)**
   Add NonZK integrity-mode routing in `verify_public()`. Hard proof-shape
   checks. Both benchmark suites with all 16 metrics. Speedup comparison vs
   monolithic typed CP.

---

## K1 — Compressed Manifest / Source Membership

**Problem.** `batch_manifest_root` is necessary but not sufficient. A malicious
prover can supply source columns inconsistent with the manifest root and the
verifier will not detect it. The current `SourceManifestColumnMembership` family
does a prover-side residual check only; the verifier binds the root without
verifying any evaluation claim.

**Approach: native WHIR oracle.**

Commit the manifest as a native WHIR/BCS multilinear oracle — the same
infrastructure already used for CP message oracles. The manifest oracle must
live inside the same top-level SYMBT3 proof object. It must not introduce a
separate WHIR proof or `family_columnar_subproof`.

The prover evaluates the manifest oracle and the source oracle at a
verifier-derived challenge point and supplies the evaluation claims. The WHIR
constraint table enforces:

```
manifest_oracle.eval(membership_challenge) == manifest_eval_claim
source_oracle.eval(membership_challenge)   == manifest_eval_claim
```

### Root-Linking Policy (Option B — chosen)

K1 uses two roots: `batch_manifest_root` (product-level) and
`manifest_oracle_root` (WHIR oracle commitment). These must be definitionally
linked. Without the link, a malicious prover can bind beta to one root and prove
source membership against a different root. Merely absorbing both roots into the
transcript is not sufficient.

**Chosen policy — Option B:**
```
batch_manifest_root := H("SYMBT3_MANIFEST", manifest_layout_digest, manifest_oracle_root)
```

This keeps the product-level manifest root distinct and versioned while making
the WHIR manifest oracle root unambiguously bound to it. The domain separator
`"SYMBT3_MANIFEST"` prevents cross-protocol collisions.

This policy is encoded as `ManifestCommitmentPolicy::DigestOfLayoutAndOracleRootV1`
and must appear in the profile as `manifest_commitment_policy_digest`. The
verifier recomputes `batch_manifest_root` from `manifest_oracle_root` and
`manifest_layout_digest` using this hash and checks it against the claimed
`batch_manifest_root` in the public statement.

### Challenge Timing: Beta vs. Manifest Membership

Two distinct challenge types exist with different derivation rules:

**`beta_challenge` (folding randomness):**
- Input-side transcript only.
- Sources: shape/profile IDs, `old_acc.x`, manifest root, source roots,
  message oracle roots, `active_count`.
- Must NOT depend on folded output or proof oracle roots.

**`manifest_membership_challenge` (proof-checking randomness):**
- Sampled after the following are bound in the transcript:
  - `manifest_oracle_root`
  - source / proof oracle commitment root
  - `manifest_layout_digest`
  - source layout digest
  - profile / relation ID
  - WHIR params digest
- May depend on the proof oracle root.
- Must NOT be used as folding beta.

This mirrors the Symphony boundary: FS folding challenges are derived from input
and message commitments; the CP proof proves algebraic consistency of those
committed objects without embedding hash circuits in the statement.

### Evaluation Claims Are Checked, Not Trusted

`manifest_eval_point` is derived by the verifier from the transcript. If it
appears in the public statement for debugging purposes, it is redundant and must
be checked against transcript recomputation during verification. It must not be
accepted as prover-supplied public data.

Apply this discipline to **all** evaluation claims, not just the eval point:
- `manifest_eval_claim` is a claim to be verified — accepted only after checking
  the WHIR opening against `manifest_oracle_root`.
- Source-oracle eval claim is checked against the same `manifest_membership_challenge`.
- Neither claim is trusted as a public input fact.

Verification of `manifest_eval_claim` requires all four conditions:
1. Recomputed `manifest_membership_challenge` from transcript.
2. WHIR opening/evaluation proof against `manifest_oracle_root`.
3. Equality to the corresponding source-oracle evaluation.
4. Root-linking: `batch_manifest_root == H("SYMBT3_MANIFEST", manifest_layout_digest, manifest_oracle_root)`.

### CP Message Oracle Authority (K1 co-requirement)

The I2 invariant must hold throughout K1: `message_to_trace_binding_count = 0`.
Message oracle values are native relation-bound views, not separately committed
trace copies.

Required invariant: for each folding round `i`:
```
c_fs,i := root(M_i)
```
where `M_i(T, U_i)` is the committed CP round-message oracle. The `beta_challenge`
(and all FS folding challenges) is derived from input boundary, `manifest_root`,
source roots, `message_oracle_roots[0..i]`, shape/profile IDs — never from
folded output or proof oracle roots.

What must be proven: typed values consumed by the folding algebra are native
views of `M_i(T, U_i)`, not separately committed trace copies.

Acceptance criteria for message oracle semantics:
1. Changing a message root changes the relevant FS challenge.
2. Changing folded output does not change beta / folding challenges.
3. Changing a message view map changes the relation/profile digest.
4. Tampering a message coordinate consumed by the evaluator causes verifier rejection.
5. No materialized `message_trace_values` or `message_trace_col` exists.
6. No byte transcript / FS opening / digest-body machinery introduced.
7. `message_to_trace_binding_count = 0`.

### Changes

**`src/modular/batched_cp.rs`**

- Add `ManifestEvaluationClaim` variant to `BatchedCpSymbt3ConstraintFamily`
  (enum lines 346–380).
- Add fields to `BatchedCpSymbt3PublicStatement`:
  - `manifest_oracle_root: Digest` — root of the committed manifest oracle
  - `manifest_eval_claim: BabyBear` — prover's claimed evaluation
  - `manifest_eval_point` must NOT be trusted from public input; derive from transcript
- Add `ManifestCommitmentPolicy::DigestOfLayoutAndOracleRootV1` enum and
  populate `manifest_commitment_policy_digest` in `Symbt3AuthorityProfile`.
  The verifier uses this to recompute and check `batch_manifest_root`.
- Extend `has_symbt3_h_families()` (lines 3862–3880) to require
  `ManifestEvaluationClaim` for `AccumulatorSoundnessAuthorityCandidateV1`
  profiles.
- Bump `SYMBT3_LAYOUT_VERSION`.

**`src/snark/whir/mod.rs`**

- In the constraint table builder, add the `ManifestEvaluationClaim` entry.
- Squeeze `manifest_membership_challenge` from transcript after absorbing
  `manifest_oracle_root`, source/proof oracle root, layout digests, profile ID,
  WHIR params — not before.
- Separately, `beta_challenge` remains squeezed from input-side transcript only
  (before any proof oracle root is absorbed).
- Verifier recomputes `manifest_eval_point` from transcript; does not accept it
  from the public statement.
- Verifier checks the claimed evaluation against `manifest_oracle_root` via the
  WHIR opening. No full manifest reconstruction.
- Existing prover-side `symbt3_manifest_membership_residual_values` (lines
  ~1848–1856) remains a witness consistency check; it is not the verification path.

### K1 Acceptance Criteria

1. `public_statement_bytes(k) / public_statement_bytes(k/2) <= 1.25` for k in 4..64.
2. `verify_transcript_ms(k) / verify_transcript_ms(k/2) <= 1.25` for k in 4..64.
3. `batch_manifest_root` and `manifest_oracle_root` are both transcript-bound
   and linked by the declared root policy.
4. `manifest_membership_challenge` is sampled after proof oracle roots are bound
   (not before); `beta_challenge` is input-side only.
5. `manifest_eval_point` is verifier-derived and not accepted from public input.
6. `ManifestEvaluationClaim` appears in the WHIR backend table.
7. Verifier does not reconstruct manifest rows.
8. `top_level_whir_proof_count = 1`, `family_columnar_subproof_count = 0`,
   `backend_table_count = 1`.
9. **Negative (verifier)**: mutating `batch_manifest_root` in public statement
   → verifier rejects.
10. **Negative (verifier)**: mutating `manifest_oracle_root` in public statement
    → verifier rejects.
11. **Negative (verifier/prover)**: source column coordinate inconsistent with
    manifest root → prover fails OR verifier rejects with test-only bypass of
    prover-side assertions.
12. **Negative (verifier)**: wrong `batch_manifest_layout_digest` → verifier rejects.
13. **Invariant test**: manifest root mutation changes `manifest_membership_challenge`.
14. **Invariant test**: manifest root mutation changes `beta_challenge`.
15. **Invariant test**: folded output mutation does NOT change `beta_challenge`.
16. **Negative (verifier)**: stale proof under changed manifest → verifier rejects.
17. All message oracle semantics criteria above hold.
18. Manifest oracle is part of the top-level SYMBT3 proof object (code audit:
    no new WHIR proof or `family_columnar_subproof` introduced).

**Files**: `src/modular/batched_cp.rs`, `src/snark/whir/mod.rs`, `tests/batched_cp.rs`

---

## K2 — Typed Accumulator Structs + Transition Relation

**Problem.** No `Symbt3AccumulatorInstance` / `Symbt3AccumulatorWitness` exist.
No constraint family enforces `new_acc = Accumulate(old_acc, folded_batch; ?)`.

**Multi-instance constraint (Quasar-style):** The accumulator transition must
not impose verifier cost linear in `k`. The verifier must not:
- recompute a linear combination of `k` roots / commitments
- read `k` manifest rows
- hash `k` message roots one by one

The verifier sees roots/digests only. The proof proves the batched/folded
relation. The accumulator update is one proof object.

### Accumulator Transition Law (Option B — chosen)

**Chosen: 2-to-1 update with a separate accumulator challenge.**

```
rho_acc = H("SYMBT3_ACC_TRANSITION", old_acc.x, folded_batch.x, ...)
new_acc  = FoldAcc(old_acc, folded_batch; rho_acc)
```

`rho_acc` is a separate, independently derived challenge — distinct from the
folding `beta_challenge`. The domain separator `"SYMBT3_ACC_TRANSITION"` prevents
cross-protocol collisions. The verifier does one O(1) combination, not O(k)
commitment combinations, satisfying the Quasar constraint.

This keeps folding randomness (`beta`) and accumulator-update randomness
(`rho_acc`) cleanly separated, and avoids ambiguity about what beta covers.
The `AccumulatorTransitionConsistency` family proves:

```
new_acc_coords == rho_acc * old_acc_coords + (1 - rho_acc) * folded_batch_coords
```

or the appropriate ring/module formulation for the declared algebra law. The
exact arithmetic form must match the `ring_module_law_digest` in the profile.

Layer 1 (current path): `k` same-shape CP objects → one folded batch object.
Layer 2 (this milestone): `old_accumulator + folded_batch → new_accumulator`.
Both layers are unified under K2. Layer 2 is not a separate milestone.

### Changes

**`src/modular/batched_cp.rs`**

Add typed structs before `BatchedCpSymbt3PublicStatement`:

```rust
pub struct Symbt3AccumulatorInstance {
    pub profile_digest: Digest,
    pub shape_id: Digest,
    pub batch_size: usize,
    pub active_count: usize,
    pub old_accumulator_digest: Digest,
    pub new_accumulator_digest: Digest,
    pub manifest_root: Digest,
    pub manifest_layout_digest: Digest,
    pub source_column_layout_digest: Digest,
    pub message_oracle_roots: Vec<Digest>,
    pub source_assignment_roots: Vec<Digest>,
    pub folded_output_boundary_digest: Digest,
    pub folded_gr1cs_boundary_digest: Digest,
    pub folded_ajtai_commitment_digest: Digest,
    pub folded_ajtai_opening_digest: Digest,
    pub whir_params_digest: Digest,
}

pub struct Symbt3AccumulatorWitness {
    pub manifest_oracle: Vec<Vec<i64>>,
    pub source_columns: Vec<Vec<i64>>,
    // Typed oracle views, not raw byte blobs — prevents regression toward
    // byte-transcript semantics.
    pub message_oracles: Vec<Symbt3TypedMessageOracle>,
    pub folded_witness_columns: Vec<Vec<i64>>,
    pub ajtai_openings: Vec<Vec<i64>>,
    pub old_accumulator_coordinates: Vec<i64>,
    pub new_accumulator_coordinates: Vec<i64>,
}
```

Note: `message_oracles` must use a typed view type (e.g. `Symbt3TypedMessageOracle`
or `MessageOracleColumns`), not `Vec<Vec<Vec<u8>>>`. Raw bytes are an internal
serialization detail, not the witness API.

- Add `AccumulatorTransitionConsistency` to `BatchedCpSymbt3ConstraintFamily`
  in K2b.
- Add `old_accumulator_digest` and `new_accumulator_digest` to
  `BatchedCpSymbt3PublicStatement`.
- Add `Symbt3AccumulatorInstance::to_public_statement(...)` conversion helper.
- Add `Symbt3AccumulatorInstance::digest()` for stable hashing.
- Bump `SYMBT3_LAYOUT_VERSION`.

**`src/snark/whir/mod.rs`**

Wire `AccumulatorTransitionConsistency` into the constraint table (Option B):
- Squeeze `rho_acc = H("SYMBT3_ACC_TRANSITION", old_acc.x, folded_batch.x, ...)`
  from the transcript after `old_accumulator_digest` and `folded_output_boundary_digest`
  are absorbed.
- Verify: `new_acc_coords == FoldAcc(old_acc_coords, folded_batch_coords; rho_acc)`.
- The verifier does one O(1) combination, not O(k) commitment combinations.

### K2 Acceptance Criteria

1. `Symbt3AccumulatorInstance::digest()` is stable (add digest stability test).
2. `AccumulatorTransitionConsistency` appears in the constraint table.
3. The Option B transition law is documented in the profile via `ring_module_law_digest`.
4. Proof with correct `old_acc → new_acc` verifies.
5. Verifier work is O(1) in `k` (no O(k) loop in verifier, code audit).
6. **Negative (verifier)**: mutating `old_accumulator_digest` → verifier rejects.
7. **Negative (verifier)**: mutating `new_accumulator_digest` → verifier rejects.
8. **Negative (verifier/prover)**: wrong `folded_accumulator_coordinates` →
   prover fails OR verifier rejects with test-only bypass.
9. **Negative (verifier)**: wrong `shape_id` in accumulator instance → rejects.
10. **Negative (verifier/prover)**: mixed-shape batch → prover fails.
11. **Negative (verifier)**: stale accumulator proof under changed manifest →
    verifier rejects.
12. **Negative (verifier)**: wrong accumulator profile digest → rejects.
13. `message_oracles` field uses typed view type, not raw bytes (code audit).
14. All existing tests pass.

**Files**: `src/modular/batched_cp.rs`, `src/snark/whir/mod.rs`, `tests/batched_cp.rs`

---

## K3 — Production Authority Profile Hardening

**Problem.** Higher authority profiles do not yet require K1 or K2 families,
do not reject development-only norm/range modes, and lack the policy digest
fields and soundness accounting fields from the design.

### Soundness Accounting: Union Bound (Not Sum)

**Do not sum bit-security contributions.** Summing would wildly overestimate
soundness. Error terms compose under a union bound:

```
total_error = sum_i  2^{-bits_i}

effective_soundness_bits = floor(-log2(total_error))
                         = floor(-log2(sum_i 2^{-bits_i}))
```

Gate passes iff `effective_soundness_bits >= soundness_bound_bits`.

Conservative equivalent:
```
min_i(bits_i) >= soundness_bound_bits + ceil(log2(number_of_error_terms))
```

Error contributions to account for:
- WHIR proximity / constrained RS soundness
- Sumcheck identity checks
- Random linear combination / batching checks
- Manifest membership evaluation checks (Schwartz-Zippel over chosen field/extension)
- Message-view checks
- Norm/range projection checks
- Ajtai binding assumptions
- Fiat-Shamir / BCS in the ROM
- Union bound overhead over all enabled families

**Extension-field requirement:** BabyBear is a small field. For authority,
`ManifestEvaluationClaim` requires either:
- Extension-field challenges (so that the Schwartz-Zippel check has enough
  soundness), or
- Repeated checks sufficient to meet `soundness_bound_bits`.

The profile must state which policy is used via `field_policy` and the
soundness accounting must reflect the actual field/extension used.

### Changes

**`src/modular/batched_cp.rs`**

Extend `Symbt3AuthorityProfile` in-place (no new struct):

```rust
// Policy digests (new fields)
pub challenge_schedule_digest: Digest,
pub fiat_shamir_domain_digest: Digest,
pub ring_module_law_digest: Digest,
pub ajtai_policy_digest: Digest,
pub norm_range_policy_digest: Digest,
pub manifest_commitment_policy_digest: Digest,  // records chosen root-linking policy
pub message_oracle_policy_digest: Digest,

// Soundness bound
pub soundness_bound_bits: u32,

// Per-error-term bit contributions (union bound, not sum)
pub whir_proximity_soundness_bits: u32,
pub sumcheck_identity_check_bits: u32,
pub rlc_batching_bits: u32,
pub manifest_membership_bits: u32,
pub message_view_bits: u32,
pub norm_range_projection_bits: u32,
pub ajtai_binding_bits: u32,
pub bcs_rom_bits: u32,
pub union_bound_overhead_bits: u32,

// Profile version discriminant
pub semantic_profile_version: u32,
// 0 = ResearchAuthorityCandidateV0 (no K1/K2 requirement)
// 1 = AccumulatorSoundnessAuthorityCandidateV1 (K1+K2+K3 required)
```

Add `profile_meets_accumulator_soundness_authority(profile) -> bool`:
- Returns `false` if `ManifestEvaluationClaim` not in families.
- Returns `false` if `AccumulatorTransitionConsistency` not in families.
- Returns `false` if `field_policy == BaseFieldSingleCheckDevelopment` and
  soundness accounting does not account for small-field weakness.
- Returns `false` if norm/range layout uses `DirectDevDenseProjectionV1` or
  `DirectSignedRangeDevV1`.
- Returns `false` if identity projection is used.
- Returns `false` if unconstrained representative residuals.
- Returns `false` if debug-only monomial columns present.
- Returns `false` if `soundness_status == DevelopmentOnly`.
- Returns `false` if `effective_soundness_bits < soundness_bound_bits` (union
  bound computation, not sum).
- Returns `false` if any policy digest field is zero (unpopulated).
- Returns `false` if `semantic_profile_version < 1`.

Authority must require:
- `StructuredBlockProjectionV1`
- `MonomialEmbeddingRangeV1`
- Declared signed representative policy
- Declared mod-q / integer lifting policy
- Declared bound B
- Projection seed binding
- Monomiality / constant-term relation

Update `research_authority_candidate_from_relation()` (lines ~4346) to
produce `semantic_profile_version = 0` (unchanged behavior).

Add new factory `accumulator_soundness_authority_candidate_from_relation()`
that produces `semantic_profile_version = 1` with all K1/K2 families required
and all policy digests populated.

**`src/snark/whir/mod.rs`**

Call `profile_meets_accumulator_soundness_authority()` inside
`verify_symbt3_batched_cp_with_profile()` for all non-development profiles with
`semantic_profile_version >= 1`.

### K3 Acceptance Criteria

1. Research-authority profile (`semantic_profile_version = 0`) is unaffected
   by new gates — old J2/K0 tests continue to pass.
2. `AccumulatorSoundnessAuthorityCandidateV1` (`semantic_profile_version = 1`)
   with `DirectSignedRangeDevV1` → gate rejects.
3. Same with `DirectDevDenseProjectionV1` → gate rejects.
4. Same with identity projection → gate rejects.
5. Same with unconstrained representative residuals → gate rejects.
6. Wrong `t_B` table digest → gate rejects.
7. Wrong projection seed → gate rejects; stale proofs reject.
8. Soundness bits below target (union bound) → gate rejects.
9. Policy digest field zeroed → gate rejects.
10. `semantic_profile_version = 0` profile rejected by accumulator authority gate.

**Norm/range acceptance criteria:**
1. In-range positive, negative, and zero values verify.
2. Out-of-range projected value → verifier rejects.
3. Wrong signed representative → verifier rejects.
4. Wrong monomial exponent → verifier rejects.
5. Wrong `t_B` table digest → verifier rejects.
6. Projection seed / layout change → stale proof rejected by verifier.
7. Projection/range data does not affect `beta_challenge`.
8. Projection/range data does affect proof-checking challenges.

**Files**: `src/modular/batched_cp.rs`, `src/snark/whir/mod.rs`, `tests/batched_cp.rs`

---

## K4 — Research Public Accumulator Verifier API (M0 + M1)

**Status.** Implemented as the named NonZK research public accumulator API. It
takes `Symbt3AccumulatorInstance` as public input, but it is still research-only
and does not change product `verify_public` routing.

M0 (research benchmark route) and M1 (soundness-authoritative non-ZK) are
implemented by the same API — M1 is M0 once the profile gates are satisfied.

### Changes

**`src/snark/whir/mod.rs`**

```rust
/// NonZK: may reveal WHIR-queried private coordinates at query positions.
/// Not a zkSNARK. routing_status=ResearchOnly, product_eligible=false.
/// For benchmarking and comparison against monolithic typed CP.
pub fn prove_public_symbt3_accumulator_research_non_zk(
    pk: &WhirProvingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
) -> Option<WhirProof>

/// NonZK: may reveal WHIR-queried private coordinates at query positions.
/// Not a zkSNARK. routing_status=ResearchOnly, product_eligible=false.
pub fn verify_public_symbt3_accumulator_research_non_zk(
    vk: &WhirVerifyingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof: &WhirProof,
) -> bool
```

Both functions fail closed unless:
- `profile.routing_status == ResearchOnly`
- `profile.zk_status == NonZkDevelopment`
- `profile.product_eligible == false`
- `profile.semantic_profile_version >= 1`
- `profile_meets_accumulator_soundness_authority(profile) == true`
- `accumulator_instance.profile_digest == profile.digest(...)`
- `accumulator_instance.to_public_statement().matches_relation(...)`

and delegate to the existing prove/verify path after converting
`Symbt3AccumulatorInstance` to `BatchedCpSymbt3PublicStatement`.
The verifier takes a `WhirVerifyingKey` because the WHIR PCS opening check is
seeded by the relation context; there is no sound verifier from only
`(profile, accumulator_instance, proof)`.

**`src/modular/batched_cp.rs`**

Adds typed conversion helpers:
- `Symbt3AccumulatorInstance::to_public_statement(...)`
- `Symbt3AccumulatorInstance::matches_profile_and_relation(...)`
- `Symbt3AccumulatorWitness::to_symbt3_witness(...)`
- `Symbt3TypedMessageOracle::to_round_messages(...)`

**`tests/batched_cp.rs`**

Integration test (k=4):
- Prove via new API, verify via new API.
- Confirm conversion preserves accumulator digests, manifest roots, source/message
  roots, folded boundary digests, and WHIR params digest.
- Confirm proof shape remains one top-level proof, zero family subproofs, one
  backend table, `message_to_trace_binding_count = 0`, and
  `accumulator_transition_claims = 1`.
- Negative coverage: `ProductAuthority`, `product_eligible = true`,
  `semantic_profile_version = 0`, missing `ManifestEvaluationClaim`, missing
  `AccumulatorTransitionConsistency`, ZK-required profile, mutated old/new
  accumulator digests, mutated profile digest, mutated manifest root, and stale
  folded-output boundary all reject.

**`benches/whir_scaling.rs`**

Adds `symbt3_accumulator_research_vs_k`, which calls the K4 research
accumulator API rather than the lower-level development verifier. The CSV row
reports proof/public bytes, prove/verify time, WHIR sizing, proof-shape counts,
manifest/source materialization counters, accumulator transition claims, message
view coordinates, and verifier cost attribution.

### K4 Acceptance Criteria

1. New prove/verify pair compiles and integration test passes.
2. API functions carry the `// NonZK:` doc comment in source.
3. `ProductAuthority` profile is rejected at the API boundary.
4. `product_eligible = false` is enforced.
5. Product `verify_public` remains unchanged and ProductAuthority still rejects
   the current NonZK profile.
6. All K1 + K2 + K3 acceptance criteria hold when tested through the new API.
7. K5 ZK/masking and K6 product-route promotion remain deferred.

**Files**: `src/snark/whir/mod.rs`, `src/modular/batched_cp.rs`,
`tests/batched_cp.rs`, `benches/whir_scaling.rs`

---

## K4.5 / K3b — Verifier-Side Evaluator Compression

**Problem.** The current SYMBT3 research verifier can preserve compact proof
shape while still doing verifier-side source R1CS residual work one logical
claim at a time. In the current shape this can mean evaluating `64 * k` source
residual claims individually, which recreates a linear-in-batch verifier cost
even when the backend table and public boundary are compact.

**Goal.** Keep source R1CS residual claims logically visible for audit and
debugging, but batch their verifier-side evaluation into one or a few challenge
evaluations. The verifier target is `O(1)` or `O(log k)` work with respect to
the batch size, not `O(k)`.

### Intended Design

- Derive a domain-separated residual batching challenge after the public
  statement/proof roots that bind the source layout, source assignment boundary,
  R1CS evaluator layout, and folded residual boundary.
- Replace per-source/per-coordinate verifier loops with a batched multilinear
  evaluation, random linear combination, or tree/folded evaluator over the
  existing committed source/R1CS columns.
- Keep `source_r1cs_residual_claims` as logical/audit metadata if useful, but
  make `source_r1cs_residual_verifier_evaluations` constant or logarithmic in
  `k`.
- Preserve K1e.2 and K2 proof-shape invariants: one top-level WHIR proof, one
  backend table, zero family subproofs, no dense manifest/source-view columns,
  and `message_to_trace_binding_count = 0`.
- Keep folding `beta` input-side only. The residual batching challenge must not
  replace or mutate beta.

### Non-Goals

- Do not add K5 ZK masking.
- Do not promote SYMBT3 to ProductAuthority.
- Do not introduce K4 public accumulator APIs if this is implemented as K3b
  before K4.
- Do not hide source R1CS residual coverage from audit output; compress verifier
  work, not semantic accountability.

### Acceptance Criteria

1. `source_r1cs_residual_claims` may remain logical, but verifier evaluation
   count is reported separately and is `O(1)` or `O(log k)`.
2. No verifier path evaluates `64 * k` source residual claims one by one.
3. Mutating any source assignment boundary, source layout, R1CS evaluator
   layout, or folded residual boundary still rejects.
4. The residual batching challenge is domain-separated and proof-checking-side;
   mutating folded output must not change folding `beta` unless it is already
   beta-bound input-side data.
5. Benchmark output reports `source_r1cs_residual_claims`,
   `source_r1cs_residual_verifier_evaluations`, and verifier timing attribution
   for the compressed evaluator.
6. Scaling test over `k=1,2,4,8` shows source-residual verifier work is constant
   or logarithmic in `k`.

**Status: implemented.** The source R1CS residual verifier uses a
domain-separated `SYMBT3_SOURCE_R1CS_RESIDUAL_BATCH` batching point for the
source residual column. `source_r1cs_residual_claims` remains logical/audit
metadata, while `source_r1cs_residual_verifier_evaluations` is reported
separately and is `1` for the current nonempty SYMBT3 profiles. This preserves
the K1e.2/K2/K4 proof shape: one top-level WHIR proof, one backend table, zero
family subproofs, no dense manifest/source-view columns, and
`message_to_trace_binding_count = 0`. This does not change the K3 authority
profile status and does not promote SYMBT3 to product routing.

**Files**: `src/snark/whir/mod.rs`, `src/modular/batched_cp.rs`,
`benches/whir_scaling.rs`, `tests/batched_cp.rs`,
`docs/whir_public_performance_north_star_plan.md`

---

## K4.6 — Compressed Public Accumulator Boundary

**Problem.** K4 and K4.5 keep proof shape and verifier residual evaluation
compact, but the public accumulator instance still serialized expanded
per-item data. In particular, expanded input boundary matrices, source
assignment roots, source opening roots, and message oracle root vectors caused
`public_statement_bytes` in the K4 benchmark to grow roughly linearly with
batch size.

**Goal.** The K4/K6 public accumulator boundary should commit to expanded
per-item data by digest, not serialize the expanded lists directly. Expanded
lists may remain available to the current research prover/dev adapter, but they
are not part of the canonical public accumulator instance bytes.

### Design

- `Symbt3AccumulatorInstance` carries first-class compressed boundary digests:
  `batch_items_digest`, `public_source_boundary_digest`,
  `source_assignment_roots_digest`, `source_ajtai_opening_roots_digest`, and
  `message_oracle_roots_digest`.
- `Symbt3AccumulatorInstance::canonical_bytes()` uses those compressed
  commitments instead of serializing expanded `input_*` matrices,
  `source_assignment_roots`, `source_ajtai_opening_roots`, or
  `message_oracle_roots`.
- The current K4 research API still accepts the expanded fields as construction
  and debug adapter data. `matches_profile_and_relation(...)` recomputes the
  compressed digests from those expanded fields and rejects stale or mismatched
  data.
- The internal `BatchedCpSymbt3PublicStatement` remains the research verifier
  adapter used by the existing single-WHIR proof path; product
  `verify_public` is unchanged.

### Acceptance Criteria

1. K4 benchmark `public_statement_bytes` measures compressed accumulator
   canonical bytes and is flat or near-flat across `k`.
2. Mutating any expanded source/message root without updating the corresponding
   digest rejects.
3. Mutating any compressed boundary digest rejects.
4. K4 proof shape remains one top-level WHIR proof, zero family subproofs, one
   backend table, `message_to_trace_binding_count = 0`, and
   `accumulator_transition_claims = 1`.
5. Product `verify_public` remains unchanged.

**Status: implemented as the K4 research-boundary compression bridge.** The
canonical accumulator instance is now `v2` and commits to expanded per-item
boundary data by digest. Expanded lists remain on the struct for the current
research prover/dev conversion path and are consistency-checked before
delegating to the SYMBT3 verifier. This is not K6 product routing and does not
change the product public verifier.

**Files**: `src/modular/batched_cp.rs`, `tests/batched_cp.rs`,
`benches/whir_scaling.rs`, `docs/whir.md`,
`docs/whir_public_performance_north_star_plan.md`

---

## K5 — ZK / Masking (Deferred)

K5 is explicitly out of scope for this implementation run. All APIs through K4
are `NonZkDevelopment` and must carry:

> `// NonZK: may reveal WHIR-queried private coordinates at query positions — not a zkSNARK.`

**Why this matters**: WHIR/BCS verification opens queried oracle values at proof
positions. Without masking, witness-bearing columns (source assignments, Ajtai
openings, R1CS residuals) may leak at those query positions.

Two authority levels for future use:

- `AccumulatorSoundnessAuthority`: sound, non-ZK. Acceptable for a research
  artifact or integrity-only product mode. Not a zkSNARK claim.

- `AccumulatorZkAuthority`: sound + ZK/masked, full CP-SNARK/zkSNARK claim.
  Requires adding random masking polynomials to all witness-bearing oracle
  columns at prove time.

ZK/masking is a future milestone gated on a product decision.

---

## K6a — Opt-In NonZK Integrity Product Route (M2a)

**Status.** Implemented as an explicit NonZK integrity product route, not as
the default product `verify_public()` route.

**Problem.** The K4 route is research-only. Product use needs a separate
opt-in envelope/policy so NonZK integrity proofs cannot be confused with the
default zkSNARK/typed-CP product path.

**Scope in this implementation run**: K6a is NonZK integrity mode only.
Monolithic typed CP `verify_public()` remains unchanged. The SYMBT3 product
route is selected only by the explicit
`ProductProofKind::Symbt3AccumulatorNonZkIntegrity` discriminator and a
`Symbt3ProductPolicy::Symbt3NonZkIntegrityOptIn` profile. Full ProductAuthority
for zkSNARK/CP-SNARK semantics remains blocked until K5.

### Changes

**`src/snark/whir/mod.rs`**

```rust
prove_public_symbt3_accumulator_non_zk_integrity(...)
verify_public_symbt3_accumulator_non_zk_integrity(
    ...,
    proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
    ...
)
```

Hard proof-shape checks in the product route:
- `top_level_whir_proof_count == 1`
- `family_columnar_subproof_count == 0`
- `backend_table_count == 1`
- Version marker is not SYMBT2F / SYMBT2C / SYMBTC / monolithic typed CP

The product route fails closed if the SYMBT3 gate fails; it does not silently
fall back to monolithic typed CP.

**`benches/whir_scaling.rs`**

Add benchmark suites:

**Suite 1: `symbt3_accumulator_vs_k`** — internal SYMBT3 scaling.
Run for k = 1, 2, 4, 8, 16, 32, 64.

**Suite 2: end-to-end product comparison.**
- `public_verify_v2_vs_k` — monolithic typed CP
- `symbt3_research_public_verify_vs_k` — K4 research route
- `symbt3_accumulator_authority_vs_k` — K6 product route

Metrics for both suites:

| Metric | Gate / Expected (SYMBT3) |
|---|---|
| `prove_ms` | — |
| `verify_ms` | ratio <= 1.25 per doubling of k |
| `proof_bytes` | — |
| `public_statement_bytes` | ratio <= 1.25 per doubling of k |
| `oracle_len` | — |
| `whir_num_vars` | — |
| `opened_field_elements` | roughly constant or logarithmic |
| `transcript_squeezes` | — |
| `pcs_openings` | — |
| `top_level_whir_proof_count` | **must be 1** |
| `family_columnar_subproof_count` | **must be 0** |
| `backend_table_count` | **must be 1** |
| `manifest_public_bytes` | ratio <= 1.25 per doubling of k |
| `manifest_logical_coordinates` | — |
| `message_view_coordinates` | — |
| `accumulator_transition_claims` | **must be constant** |

Report speedup vs monolithic typed CP for `verify_ms` and `proof_bytes`.

### K6a Acceptance Criteria

1. Explicit SYMBT3 NonZK integrity product route verifies matching profiles.
2. ZK-requiring profiles are rejected (K5 not done).
3. SYMBT2F / SYMBT2C / SYMBTC proofs rejected by product gate.
4. Monolithic typed CP proofs rejected as SYMBT3 authority.
5. All scaling metrics meet the ratio <= 1.25 gate per doubling of k.
6. `top_level_whir_proof_count = 1`, `family_columnar_subproof_count = 0`,
   `backend_table_count = 1` across all k values.
7. Monolithic typed CP `verify_public()` works unchanged.
8. Speedup reported vs monolithic typed CP for both benchmark suites.

**Files**: `src/snark/whir/mod.rs`, `benches/whir_scaling.rs`, `tests/batched_cp.rs`

---

## K6b — Product Route Comparison Report

**Status.** Implemented as a reporting/regression milestone. Protocol logic and
default product `verify_public()` routing are unchanged.

K6b adds `product_route_comparison_vs_k`, a consolidated benchmark reporter
joining:
- `public_verify_v2_vs_k` — current monolithic typed-CP product route.
- `symbt3_accumulator_authority_vs_k` — explicit opt-in SYMBT3 K6a NonZK
  integrity product route.

The reporter emits stable `PRODUCT_COMPARISON_CSV` rows. Monolithic proof bytes
are `cp_proof_bytes + output_proof_bytes`; monolithic public bytes are the
compressed public envelope with proof payloads omitted. SYMBT3 proof bytes are
the single SYMBT3 WHIR proof bytes; SYMBT3 public bytes are the compressed
`Symbt3AccumulatorInstance` canonical bytes.

Run:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4,8 cargo bench --bench whir_scaling --features whir -- "product_route_comparison_vs_k"
```

### K6b: Product Route Comparison

| k | monolithic verify_ms | SYMBT3 K6a verify_ms | verify speedup | monolithic proof bytes | SYMBT3 proof bytes | proof ratio | monolithic public bytes | SYMBT3 public bytes | notes |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 2,109.052 | 17.656 | 119.45x | 1,206,465 | 311,568 | 0.258 | 15,171 | 18,715 | K6a selected, no fallback |
| 2 | 6,232.810 | 24.180 | 257.77x | 1,256,159 | 335,935 | 0.267 | 15,187 | 18,715 | K6a selected, no fallback |
| 4 | 13,326.962 | 24.348 | 547.36x | 1,556,795 | 329,707 | 0.212 | 15,219 | 18,715 | K6a selected, no fallback |
| 8 | 51,182.449 | 30.702 | 1,667.09x | 1,613,175 | 387,417 | 0.240 | 15,283 | 18,715 | K6a selected, no fallback |

These are one-shot route measurements from the comparison reporter; the
individual route benchmarks remain the repeated Criterion timing sources.
SYMBT3 K6a is NonZK integrity only, explicit opt-in only, not default product
routing, does not implement K5 masking, and does not support private manifest
membership.

### K6b Acceptance Criteria

1. `PRODUCT_COMPARISON_CSV` rows emitted for k = 1, 2, 4, 8.
2. Table reports verify speedup, proof-size ratio, and public-boundary ratio.
3. Existing monolithic product `verify_public()` remains unchanged.
4. SYMBT3 K6a remains explicit opt-in and does not fall back to monolithic typed
   CP on failed K6a gates.
5. The route labels state that K6a is NonZK integrity only and not K5/K6
   default zkSNARK product routing.

**Files**: `benches/whir_scaling.rs`, `tests/batched_cp.rs`, `docs/whir.md`,
`docs/whir_public_performance_north_star_plan.md`,
`docs/symbt3_accumulator_authoritative_roadmap.md`

---

## Full Negative Test Checklist

**Convention:** "prover fails" is an honest-prover sanity check, not a soundness
criterion. For each such item, the authority-relevant test is verifier rejection.
Tests are marked:
- **(verifier)** — verifier must reject even with a malicious/arbitrary prover
- **(prover)** — honest prover detects and fails
- **(verifier/prover)** — both versions required: honest prover fails AND
  verifier rejects with test-only bypass of prover-side assertions

### Manifest / Source (K1)
- [x] **(verifier)** Mutate `batch_manifest_root` → verifier rejects
- [x] **(verifier)** Mutate `manifest_oracle_root` → verifier rejects
- [x] **(verifier)** Wrong `batch_manifest_layout_digest` → verifier rejects
- [x] **(verifier/prover)** Source column coordinate inconsistent with manifest root
- [x] **(invariant)** Manifest root mutation changes `manifest_membership_challenge`
- [ ] **(invariant)** Manifest root mutation changes `beta_challenge`
- [x] **(invariant)** Folded output mutation does NOT change `beta_challenge`
- [x] **(verifier)** Stale proof under changed manifest root → verifier rejects

### Message Oracles (K1 co-requirement)
- [ ] **(verifier)** Wrong message root → verifier rejects
- [ ] **(verifier)** Wrong prefix challenge schedule → verifier rejects
- [ ] **(invariant)** Later message root does not affect earlier prefix challenge
- [ ] **(verifier)** Message view map mutation changes relation/profile digest → verifier rejects
- [ ] **(verifier)** Tampered message coordinate consumed by evaluator → verifier rejects
- [ ] **(audit)** No `message_trace_values` / `message_trace_col` materialized

### Folding Algebra
- [ ] **(verifier)** Tampered `folded_public_input` → verifier rejects
- [ ] **(verifier)** Tampered `folded_commitment` → verifier rejects
- [ ] **(verifier)** Tampered folded GR1CS product triple → verifier rejects
- [ ] **(verifier)** Wrong ring/module product law → verifier rejects
- [ ] **(verifier)** Wrong beta action → verifier rejects

### Ajtai
- [ ] **(verifier)** Wrong Ajtai matrix digest → verifier rejects
- [ ] **(verifier)** Tampered folded opening → verifier rejects
- [ ] **(verifier)** Tampered folded commitment → verifier rejects
- [ ] **(verifier)** Wrong A\*f=c relation → verifier rejects
- [ ] **(verifier)** Wrong norm/range witness → verifier rejects
- [ ] **(verifier)** Out-of-range projected value → verifier rejects

### Norm / Range (K3)
- [ ] **(positive)** In-range positive value → verifies
- [ ] **(positive)** In-range negative value → verifies
- [ ] **(positive)** In-range zero value → verifies
- [ ] **(verifier)** Out-of-range projected value → verifier rejects
- [ ] **(verifier)** Wrong signed representative → verifier rejects
- [ ] **(verifier)** Wrong monomial exponent → verifier rejects
- [ ] **(verifier)** Wrong `t_B` table digest → verifier rejects
- [ ] **(verifier)** Projection seed / layout change → stale proof rejected
- [ ] **(invariant)** Projection/range data does not affect `beta_challenge`
- [ ] **(invariant)** Projection/range data does affect proof-checking challenges

### Accumulator Transition (K2)
- [ ] **(verifier)** Wrong `old_accumulator_digest` → verifier rejects
- [ ] **(verifier)** Wrong `new_accumulator_digest` → verifier rejects
- [ ] **(verifier/prover)** Wrong `folded_accumulator_coordinates`
- [ ] **(verifier)** Wrong `shape_id` in accumulator instance → rejects
- [ ] **(verifier/prover)** Mixed-shape batch → prover fails
- [ ] **(verifier)** Stale accumulator proof under changed manifest → verifier rejects
- [ ] **(verifier)** Wrong accumulator profile digest → verifier rejects

### Authority Profile (K3)
- [ ] **(gate)** Dev range mode in `semantic_profile_version=1` → gate rejects
- [ ] **(gate)** Dev projection mode → gate rejects
- [ ] **(gate)** Identity projection → gate rejects
- [ ] **(gate)** Wrong `t_B` table digest → gate rejects
- [ ] **(gate)** Wrong projection seed → gate rejects
- [ ] **(gate)** Effective soundness bits below target (union bound) → gate rejects
- [ ] **(gate)** Policy digest field zeroed → gate rejects
- [ ] **(gate)** `semantic_profile_version=0` profile → accumulator authority gate rejects

### Proof Shape (K6)
- [ ] **(verifier)** `top_level_whir_proof_count != 1` → product gate rejects
- [ ] **(verifier)** `family_columnar_subproof_count != 0` → product gate rejects
- [ ] **(verifier)** `backend_table_count != 1` → product gate rejects
- [ ] **(verifier)** Appended typed CP R1CS path → product gate rejects
- [ ] **(verifier)** SYMBT2F proof presented as SYMBT3 authority → product gate rejects
- [ ] **(verifier)** SYMBT2C proof presented as SYMBT3 authority → product gate rejects
- [ ] **(verifier)** Monolithic typed CP proof presented as SYMBT3 authority → rejects

---

## End-to-End Authoritative Path

**Prover (7 steps):**
1. Bucket CP accumulator objects by exact same shape.
2. Build compressed batch manifest: `manifest_root`, `manifest_layout_digest`.
3. Commit manifest as native WHIR/BCS multilinear oracle: `manifest_oracle_root`.
   Link to `batch_manifest_root` via the declared root policy.
4. Commit CP messages as native WHIR/BCS oracles: `c_fs,i = root(M_i)`.
5. Derive `beta_challenge` from input-side transcript only: shape/profile IDs,
   `old_acc.x`, manifest root, source roots, message roots, `active_count`.
6. Prove one cumulative SYMBT3 accumulator relation covering all 13 semantic
   families (see mapping table). Manifest membership challenge is a separate
   proof-checking challenge sampled after proof oracle roots are bound.
7. Output one WHIR proof object and the new accumulator instance.

**Verifier:**
- Checks `manifest_oracle_root` against the canonical public manifest root.
- Recomputes `ManifestView(zeta)` from compressed public boundary data.
- Checks virtual `SourceView(zeta)` from the public-boundary layout against that
  verifier-computed view without a source-view backend column.
- Recomputes `manifest_eval_point` from transcript; does not accept it from input.
- Does not trust `manifest_eval_claim` as a public fact.
- Checks `old_accumulator_digest` and `new_accumulator_digest` are transcript-bound.
- Runs one WHIR verification call.

**The verifier does NOT:**
- Read all manifest rows.
- Read all source columns.
- Replay transcript bytes.
- Verify per-table proofs.
- Verify `k` leaf proofs.
- Run `CpFieldRelation::check`.
- Construct appended R1CS rows.
- Reconstruct full manifest from public statement coordinates.

---

## Invariants That Must Not Change

- `message_to_trace_binding_count = 0` — I2 invariant. Message oracle values
  are relation-bound views, not separately committed copies.
- `beta_challenge` is derived from input-side transcript only (shape/profile IDs,
  `old_acc.x`, manifest root, source roots, message roots, `active_count`).
  Never from folded output or proof oracle roots.
- `manifest_membership_challenge` is a proof-checking challenge, not folding
  beta. It may depend on proof oracle roots.
- `top_level_whir_proof_count = 1`, `family_columnar_subproof_count = 0`,
  `backend_table_count = 1` throughout all milestones.
- Do not restore: full manifest in public statement, full manifest in backend
  table, per-coordinate manifest equality rows, byte sections, Poseidon
  digest-body reconstruction, witness-side verifier checks.
- `product_verify_public` interface is unchanged until K6.
- Manifest oracle is part of the top-level SYMBT3 proof object (no new WHIR
  proof or subproof introduced).

---

## Status Labels

| Label | Meaning |
|---|---|
| `SYMBT3-J2/K0` | Compact research proof path. `ResearchAuthorityCandidateV0`. Not accumulator-authoritative. |
| `SYMBT3-K1` | Compressed manifest/source membership. Closes root-only soundness gap. |
| `SYMBT3-K2` | Accumulator transition proof `old_acc → new_acc`. Typed accumulator structs. |
| `SYMBT3-K3` | `AccumulatorSoundnessAuthorityCandidateV1`. Soundness accounting (union bound). Policy digests. |
| `SYMBT3-K4` | Implemented research public accumulator verifier API (M0/M1). NonZK, research-only. |
| `SYMBT3-K4.5/K3b` | Implemented verifier-side evaluator compression for source R1CS residuals. |
| `SYMBT3-K4.6` | Implemented compressed public accumulator boundary canonicalization. |
| `SYMBT3-K5` | ZK/masking. Deferred. Required for full CP-SNARK claim. |
| `SYMBT3-K6a` | Implemented explicit opt-in ProductAuthority NonZK integrity route. Default `verify_public()` unchanged. |
| `SYMBT3-K6b` | Implemented side-by-side product route benchmark/report. No protocol or routing change. |
| `SYMBT3-ACC` | Accumulator transition proof `old_acc → new_acc` (alias for K2 work). |
| `SYMBT3-SoundAuthority` | Non-ZK accumulator integrity proof, K1+K2+K3+K4+K6a opt-in, K6b reported. |
| `SYMBT3-ZkAuthority` | Full ZK/CP-SNARK product-eligible proof. Requires K5+K6. |

---

## Key File Locations

| Item | File | Lines |
|---|---|---|
| Constraint family enum | `src/modular/batched_cp.rs` | 346–380 |
| Manifest component kinds | `src/modular/batched_cp.rs` | 393–401 |
| Authority profile struct | `src/modular/batched_cp.rs` | 530–566 |
| Profile factory functions | `src/modular/batched_cp.rs` | 4327–4453 |
| `has_symbt3_h_families()` gate | `src/modular/batched_cp.rs` | 3862–3880 |
| Manifest rows function | `src/modular/batched_cp.rs` | 8656–8711 |
| Verifier manifest binding (K0/J3 design) | `src/snark/whir/mod.rs` | ~1076–1082 |
| Manifest residual function | `src/snark/whir/mod.rs` | ~1848–1856 |
| Main verify entry point | `src/snark/whir/mod.rs` | ~2750–2756 |
| Proof shape checks | `src/snark/whir/mod.rs` | ~2948–3016 |
| Test suite | `tests/batched_cp.rs` | full file (~3547 lines) |
| Scaling benchmarks | `benches/whir_scaling.rs` | full file |
