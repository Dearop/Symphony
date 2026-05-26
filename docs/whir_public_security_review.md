# WHIR Public Verifier Security Review

## Status

WHIR+WHIR public verification is authoritative and expected to pass through
`verify_public` using public data only. The reviewed product boundary is:

- `ModularProver::prove_public` / `ModularVerifier::verify_public`;
- `SymphonyProver::prove_public` / `SymphonyVerifier::verify_public`;
- `ProofBundleV2` / `PublicProofBundle`;
- `SymphonyProofV2` / `PublicSymphonyProof`;
- `PublicProofEnvelope`;
- canonical WHIR CP and output proof payloads.

The public verifier receives caller-supplied public inputs and R1CS metadata,
public FS commitments, public roots/digests, the public folded output, and the
WHIR CP/output proofs. It must not read FS openings, FS messages, fold inputs,
original witnesses, folding proof internals, folded witnesses, CP witness
bundles, or other witness-side debug data.

`prove_v2` / `verify_v2` are compatibility names for the same public-only
route. Other compatibility/debug surfaces outside the product review boundary
are legacy `prove` / `verify`, raw typed CP context serializers, explicit
soundness helpers, audit/profile helpers, backend payload codecs, compressed
public-envelope v2 helpers, SYMBT3 research/non-ZK opt-in routes,
native-oracle N6/N7 wrappers, the explicit N8 accumulation API, and non-WHIR
backends unless separately reviewed. The default product `verify_public` route
remains the monolithic authoritative WHIR typed-CP route; the N8
`N8NonZkSameShapeV1` accumulation decider is a separate explicit NonZK
same-shape route with its boundary documented in
`docs/protocols/n8_accumulation_relation.md`.

## Soundness Claim Matrix

| Claim | Public proof fields | Code path | Audit block | Digest/body binding | Tests |
|---|---|---|---|---|---|
| Public inputs and R1CS metadata are bound | out-of-band public inputs, R1CS metadata, `transcript_seed_digest` | `ProofBundleV2::public_boundary_is_well_formed_with_scheme`, `Verifier::verify_public`, `CpPublicStatement::new` | `PublicInputBinding`, `ByteConstraints` | `transcript_seed` body over public inputs, constraint count, variable count, public arity | `modular_transcript_seed_digest_tampering_rejected`, `public_verify_whir_whir_succeeds_and_rejects_tampering`, `typed_cp_digest_r1cs_rejects_wrong_public_digests_and_replay` |
| `fs_commitments` bind to `fs_root` | `fs_commitments`, `fs_root` | `digest_fs_root_with_scheme`, public-boundary check, `CpPublicStatement::with_fs_commitments` | `PoseidonDigestGadgets`, `ByteConstraints` | `fs-root` body from public FS commitment limbs and canonical count/length framing | `public_verify_whir_whir_succeeds_and_rejects_tampering`, `typed_cp_digest_r1cs_rejects_tampered_root_and_challenge_bodies`, `digest_fs_commitments_differs_on_change` |
| FS openings and messages are enforced inside typed CP | `fs_commitments`, CP proof | `WhirSnark::prove_typed_cp`, `WhirSnark::verify_typed_cp`, `CpFieldRelation::check` sanity path | `PoseidonDigestGadgets`, `ByteConstraints`, `Gr1csMessageReconstruction` | `fs-commit = Poseidon2BabyBear("fs-commit" || len(message) || message || opening)` | `typed_cp_field_relation_rejects_bad_fs_opening`, `typed_cp_field_relation_rejects_bad_fs_message`, `typed_cp_digest_r1cs_rejects_bad_private_digest_inputs` |
| GR1CS message serialization is exact-byte bound | CP proof, `fs_commitments`, `fold_root` | typed CP digest witness encoding and R1CS body reconstruction | `Gr1csMessageReconstruction`, `ByteConstraints`, `RangeMonomialSemantics` | `encode_gr1cs_round_message` bytes used in FS commitments and fold-root bodies | `typed_cp_digest_r1cs_binds_hadamard_message_bytes_to_cp_columns`, `typed_cp_digest_r1cs_binds_range_message_shape_prefixes`, `typed_cp_digest_r1cs_rejects_tampered_structured_body_bindings` |
| `fold_root` binds commitments, public inputs, and GR1CS messages | `fold_root`, folded output, CP proof | `digest_fold_root_with_scheme`, typed CP structured body reconstruction | `CpFoldingCore`, `ByteConstraints`, `Gr1csMessageReconstruction`, `PublicInputBinding` | `fold-root` body from original commitments, public inputs, and structured GR1CS message bytes | `modular_fold_root_tampering_rejected`, `typed_cp_field_relation_rejects_bad_fold_and_challenge_digests`, `public_verify_whir_whir_succeeds_and_rejects_tampering` |
| Poseidon challenge outputs bind to `challenge_digest` | `challenge_digest`, `fs_commitments`, public inputs, R1CS metadata | `derive_challenges_with_scheme`, typed CP challenge blocks | `PoseidonDigestGadgets`, `ByteConstraints`, `PublicInputBinding` | per-round `challenge` body and `challenge-digest` body from challenge output bytes | `modular_challenge_digest_tampering_rejected`, `typed_cp_digest_r1cs_rejects_tampered_root_and_challenge_bodies`, `typed_cp_field_relation_rejects_bad_fold_and_challenge_digests` |
| Poseidon challenge bytes bind to CP `beta` | `challenge_digest`, CP proof | `poseidon_challenge_to_beta`, typed CP beta-binding rows | `ChallengeToBetaBinding` | 32 challenge bytes decompose as `byte = d0 + 5*d1 + 25*q`; beta coefficients are `d0 - 2`, `d1 - 2` | `poseidon_challenge_to_beta_uses_base5_byte_mapping`, `typed_cp_digest_r1cs_binds_poseidon_challenge_to_beta`, `typed_cp_audit_report_isolates_targeted_mutation_blocks` |
| Folded output derives from beta-bound fold inputs | folded output, `fold_root`, `challenge_digest`, CP proof | CP folding core, folded-output derivation rows, statement boundary equality | `CpFoldingCore`, `FoldedOutputDerivation`, `PublicInputBinding` | fold-root inputs and beta-bound GR1CS evaluations feed public folded evaluation tensors | `typed_cp_digest_r1cs_derives_folded_evaluation_values`, `typed_cp_field_relation_rejects_folded_output_and_original_witness_tampering`, `public_verify_whir_whir_succeeds_and_rejects_tampering` |
| Original Ajtai openings are valid | CP proof, public FS/fold digests | typed CP original opening rows | `AjtaiOpeningChecks`, `RangeMonomialSemantics` | original commitments and range-proof monomial commitments open under verifier-reconstructable Ajtai parameters | `original_statement_r1cs_accepts_valid_ajtai_and_r1cs_witness`, `typed_cp_audit_report_isolates_targeted_mutation_blocks`, `typed_cp_field_relation_rejects_folded_output_and_original_witness_tampering` |
| Original R1CS witnesses satisfy the relation | CP proof, public R1CS metadata | typed CP original R1CS validity rows | `OriginalR1csValidity`, `PublicInputBinding` | public inputs and private witness parts assemble the original assignments checked against source R1CS | `original_statement_r1cs_rejects_tampered_assignment`, `typed_cp_field_relation_rejects_invalid_original_r1cs_assignment`, `typed_cp_audit_software_checker_matches_r1cs_mutation_corpus` |
| WHIR output proof transcript-binds `FoldedOutputInstance` | folded output, output proof | `WhirSnark::verify_typed_output`, `validate_typed_output_public_instance`, `typed_output_binding_instance` | output proof, not typed CP audit rows | encoded folded-output bytes bind the public output relation | `typed_output_roundtrip_direct`, `typed_output_rejects_malformed_relation`, `typed_output_rejects_spliced_transcript_instance`, `public_verify_whir_whir_succeeds_and_rejects_tampering` |
| Public proof envelope rejects malformed serialization | all envelope fields | `PublicProofEnvelope::from_bytes`, `canonical_public_envelope_bytes`, `whir_proof_from_canonical_bytes` | envelope/payload codec, not typed CP audit rows | versioned `SYMPUB2\0` envelope and `SYMWHPF\0` WHIR payload framing | `public_proof_envelope_rejects_unknown_version`, `public_proof_envelope_rejects_unknown_digest_scheme`, `public_proof_envelope_rejects_truncation_and_trailing_bytes`, `canonical_whir_proof_payload_is_deterministic_and_binding` |
| Proof splicing, replay, and tampering reject | all `ProofBundleV2` fields | `Verifier::verify_public`, `WhirSnark::verify_typed_cp`, `WhirSnark::verify_typed_output` | all typed CP audit blocks plus output proof binding | public inputs, digests, folded output, CP proof, and output proof are cross-bound | `public_verify_whir_whir_succeeds_and_rejects_tampering`, `modular_proof_splicing_cp_from_different_statement_rejected`, `modular_replay_with_wrong_public_inputs_rejected` |
| Non-authoritative backends fail closed | backend authority flags | `has_authoritative_typed_cp`, `has_authoritative_typed_output`, `verify_public` route gates | route gate, not typed CP audit rows | no digest fallback; helper hooks are ignored without authority | `verify_public_fails_closed_when_only_output_is_authoritative`, `non_authoritative_typed_cp_hook_is_not_selected`, `verify_public_uses_typed_authority_not_legacy_backend_verify` |

Every `TypedCpAuditBlockKind` is represented above: `CpFoldingCore`,
`ByteConstraints`, `PoseidonDigestGadgets`, `Gr1csMessageReconstruction`,
`RangeMonomialSemantics`, `ChallengeToBetaBinding`,
`FoldedOutputDerivation`, `AjtaiOpeningChecks`,
`OriginalR1csValidity`, and `PublicInputBinding`.

## Assumptions

- Poseidon2/BabyBear constants for WHIR infrastructure are derived
  deterministically from the full 32-byte relation seed using `ChaCha20Rng`.
- Poseidon2/BabyBear public digests serialize as eight canonical BabyBear limbs,
  each little-endian `u32`, for exactly 32 bytes.
- Typed CP digest bodies preserve the documented `digest_core` framing: domain
  frame, body length, 3-byte BabyBear packing, and final length sentinel.
- Challenge-to-beta mapping is fixed: each 32-byte challenge output yields 64
  coefficients in `{-2,-1,0,1,2}` using the base-5 byte decomposition.
- Main Ajtai parameters come from verifier setup; typed CP range subrelations
  use deterministic verifier-reconstructable Ajtai parameters documented in the
  typed CP arithmetization.
- WHIR uses a 100-bit security target and `UniqueDecoding` soundness settings.
- The authoritative typed CP relation is fixed to setup-derived public/witness
  lengths and `params.ell_np`; proofs for different fold counts or malformed
  layouts must reject.

## Threat Model

- Malicious provers may choose witnesses, FS openings/messages, folding proof
  internals, and backend proof bytes.
- Public verifiers may receive malformed public envelope bytes, truncated WHIR
  payloads, unknown versions, unknown digest schemes, or trailing bytes.
- Attackers may replay a proof under different public inputs or R1CS metadata.
- Attackers may splice `fs_commitments`, digest tuples, folded outputs, CP
  proofs, or output proofs across otherwise valid public proofs.
- Attackers may try digest-collision, transcript-confusion, or challenge/beta
  mismatch attacks against the Poseidon2/BabyBear public digest path.
- Attackers may try downgrade or route-confusion attacks that rely on legacy
  SHA/full-verifier paths, non-authoritative typed hooks, or witness-side
  explicit soundness checks.
- Relation metadata is verifier-supplied. Chosen-relation behavior is in scope
  only to the extent that setup, context hashing, public R1CS metadata binding,
  and relation-specific typed CP setup prevent cross-relation proof reuse.

SHA-256 is compatibility-only for non-WHIR and legacy/full verifier paths. WHIR
does not prove SHA-256 inside typed CP, and WHIR public verification must not
fall back to SHA-256.

## Known Limits

- Performance remains the main engineering limit. Milestone E reduced public
  verification cost, but typed CP verification is still the dominant component.
- Current benchmarks default to `k = 1`. Broader curves require explicitly
  setting `SYMPHONY_WHIR_PUBLIC_VERIFY_KS`.
- The reviewed authoritative path is WHIR+WHIR public verification. Spartan,
  Sumcheck, Dummy, legacy full/private verification, and ignored long-running
  soundness tests are compatibility or test surfaces unless separately reviewed.
- Explicit SYMBT3/K6a/N6b/N7b/N8 NonZK routes are not the default
  `verify_public` route. N8 has an opt-in authoritative decider only for
  same-shape, nonempty NonZK accumulation transitions selected by
  `N8NonZkSameShapeV1`; it is not ZK, not privacy-preserving, and not covered
  by this default public-verifier claim matrix.
- The current typed CP relation supports setup-derived fixed shapes. Broader
  shape support must add malformed-input, replay, and splicing tests before it
  is considered reviewed.
- This package is an internal review guide, not an external cryptographic
  audit. External review should independently assess WHIR assumptions,
  Poseidon2/BabyBear parameter generation, Ajtai assumptions, and the typed CP
  arithmetization.

## Review Notes

### Confirmed Issues

None identified during Milestone G on the active WHIR public verifier soundness
path.

### Accepted Risks

- Public verification remains expensive because the authoritative typed CP
  relation is large.
- External cryptographic review is still required before calling the system
  production audited.
- Non-WHIR and legacy/full verifier paths are compatibility surfaces, not the
  reviewed product public verifier boundary.

### Future Work

- Complete Milestone H release-gate verification from a clean checkout.
- Record external review findings against this claim matrix.
- Add broader benchmark curves once performance work makes larger `k` points
  practical on developer machines.

## Verification Commands

Milestone G review packaging should pass:

```text
cargo test --features whir verify_public
cargo test --features whir typed_cp_digest
cargo test --features whir typed_cp
cargo test --features whir poseidon
cargo test --features whir
cargo test
git diff --check
```

Before claiming production grade, also run the release gate documented in
`docs/past_roadmaps/whir_typed_cp_authority_plan.md`.
