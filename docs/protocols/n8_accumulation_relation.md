# SYMBT3 N8 Accumulation Relation

## Status

`SYMBT3-N8` accumulation is an explicit opt-in NonZK same-shape accumulation
decision route for nonempty accumulator transitions. It is selected by
`Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1` and the ACC.D entry
point `decide_symbt3_n8_accumulator_non_zk(...)`.

It is not the default product `verify_public` route, not ZK, and not
production-reviewed. The default public verifier remains the typed-CP WHIR
public route.

Within this opt-in ACC.D boundary, acceptance means the verifier accepted the
N8 public transition checks, the N8 authority-candidate gate, and one integrated
WHIR backend proof over the descriptor-bound semantic batches. It does not make
N8 a production-grade or privacy-preserving route.

## Versioned Boundary

| Object | Canonical version |
| --- | --- |
| Authority profile | `SYMBT3_ACCUMULATION_AUTHORITY_PROFILE_VERSION = 1` |
| Accumulator public instance | `SYMBT3_ACCUMULATOR_PUBLIC_INSTANCE_VERSION = 1` |
| Accumulation batch | `SYMBT3_ACCUMULATION_BATCH_VERSION = 1` |
| Accumulator object | `SYMBT3_ACCUMULATOR_OBJECT_VERSION = 1` |
| Accumulation proof | `SYMBT3_N8_ACCUMULATION_PROOF_VERSION = 1` |
| Integrated relation descriptor | `SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_VERSION = 1` |
| Integrated prover output | `N8_INTEGRATED_WHIR_PROVER_OUTPUT_VERSION = 1` |
| Integrated proof plan | `N8_INTEGRATED_WHIR_PROOF_PLAN_VERSION = 1` |
| Integrated query schedule | `N8_INTEGRATED_WHIR_QUERY_SCHEDULE_VERSION = 1` |

All public boundary objects expose deterministic canonical bytes. Version
mismatches fail closed before backend verification.

## Public Inputs

ACC.V/ACC.D consume only:

- `Symbt3AccumulationBatch`, containing the K6a `Symbt3AuthorityProfile` and
  a `BatchedCpSymbt3PublicStatement`;
- old and new `Symbt3AccumulatorPublicInstance` values;
- `Symbt3AccumulationProof`;
- the WHIR verifying key relation context.

The public batch binds the profile, shape id, batch capacity, active count,
old/new accumulator coordinate digests, public boundary digests, manifest roots,
source roots, message roots, folded-output values, folded Ajtai boundary,
layout digests, folded-output accumulator root, and WHIR parameter digest.

## Witness

ACC.P additionally consumes `Symbt3AccumulatorWitness`. The witness is used only
by the prover path `accumulate_symbt3_n8_non_zk(...)` to build the direct N8 K6a
semantic source, tuple-RLC material, integrated descriptor, and one real WHIR
proof. The witness is not part of `Symbt3AccumulationProof`,
`Symbt3AccumulatorPublicInstance`, or ACC.V/ACC.D.

## Semantic Checks

The authoritative decision requires:

- same profile digest and shape id on the old/new public accumulator boundary;
- nonempty batch capacity and active count;
- public statement/relation consistency through
  `Symbt3AccumulatorInstance::matches_profile_and_relation`;
- old/new accumulator transition consistency;
- proof top-level digests matching the recomputed public statement and
  accumulator instance digests;
- N8 descriptor workload `FullK6aAccumulatorV1`;
- complete K6a semantic rows, tuple-RLC semantic rows, and transition/binding
  semantic rows;
- one real integrated WHIR proof, one root, one query schedule, no tuple PCS
  proof, no split delegation, and no synthetic backend-plumbing mode;
- backend verification through
  `verify_symbt3_integrated_whir_backend_from_verifier_input(...)`.

The integrated backend verifier recomputes the expected real-mode query
schedule from the evaluator rows, checks descriptor/plan/table digest
consistency, rejects extra roots/proofs or legacy delegated proof material, and
uses `whir_verify_opening_multi(...)` over the integrated proof's semantic batch
claims.

## Digest Bindings

The proof binds:

- `public_statement_digest`;
- `accumulator_instance_digest`;
- old/new accumulator digests;
- batch size and active count;
- K6a relation id and WHIR parameter digest;
- tuple leaf root, layout digest, and descriptor digest;
- native oracle descriptor digest and native message roots digest;
- N8 transcript-binding digest;
- N8 claim-plan digest;
- N8 committed-table layout and table digests;
- semantic completion flags;
- N8 semantic batching descriptor and K6a source-row batching descriptor;
- integrated descriptor canonical bytes and integrated prover output canonical
  bytes.

The accumulator public instance digest is role-neutral over `state`
coordinates. The transition relation still binds role-specific `old` and `new`
coordinate digests.

## Code Paths

- ACC.P: `accumulate_symbt3_n8_non_zk(...)`;
- ACC.V: `verify_symbt3_n8_accumulation_non_zk(...)`;
- ACC.D: `decide_symbt3_n8_accumulator_non_zk(...)`;
- public context: `symbt3_n8_accumulation_public_context_from_relation(...)`;
- binding gate: `symbt3_n8_accumulation_binding_blocker(...)`;
- integrated authority gate:
  `verify_symbt3_n8_integrated_prover_output_authority_gate(...)`;
- backend verifier:
  `verify_symbt3_integrated_whir_backend_from_verifier_input(...)`.

Synthetic N8 backend-plumbing output still exists as
`SyntheticNonAuthoritativeV1` for tests, but the N8 authority gate rejects it.

## Tests

The `symbt3_n8` test family covers:

- honest `k = 1, 2, 4`;
- `acc0 -> acc1 -> acc2` replay and swap rejection;
- table-driven mutation rejection for accumulator public instances, all public
  batch/public-statement fields, and all top-level accumulation proof fields;
- wrong version rejection for descriptor, prover output, proof plan/query
  schedule, and proof boundary versions;
- empty batch rejection;
- malformed accumulator rejection;
- witness/batch mismatch rejection;
- proof replay across batches;
- N7b proof-as-N8 rejection;
- split delegation rejection;
- N7 smoke/fallback proof rejection;
- K6a-only product proof rejection;
- synthetic N8 output rejection;
- default `verify_public` routing unchanged;
- wrong digest and semantic-completion flag rejection;
- descriptor, proof-plan, semantic-batching, source-row-batching, query
  schedule, and backend proof/root mutation rejection.

Use `scripts/release_gate_n8_accumulation.sh` before claiming the N8
accumulation route is ready for review.
