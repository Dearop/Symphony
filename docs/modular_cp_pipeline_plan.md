# `docs/modular_cp_pipeline_plan.md` — Modular Plan for Full CP Pipeline, Full Transcript Handling, Full Verification

## Summary

This plan defines a **generic-first crate architecture** for a full commit-and-prove (CP) stack that can plug into Symphony or any other folding system.  
Target outcomes:

1. Full CP pipeline (prove + verify) with constant-size public CP instance.
2. Full transcript handling (canonical encoding, parsing, challenge derivation, commitment binding).
3. Full top-level verification (all public digests enforced, no public O(k) replay).

## Crate Architecture (Independent, Reusable)

Use a Cargo workspace with the following crates.


| Crate                                                       | Responsibility                                                                                                | Public Interfaces                                                                         |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `folding_core`                                              | Folding domain types + fold semantics (no backend assumptions).                                               | `Statement`, `FoldInput`, `FoldedInstance`, `FoldSemantics` trait                         |
| `transcript_core`                                           | Transcript schema, canonical encode/decode, domain separation, challenge derivation hooks.                    | `TranscriptEvent`, `TranscriptCodec`, `ChallengeDeriver` traits                           |
| `digest_core`                                               | Deterministic digests/roots for transcript seed, FS commitments, fold inputs, challenges.                     | `digest_transcript_seed`, `digest_fs_root`, `digest_fold_root`, `digest_challenge_digest` |
| `cp_relation_core`                                          | CP public/witness model + relation checks (transcript consistency + fold replay + folded output consistency). | `CpPublicInstance`, `CpWitnessBundle`, `CpRelation::check`                                |
| `cp_backend_api`                                            | Backend-agnostic CP proving API.                                                                              | `CpBackend` trait (`setup/prove/verify`)                                                  |
| `output_backend_api`                                        | Backend-agnostic folded-statement proving API.                                                                | `OutputBackend` trait (`setup/prove/verify`)                                              |
| `proof_orchestrator`                                        | End-to-end proving/verifying flow combining all crates above.                                                 | `Prover`, `Verifier`, `ProofBundle`                                                       |
| `adapter_symphony`                                          | Mapping between Symphony current structs and generic crate types.                                             | `From/Into` converters + wiring helpers                                                   |
| `cp_backend_whir` / `cp_backend_spartan` (optional)         | CP backend implementations.                                                                                   | `CpBackend` impls                                                                         |
| `output_backend_whir` / `output_backend_spartan` (optional) | Output backend implementations.                                                                               | `OutputBackend` impls                                                                     |


## Full CP Pipeline (Decision-Complete)

### Prover flow

1. Convert external statements into `folding_core::Statement`.
2. Build transcript events via `transcript_core`, commit FS messages, collect openings.
3. Compute `fs_root`, `fold_root`, `challenge_digest`, `transcript_seed_digest` via `digest_core`.
4. Compute folded result via `folding_core::FoldSemantics`.
5. Build `cp_relation_core::CpPublicInstance`:
  `fs_root`, `fold_root`, `challenge_digest`, `transcript_seed_digest`, `x_folded`.
6. Build `CpWitnessBundle`:
  transcript bytes/messages/openings, fold inputs, per-round artifacts needed by relation.
7. Prove CP relation via `cp_backend_api::CpBackend::prove`.
8. Prove folded statement via `output_backend_api::OutputBackend::prove`.
9. Emit `ProofBundle { cp_proof, output_proof, cp_public_instance }`.

### Verifier flow

1. Recompute `transcript_seed_digest` from public inputs and statement metadata.
2. Check recomputed seed digest equals `cp_public_instance.transcript_seed_digest`.
3. Verify CP proof against **full** CP public instance.
4. Verify output proof against `x_folded`.
5. Accept iff both proofs pass and all digest equality checks pass.

## Full Transcript Handling (Decision-Complete)

1. Transcript schema is explicit and versioned (`version`, `domain_tag`, ordered events).
2. Event encoding is canonical and length-delimited; decoding is total (clear parse errors).
3. Domain tags separate phases: folding transcript, CP transcript, output transcript.
4. Challenge derivation depends only on canonical transcript representation plus domain tag.
5. Transcript consistency is enforced inside CP relation:
  parsed transcript + openings must match `fs_root`, derived challenges must match `challenge_digest`.
6. No ad hoc transcript construction in top-level verifier outside deterministic seed digest check.

## Full Verification (Decision-Complete)

1. Top-level verifier never iterates over per-instance O(k) transcript/fold objects.
2. `fs_root`, `fold_root`, `challenge_digest`, and `transcript_seed_digest` are all binding and enforced.
3. CP relation must prove:
  transcript parse validity, FS commitment/opening consistency, challenge consistency, fold replay consistency, and folded-output equality to public `x_folded`.
4. Output relation proves folded statement validity for `x_folded`.
5. Final verifier complexity target:
  O(|public_inputs|) for seed digest + backend verification costs; no explicit public fold replay.

## API/Type Changes

1. Introduce backend-split types in `proof_orchestrator`:
  `ProofBundle<CPB, OB>`, allowing different CP/output backends.
2. Replace backend-specific CP instance building in orchestrator with `CpPublicInstance`.
3. Keep Symphony compatibility through `adapter_symphony`:
  current `SymphonyProof` can be produced/consumed by adapter mapping until full migration.
4. Deprecate direct use of backend-specific CP encoders in top-level verifier path.

## Test Plan

1. Unit tests per crate:
  canonical transcript round-trip, digest stability/binding, fold semantics invariants, CP relation checks.
2. Negative tamper tests:
  flip one bit in each digest; alter transcript bytes; alter fold inputs; alter folded output; all must fail.
3. Backend swap tests:
  CP=WHIR/output=Spartan, CP=Spartan/output=WHIR, and same-backend combinations.
4. Integration tests:
  Symphony adapter round-trip prove/verify parity with current behavior.
5. Regression tests:
  ensure old advisory fields (`fs_root`, `fold_root`, `challenge_digest`) become mandatory checks in new path.

## Assumptions and Defaults

1. Hash default: SHA-256 in `digest_core`; hash abstraction can be added later.
2. Transcript canonical binary format is workspace-owned and stable by version.
3. Migration is staged:
  first extract crates without behavior change, then enforce full digest checks in verifier.
4. Initial target path for this document: `docs/modular_cp_pipeline_plan.md`.

