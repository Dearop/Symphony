# Modular CP Pipeline Modules

This directory groups the reusable, backend-agnostic CP pipeline components used
by the product public verifier and the structured batched-CP development paths.

- `transcript_core`: canonical transcript schema/codec and challenge derivation.
- `digest_core`: SHA-256 compatibility digests plus WHIR public
  `Poseidon2BabyBear` digest/root helpers.
- `folding_core`: folding-domain traits and adapters.
- `cp_relation_core`: `CpPublicStatement`, public/witness model, and
  `CpFieldRelation` checks used as the software typed-CP reference.
- `cp_backend_api`: CP backend trait abstraction and authority gates.
- `output_backend_api`: output backend trait abstraction.
- `proof_orchestrator`: end-to-end split-backend prover/verifier, including
  `prove_public` / `verify_public` over `ProofBundleV2` /
  `PublicProofBundle`.
- `public_proof`: versioned `PublicProofEnvelope` and the compressed-envelope
  roadmap wire shape.
- `batched_cp`: same-shape batched CP foundations plus SYMBTC1/SYMBTC2,
  SYMBT2C/SYMBT2F, and SYMBT3 public/layout/context types. These are
  development or explicit opt-in NonZK routes unless a product route selects
  them explicitly.
- `adapter_symphony`: compatibility mapping with legacy `SymphonyProof`.

Product public verification is authority-gated. Non-authoritative backends fail
closed; WHIR currently advertises authoritative typed CP and typed output and
uses `Poseidon2BabyBear` public digests. Legacy/full verifier paths remain
separate compatibility surfaces.

Modules are re-exported from crate root (`lib.rs`) to preserve stable public
paths.
