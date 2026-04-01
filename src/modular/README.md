# Modular CP Pipeline Modules

This directory groups the reusable, backend-agnostic CP pipeline components:

- `transcript_core`: canonical transcript schema/codec and challenge derivation
- `digest_core`: digest/root helpers for transcript and fold bindings
- `folding_core`: folding-domain traits and adapters
- `cp_relation_core`: CP public/witness model and relation checks
- `cp_backend_api`: CP backend trait abstraction
- `output_backend_api`: output backend trait abstraction
- `proof_orchestrator`: end-to-end split-backend prover/verifier
- `adapter_symphony`: compatibility mapping with legacy `SymphonyProof`

They are re-exported from crate root (`lib.rs`) to preserve stable public paths.
