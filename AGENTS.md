# AGENTS

This file is the operating guide for LLM agents working in this repository.
Read it before making implementation decisions.

## Ground Truth

Use these documents as the authoritative references for WHIR public verifier work:

- `docs/whir_typed_cp_authority_plan.md` - canonical implementation plan, milestone status, and production-grade roadmap.
- `docs/whir_public_performance_north_star_plan.md` - performance roadmap for moving from authoritative but linear WHIR public verification to a compressed/sublinear public verifier.
- `docs/whir_public_security_review.md` - security review package mapping WHIR public verifier claims to code, tests, row blocks, fields, and assumptions.
- `docs/public_proof_v2.md` - canonical public verifier boundary and proof shape.
- `docs/whir.md` - WHIR backend architecture and current implementation status.
- `docs/symphony_crate_spec.md` - broader crate architecture and security notes.

If documents conflict, prefer them in the order above for WHIR typed CP authority
work. Update the relevant docs whenever implementation reality changes.

## Current State

The current intended state is:

- WHIR typed CP is product-authoritative for public verification.
- WHIR public proofs use `Poseidon2BabyBear` public digests.
- `WhirSnark::has_authoritative_typed_cp()` is true.
- `verify_public` / `verify_v2` succeeds for WHIR+WHIR using public data only.
- `public_verify_v2_vs_k` exists and measures public-only verification.
- `public_verify_v2_vs_k` defaults to the conservative `k=1` point; use
  `SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,...` to benchmark a broader curve.
- The WHIR output proof at the public boundary is a transcript-binding proof
  over `FoldedOutputInstance`; typed CP owns semantic folded-output derivation.

Milestones 1-6 in `docs/whir_typed_cp_authority_plan.md` are implemented.
The remaining north star is the production-grade roadmap in that same file:

- Production Milestone A: freeze and version the public proof spec.
- Production Milestone B: complete the public verifier negative matrix.
- Production Milestone C: add the typed CP arithmetization audit harness.
- Production Milestone D: establish performance baselines and constraint
  profiling.
- Production Milestone E: reduce typed CP/public verification cost without
  weakening the security boundary.
- Production Milestone F: clean up legacy routing and compatibility boundaries
  (implemented).
- Production Milestone G: prepare the security review package (implemented).
- Production Milestone H: pass the release gate.

The next work should move through those milestones in order unless the user
explicitly redirects.

## Non-Negotiable Rules

- Do not flip authority flags as a shortcut.
- Do not make public verification call witness-side checks.
- Do not prove SHA-256 inside WHIR; SHA remains compatibility-only.
- Preserve exact Poseidon2/BabyBear digest semantics and byte layouts.
- Treat prover-side `CpFieldRelation::check` as a sanity check only; it is not soundness.
- Keep legacy SHA/full-verifier compatibility paths working unless explicitly asked to remove them.
- Add negative tests before changing any security boundary.
- If public verification would require FS openings, FS messages, fold inputs, original witnesses, folded witnesses, folding proof internals, or CP witness bundles, it is not the public verifier path.
- Do not optimize away constraints unless an audit or equivalence test preserves
  the same public verifier claims.
- Do not broaden supported public proof shapes without explicit malformed-input,
  replay, and splicing tests.

## Next Implementation Target

The next target is production hardening of the authoritative WHIR public
verifier path. Follow the production milestones in
`docs/whir_typed_cp_authority_plan.md`.

Required implementation behavior:

- Start with Production Milestone H unless the user names a different
  milestone.
- Keep `ProofBundleV2` / `PublicProofBundle` public-only: public inputs
  out-of-band plus public FS commitments, digests/roots, folded output instance,
  CP proof, and output proof, with no private CP witness data.
- Keep `verify_public` verifying typed CP from `CpPublicStatement` plus public
  FS commitments and backend proof only.
- Keep full/private verification compatible with legacy SHA paths.
- Keep the default `public_verify_v2_vs_k` point cheap enough to run, and use
  `SYMPHONY_WHIR_PUBLIC_VERIFY_KS` for explicitly requested broader curves.
- Add more public verifier negative tests before broadening supported shapes.
- Keep the public proof spec, docs, tests, and benchmark output synchronized.

## Production Milestone Discipline

When implementing the production roadmap:

- Treat each production milestone as independently reviewable.
- Add acceptance tests in the same change that implements a milestone.
- For Milestone A, do not change proof semantics without versioning the public
  proof spec.
- For Milestone B, prefer table-driven tampering tests covering every
  verifier-visible field.
- For Milestone C, make row-block accounting explainable and snapshot it for the
  small public verifier fixture.
- For Milestone D, record relation/proof size metadata with benchmark numbers.
- For Milestone E, record before/after row counts and benchmark numbers for
  every optimization.
- For Milestone F, keep product APIs and compatibility/debug APIs clearly
  separated.
- For Milestone G, map each public soundness claim to code, tests, row blocks,
  public proof fields, and docs.
- For Milestone H, run the complete release verification command set before
  claiming production grade.

## Expected Agent Behavior

- Read the ground-truth docs and relevant code before planning or editing.
- Prefer small, verifiable changes over broad rewrites.
- Preserve existing API compatibility unless the task explicitly changes it.
- Keep changes scoped to the current security boundary.
- Document security-sensitive decisions in `docs/whir_typed_cp_authority_plan.md`, `docs/public_proof_v2.md`, or `docs/whir.md`.
- Use precise status language: distinguish "implemented", "directly verified", "non-authoritative", and "authoritative".
- When reporting status, explicitly say whether `verify_public` is expected to pass or fail closed.
- When adding benchmarks, state whether they measure public verification, full/private verification, folding only, proving, or witness-side checks.
- When changing the public proof format, state the versioning impact and whether
  existing fixtures should remain stable.
- When changing typed CP arithmetization, state which `CpFieldRelation` checks
  are affected and which row blocks enforce them.

## Verification Expectations

Before claiming any WHIR typed CP/public verifier change is complete, run:

```text
cargo test --features whir typed_cp_digest
cargo test --features whir typed_cp
cargo test --features whir poseidon
cargo test --features whir verify_public
cargo test --features whir
cargo test
git diff --check
```

Before claiming public WHIR verification is production-ready, also run:

```text
cargo bench --bench whir_scaling --features whir --no-run
cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
```

If a command cannot be run, report that explicitly.

Before claiming the full public verifier path is production grade, run the
release gate from `docs/whir_typed_cp_authority_plan.md`:

```text
cargo test
cargo test --features whir
cargo test --features whir typed_cp_digest
cargo test --features whir typed_cp
cargo test --features whir poseidon
cargo test --features whir verify_public
cargo bench --bench whir_scaling --features whir --no-run
cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
git diff --check
```

## Code Review Checklist

For WHIR public verifier or typed CP changes, check:

- Does public verification rely only on `CpPublicStatement`, public FS commitments, folded output, and backend proofs?
- Are public inputs, R1CS metadata, FS commitments, roots/digests, and folded output bound in the proof?
- Are private bytes constrained to exact canonical serialization?
- Are Poseidon digest outputs tied to the same bodies used by public digests?
- Is beta derived from the same challenge path that feeds `challenge_digest`?
- Is folded output derived from the same beta-bound fold inputs?
- Do tampering, splicing, replay, and legacy-SHA rejection tests fail as expected?
- Are authority flags still false unless all public verifier checks above are enforced by backend proofs?
- If authority flags are true, does `verify_public` succeed without witness-side data and reject every tampered public field/proof?
- Is the public proof spec versioned and canonical if serialization changed?
- Are row-block counts and `CpFieldRelation` coverage updated if typed CP
  arithmetization changed?
- Are benchmark claims clear about whether proof construction is inside or
  outside the measured loop?
