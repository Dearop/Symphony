# WHIR Typed CP Authority Plan

## Current State

WHIR typed CP is authoritative for the public verifier boundary. WHIR public
proofs use `Poseidon2BabyBear` public digests, and
`WhirSnark::has_authoritative_typed_cp()` is true. Public verification now
succeeds for WHIR+WHIR without witness-side data.

The WHIR output proof at the public boundary is a WHIR transcript-binding proof
over the public folded-output bytes. The semantic folded-output derivation is
owned by the authoritative typed CP proof, which binds public inputs, FS
commitments, fold roots, challenge digests, beta values, original Ajtai/R1CS
validity, and the folded-output instance.

The typed CP arithmetization currently includes:

- Poseidon2/BabyBear private-input digest gadgets.
- Exact-byte digest body packing matching `digest_core`.
- Structured digest body reconstruction for FS commitments, `fs_root`, `fold_root`, `challenge_digest`, and `transcript_seed_digest`.
- In-circuit canonical length-prefix, transcript-metadata, and static transcript-frame checks for those digest bodies.
- Hadamard-message prefix binding from `encode_gr1cs_round_message` to existing CP-R1CS Hadamard columns.
- Parsed fixed-shape range-proof section prefix checks for GR1CS messages with private proof data.
- Structured private payload columns for range-proof monomial commitments,
  monomial vectors, monomial sumcheck evaluations, monomial evaluation tensors,
  square evaluations, and `projected_values`, with serialized bytes constrained
  to those columns.
- Semantic constraints for the structured monomial vectors: every coefficient
  has boolean square, every ring element has at most one nonzero coefficient,
  and `projected_values` reconstruct from the monomial decomposition digits
  using `d_prime = D - 2`.
- Deterministic verifier-reconstructable Ajtai parameters for range-proof
  monomial commitments, plus in-circuit opening constraints binding each
  structured monomial commitment to its structured monomial vector.
- `CpSharedChallengeData` now carries the monomial sumcheck seed and monomial
  sumcheck challenges alongside the Hadamard challenge material.
- The typed CP R1CS now encodes those monomial challenge variables and
  constrains the monomial sumcheck verifier equations, including degree-4 round
  consistency, final evaluation consistency, coefficient cubic checks, and
  square-evaluation boolean consistency.
- Monomial evaluation claims are now bound to the structured monomial-vector
  multilinear extensions at the monomial sumcheck output point, and
  square-evaluation claims are bound to the structured monomial-vector square
  tables at that same point.
- Each per-round `Poseidon2BabyBear("challenge", ...)` output is now bound to
  the CP-R1CS `beta` columns with a fixed base-5 byte mapping. Every 32-byte
  challenge output yields the 64 beta coefficients by splitting each byte into
  two base-5 digits: `byte = d0 + 5*d1 + 25*q`, with `d0,d1 in 0..=4`, then
  mapping digits to coefficients `d0 - 2` and `d1 - 2`.
- Public input binding through `CpPublicStatement`.
- CP-core commitment/public-input folding constraints.
- Original Ajtai opening validity.
- Original R1CS witness validity.

The remaining engineering work is performance and coverage hardening, not a
fail-closed authority blocker.

## Milestone 1 - GR1CS Message Semantic Reconstruction

Replace byte-only GR1CS message binding with structured reconstruction from typed CP witness variables.

Implementation requirements:

- Reconstruct the Hadamard section of `encode_gr1cs_round_message` from existing CP-R1CS Hadamard columns. The sumcheck-round count, per-round evaluation count, sumcheck evaluations, and Hadamard evaluation matrix prefix are now bound in-circuit.
- Add structured private columns for range-proof serialization sections that are not yet represented in `CpR1csLayout`.
- Bind every serialized GR1CS message byte used by FS commitments and fold-root bodies to those structured variables.
- Preserve exact current byte semantics of `encode_gr1cs_round_message`.
- Continue byte-range constraining all serialized bytes.

Milestone 1 status: implemented for the current fixed-shape typed CP range
payload. Milestone 2 adds challenge-to-beta binding; the next security
milestone is folded-output derivation.

Acceptance tests:

- Honest typed CP digest/R1CS witness satisfies.
- Tampered Hadamard message bytes reject.
- Tampered range-proof serialization bytes reject.
- FS message bytes cannot diverge from fold-root GR1CS message bytes.
- Existing `typed_cp`, `typed_cp_digest`, and `poseidon` tests remain green.

## Milestone 2 - Challenge-to-Beta Binding

Constrain Poseidon-derived challenge outputs to the CP-R1CS `beta` columns.

Implementation requirements:

- Define the exact conversion from each per-round `Poseidon2BabyBear("challenge", ...)` output to the corresponding folding `RingElement beta`.
- Add constraints tying challenge output limbs to `cp_layout.beta(ell, coeff)` variables.
- Ensure the derived beta sequence has exactly `params.ell_np` entries.
- Reject proofs with mismatched fold count or malformed challenge bodies.
- Keep `challenge_digest` bound to the same per-round challenge outputs.

Acceptance tests:

- Honest beta binding satisfies.
- Tampering any beta coefficient rejects.
- Tampering a challenge output limb rejects.
- Tampering `challenge_digest` rejects.
- Replaying public inputs across different statements rejects.

Milestone 2 status: implemented. Challenge-to-beta binding is part of the
authoritative typed CP R1CS.

## Milestone 3 - Folded Output Derivation

Prove that the public folded output was derived from the original folded inputs using the bound beta values.

Implementation requirements:

- Bind fold-root commitment bytes to CP-core commitment columns.
- Bind fold-root public input bytes to `CpPublicStatement.public_inputs`.
- Bind fold-root GR1CS message bytes to reconstructed GR1CS messages.
- Enforce that the folded commitment equals the beta-weighted sum of original commitments.
- Enforce that the folded public input equals the beta-weighted sum of original public inputs.
- Enforce that folded evaluation values match the beta-weighted GR1CS evaluations.
- Bind the resulting folded instance to `CpPublicStatement.instance.x_folded`.
- Bind typed folded-output consistency to the output proof boundary.

Acceptance tests:

- Honest folded output derivation satisfies.
- Tampered folded commitment rejects.
- Tampered folded public input rejects.
- Tampered folded evaluation values reject.
- Splicing folded output from another proof rejects.
- Proof replay across different public inputs rejects.

Milestone 3 status: implemented. Fold-root commitment bytes, public-input bytes, and GR1CS message
bytes are already bound to structured variables; CP-core rows enforce
beta-weighted folded commitments and public inputs using the beta values bound
in Milestone 2; and the typed CP digest layer now exposes folded evaluation
tensor coordinates publicly and enforces that they equal the beta-weighted
GR1CS evaluation matrices. Typed folded-output consistency is checked at the
typed statement boundary by requiring `folded_output.folded_instance ==
x_folded`.

## Milestone 4 - Compose Full Typed CP R1CS Into WHIR

Replace the partial typed CP relation used by WHIR with the full authoritative typed CP R1CS.

Implementation requirements:

- Add a full typed CP R1CS builder that composes:
  - CP-R1CS folding core.
  - Original Ajtai opening checks.
  - Original R1CS validity checks.
  - Exact-byte Poseidon digest gadgets.
  - Structured GR1CS message reconstruction.
  - Challenge-to-beta binding.
  - Folded-output derivation.
- Update WHIR typed CP setup to serialize/use this full relation.
- Update WHIR typed CP proving to encode the full witness layout.
- Update WHIR typed CP verification to rely only on `CpPublicStatement` plus the WHIR proof.
- Keep legacy SHA/full verifier compatibility paths unchanged.

Acceptance tests:

- Honest WHIR typed CP proof verifies.
- Tampered public digest rejects.
- Tampered public input rejects.
- Tampered R1CS metadata rejects.
- Tampered folded output rejects.
- Legacy SHA CP proof rejects under authoritative WHIR typed CP.

Milestone 4 status: implemented. WHIR typed CP setup now builds the full typed CP digest R1CS from
setup-derived canonical lengths instead of the previous partial typed CP R1CS.
`WhirSnark::prove_typed_cp` encodes the full Poseidon2/BabyBear typed CP
public instance and witness layout, and `WhirSnark::verify_typed_cp` verifies
only `CpPublicStatement` public data plus the WHIR proof. The public statement
now carries public FS commitments so the verifier can encode the typed CP
instance without witness data. Direct WHIR typed CP tests cover honest proof
verification, public digest tampering, public-input tampering, and legacy SHA
typed CP rejection.

## Milestone 5 - Flip Public Authority

Only after all negative tests pass:

- Change `WhirSnark::public_digest_scheme()` from `Sha256` to `Poseidon2BabyBear`.
- Set `WhirSnark::has_authoritative_typed_cp()` to `true`.
- Ensure public proof construction uses Poseidon2/BabyBear FS commitments and public digests.
- Ensure `verify_public` / `verify_v2` succeeds for WHIR+WHIR without witness-side data.
- Ensure public proof bundles contain no witness bundle, FS openings, FS messages, fold inputs, original witnesses, folding proof internals, folded witness, or typed CP private witness.

Acceptance tests:

- WHIR+WHIR `verify_public` succeeds without witness data.
- `verify_public` rejects tampered CP proof.
- `verify_public` rejects tampered output proof.
- `verify_public` rejects proof splicing across public inputs, digests, or folded outputs.
- Full/private verification remains compatible.

Milestone 5 status: implemented. `WhirSnark::public_digest_scheme()` returns
`Poseidon2BabyBear`, `WhirSnark::has_authoritative_typed_cp()` returns true,
and `verify_public` / `verify_v2` succeeds for WHIR+WHIR using only public
inputs, public FS commitments, public digests, folded output, CP proof, and
output proof. The public integration test rejects tampered FS commitments,
public inputs, folded output, CP proof, and output proof.

## Milestone 6 - Add Public Verifier Benchmark

Add the headline benchmark only after public verification is real.

Command:

```text
cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
```

Benchmark requirements:

- Measures public verification only.
- Uses WHIR typed CP plus WHIR typed output.
- Does not include witness-side checks.
- Reports verification time versus folded statement count `k`.

Milestone 6 status: implemented. `benches/whir_scaling.rs` contains
`whir_scaling/public_verify_v2_vs_k`, which precomputes a WHIR+WHIR public proof
and measures `verify_public` only. The default run uses the conservative
`k=1` point because authoritative typed CP proof generation is still expensive.
To benchmark a curve, set `SYMPHONY_WHIR_PUBLIC_VERIFY_KS` to a comma-separated
list, for example:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
```

## Production-Grade Roadmap

The authority milestones above establish a real public verifier boundary. The
remaining work to reach a production-grade Symphony implementation is hardening,
spec freezing, performance, and release discipline. These milestones are finer
grained on purpose: each one should be small enough to implement and verify
without changing the public verifier security boundary accidentally.

### Production Milestone A - Freeze Public Proof Spec

Goal: make the public proof boundary stable enough for downstream users,
serialization, and review.

Implementation requirements:

- Define a versioned public proof envelope for `ProofBundleV2` /
  `PublicProofBundle`.
- Specify exact canonical serialization for:
  - public FS commitments;
  - `fs_root`;
  - `fold_root`;
  - `challenge_digest`;
  - `transcript_seed_digest`;
  - `FoldedOutputInstance`;
  - WHIR CP proof;
  - WHIR output proof.
- Specify rejection behavior for unknown versions, unknown digest schemes,
  malformed digest lengths, malformed public input counts, mismatched R1CS
  metadata, and mismatched fold count.
- Add fixtures or golden vectors for the smallest WHIR+WHIR public proof.
- Keep witness-side structures out of the public proof spec.

Acceptance tests:

- Canonical public proof serialization round-trips.
- Non-canonical or truncated public proof bytes reject.
- Unknown version rejects.
- Unknown digest scheme rejects.
- Public proof fixture remains stable unless the spec version changes.

Milestone A status: implemented. The repository now defines
`PUBLIC_PROOF_ENVELOPE_VERSION = 1` and a canonical `SYMPUB2\0` public proof
envelope for public fields plus length-delimited backend proof payloads. The
envelope round-trips and rejects unknown versions, unknown digest schemes,
truncation, and trailing bytes. WHIR defines `WHIR_PROOF_PAYLOAD_VERSION = 1`,
`canonical_whir_proof_bytes`, and `whir_proof_from_canonical_bytes` for the
backend-owned CP/output proof payloads placed inside the public envelope.

The reviewed golden fixture is
`tests/fixtures/public_proof_v2_whir_minimal.hex`. It freezes the version-1
WHIR+WHIR public envelope wire format with canonical WHIR CP/output payloads.
The fixture is deterministic and intentionally synthetic; live public WHIR
proving still uses randomized FS openings. The live WHIR+WHIR integration test
therefore separately proves/verifies a real public proof, decodes its public
envelope, and decodes both backend WHIR proof payloads.

### Production Milestone B - Public Verifier Negative Matrix

Goal: broaden the public verifier test suite until every public field and
cross-field binding has a direct tampering test.

Implementation requirements:

- Add table-driven public verifier tampering tests for every verifier-visible
  field in `ProofBundleV2`.
- Add proof-splicing tests across:
  - public inputs;
  - FS commitments;
  - public digest tuple;
  - folded output;
  - CP proof;
  - output proof;
  - R1CS metadata;
  - fold count `ell_np`.
- Add replay tests across different valid statements with the same dimensions.
- Add malformed-layout tests for empty inputs, too many inputs, wrong public
  input arity, wrong R1CS dimensions, and wrong digest lengths.
- Assert public verification never needs `CpWitnessBundle`, FS openings, FS
  messages, original witnesses, folding proof internals, or folded witness.

Acceptance tests:

- Honest WHIR+WHIR public proof verifies.
- Every verifier-visible public field has at least one negative test.
- Splicing any major proof section from another proof rejects.
- Public verification still succeeds without witness-side data.
- Existing full/private verifier tests remain green.

Milestone B status: implemented. The WHIR+WHIR public integration test now
builds two valid same-shape public proofs and runs a matrix over verifier-visible
fields, cross-proof splicing, malformed public input/R1CS layouts, and wrong
`ell_np` verifier setup. The honest path still decodes the versioned public
envelope and both canonical WHIR proof payloads, and the test pattern-matches the
public proof bundle without witness-side fields.

### Production Milestone C - Typed CP Arithmetization Audit Harness

Goal: make the typed CP R1CS independently inspectable and regression-safe.

Implementation requirements:

- Add a debug/audit API that reports typed CP R1CS dimensions and row-block
  counts by category:
  - CP folding core;
  - byte constraints;
  - Poseidon digest gadgets;
  - GR1CS message reconstruction;
  - range/monomial semantics;
  - challenge-to-beta binding;
  - folded-output derivation;
  - Ajtai opening checks;
  - original R1CS validity.
- Add per-block satisfaction tests that can isolate which block rejects after a
  targeted mutation.
- Add row-count snapshots for the small public verifier fixture.
- Document which `CpFieldRelation` check each row block enforces.
- Add an internal consistency test comparing software `CpFieldRelation::check`
  with typed CP R1CS satisfaction over the same honest and tampered witnesses.

Acceptance tests:

- Row-block accounting sums to the full typed CP R1CS row count.
- Each major row block has at least one targeted negative test.
- Software checker and R1CS checker agree on the standard mutation corpus.
- Row-count snapshots require deliberate updates when arithmetization changes.

Milestone C status: implemented. The WHIR-gated typed CP R1CS module now
exposes `generate_typed_cp_digest_r1cs_with_audit`, `TypedCpAuditReport`, and
row-block metadata by security category. The current small range-shaped typed CP
snapshot records row totals for CP folding core, byte constraints, Poseidon
digest gadgets, GR1CS message reconstruction, range/monomial semantics,
challenge-to-beta binding, folded-output derivation, Ajtai opening checks,
original R1CS validity, and public-input binding. Tests verify contiguous row
coverage, targeted mutation-to-block classification, and agreement between
software `CpFieldRelation::check` and typed CP R1CS satisfaction over the
standard tamper corpus.

### Production Milestone D - Performance Baseline and Constraint Profiling

Goal: understand and track the cost of public verification and typed CP proving.

Implementation requirements:

- Expand `public_verify_v2_vs_k` to run a documented small curve when explicitly
  requested via `SYMPHONY_WHIR_PUBLIC_VERIFY_KS`.
- Add a typed CP relation-size report to the benchmark output:
  - public input count;
  - witness variable count;
  - row count;
  - WHIR `num_vars`;
  - proof byte estimate.
- Add optional benchmark groups for:
  - typed CP proof generation only;
  - typed CP verification only;
  - typed output verification only;
  - public proof construction outside Criterion timing;
  - public proof serialization size.
- Store current baseline numbers in docs, with machine/date/context noted.
- Avoid silently comparing Criterion results against stale baselines.

Acceptance tests:

- `cargo bench --bench whir_scaling --features whir --no-run` builds all
  benchmark groups.
- `public_verify_v2_vs_k` reports public verification only.
- Benchmark output includes enough relation/proof size metadata to explain
  runtime changes.
- Default benchmark remains runnable on a developer laptop.

Milestone D status: implemented. `benches/whir_scaling.rs` now reports typed CP
R1CS dimensions, WHIR proof `num_vars`, canonical CP/output proof sizes, public
envelope size, and audit row totals for the public WHIR fixture. The
`public_verify_v2_vs_k` timed loop still measures only `verify_public`.
Additional selectable groups cover typed CP proving, typed CP verification,
typed output verification, and public proof envelope serialization. The default
public verifier curve remains `k = [1]`, with broader curves selected by
`SYMPHONY_WHIR_PUBLIC_VERIFY_KS`.

Initial baseline recorded in `docs/whir.md` from:

```text
cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
```

on 2026-05-03 08:25:47 CEST, Darwin 25.3.0 arm64, Rust 1.93.1. For `k = 1`,
public verification measured 3.8789 s - 3.9313 s with mean 3.9059 s. The
profiled typed CP relation had 618 public inputs, 1,117,125 witness variables,
1,127,260 rows, WHIR `num_vars = 21`, CP proof size 1,205,322 bytes, output
proof size 951 bytes, and public envelope size 1,221,492 bytes. Criterion
history under `target/criterion` must be reset or interpreted as local history
before using `change` percentages as a regression signal.

### Production Milestone E - Performance Reduction Pass

Goal: reduce public verification and proving cost without weakening the public
security boundary.

Implementation requirements:

- Use Milestone D profiling to identify the largest row blocks and witness
  regions.
- Remove duplicated byte constraints or digest body materialization where the
  same value is already constrained.
- Share Poseidon auxiliary state where this preserves exact digest semantics.
- Reduce redundant serialization columns after the audit harness can prove
  equivalence.
- Keep exact Poseidon2/BabyBear byte semantics and beta derivation unchanged
  unless the public proof spec version changes.
- Record every optimization with before/after row counts and benchmark numbers.

Acceptance tests:

- All public verifier negative tests still pass.
- Row-block accounting remains consistent.
- Golden public proof fixtures either remain stable or intentionally version.
- `public_verify_v2_vs_k` improves or the tradeoff is documented.

Milestone E status: implemented. The first reduction pass preserved the public
proof format and exact Poseidon2/BabyBear digest semantics. WHIR now caches
generated typed CP relations by serialized context hash and typed CP relation
descriptions by descriptor hash, avoiding repeated R1CS/layout regeneration on
the public verifier path. The typed CP digest composer also absorbs canonical
packed byte-template linear expressions directly, removing duplicated private
packed-input columns and input-equality rows from the typed CP relation.

Before/after local metrics for default `k = 1`:

| Metric | Before | After |
|---|---:|---:|
| `public_verify_v2_vs_k` mean | 3.9059 s | 2.0178 s |
| Typed CP rows | 1,127,260 | 1,116,203 |
| Typed CP witness variables | 1,117,125 | 1,106,068 |
| CP proof bytes | 1,205,322 | 1,202,970 |
| Public envelope bytes | 1,221,492 | 1,219,142 |

The post-optimization public fixture has audit row totals:
CP folding core 11,520; byte constraints 296,566; Poseidon digest gadgets
780,060; GR1CS message reconstruction 17,781; range/monomial semantics 8,217;
challenge-to-beta binding 872; folded-output derivation 896; Ajtai opening
checks 128; original R1CS validity 64; public-input binding 99. Component
benchmarks show typed CP verification remains the dominant public verifier
cost: `typed_cp_verify_only_vs_k` mean 1.8557 s, typed output verification mean
44.460 us, and public envelope serialization mean 57.404 us.

### Production Milestone F - Legacy Compatibility and Routing Cleanup

Goal: make the public path the product boundary while preserving intentional
compatibility paths.

Implementation requirements:

- Audit all `verify`, `verify_public`, `verify_v2`, typed CP, typed output, and
  legacy CP routing branches.
- Ensure WHIR+WHIR public verification always uses authoritative typed CP and
  typed output.
- Ensure SHA-256 remains compatibility-only and is never required inside WHIR.
- Remove or clearly mark dead/non-authoritative typed CP development hooks.
- Keep legacy full/private verifier behavior covered by regression tests.
- Document which APIs are product APIs and which are compatibility/debug APIs.

Acceptance tests:

- WHIR+WHIR public verification succeeds through the public API only.
- Witness-side verification cannot be reached from `verify_public`.
- Legacy SHA/full verifier tests remain green.
- Non-authoritative backend combinations fail closed through `verify_public`.
- Dead code removal does not change public proof semantics.

Milestone F status: implemented. The product APIs are documented as
`prove_public` / `verify_public` over `ProofBundleV2` /
`PublicProofBundle` and `SymphonyProofV2` / `PublicSymphonyProof`.
`prove_v2` / `verify_v2` remain compatibility aliases, while legacy
`prove` / `verify`, explicit soundness checks, raw typed-CP context
serializers, audit reports, and backend payload codecs are documented as
compatibility/debug surfaces. Public route guard tests cover WHIR+WHIR public
verification, non-authoritative backend fail-closed behavior, and a sentinel
backend that panics if `verify_public` calls legacy backend verification.

### Production Milestone G - Security Review Package

Goal: prepare the implementation for a serious internal or external review.

Implementation requirements:

- Produce a review guide mapping each public soundness claim to:
  - code location;
  - tests;
  - R1CS row block;
  - public proof field;
  - documented digest body.
- Document assumptions for Poseidon2/BabyBear parameter generation, Ajtai
  parameters, BabyBear field encoding, beta mapping, and WHIR soundness
  settings.
- Add a threat model for public verification, proof splicing, replay,
  malformed serialization, and chosen-relation behavior.
- Add a known-limits section for performance, supported parameter shapes, and
  non-reviewed code paths.
- Run an internal code review pass focused only on security boundary changes.

Acceptance tests:

- Every public verifier security claim has a code/test/doc reference.
- No unresolved TODO may sit on the public verifier soundness path.
- Review notes distinguish confirmed issues, accepted risks, and future work.
- A fresh checkout can run the documented verification commands.

Milestone G status: implemented. The review package is
`docs/whir_public_security_review.md`. It defines the reviewed WHIR public
verifier boundary, maps public soundness claims to code paths, tests, typed CP
audit row blocks, public proof fields, and documented digest bodies, and
records assumptions, threat model, known limits, accepted risks, future work,
and verification commands. The Milestone G TODO/FIXME review found no
unresolved TODO/FIXME markers on the active WHIR public verifier soundness
path.

### Production Milestone H - Release Gate

Goal: define the minimum bar for calling the WHIR public verifier production
grade.

Release requirements:

- Public proof spec is versioned and stable.
- Public verifier negative matrix is complete.
- Typed CP audit harness exists and is documented.
- Public verifier benchmark has baseline numbers for at least the supported
  small curve.
- Full test suite passes with and without `--features whir`.
- Public proof contains no witness-side data.
- WHIR public verification succeeds through `verify_public` / `verify_v2` and
  rejects all documented tampering/splicing/replay cases.
- Legacy compatibility paths are tested or explicitly deprecated.
- Security review package is complete.

Release verification commands:

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

## Required Verification Commands

Run before flipping authority:

```text
cargo test --features whir typed_cp_digest
cargo test --features whir typed_cp
cargo test --features whir poseidon
cargo test --features whir verify_public
cargo test --features whir
```

Run after flipping authority:

```text
cargo test
cargo test --features whir
cargo test --features whir typed_cp
cargo test --features whir verify_public
cargo bench --bench whir_scaling --features whir --no-run
cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
```

## Non-Negotiable Guardrails

- Do not set `has_authoritative_typed_cp()` to true before the verifier proof enforces the full typed CP relation.
- Do not switch WHIR public digests to Poseidon2/BabyBear until typed CP is authoritative.
- Do not add `public_verify_v2_vs_k` before public verification succeeds without witness-side checks.
- Do not prove SHA-256 inside WHIR.
- Preserve exact documented Poseidon2/BabyBear digest semantics.
- Prover-side `CpFieldRelation::check` is allowed as a sanity check, but it is not soundness.
