# SYMBT3 Native Accumulator Authority Plan

Status: design + implementation plan  
Target: full NonZK native accumulator authority route  
Scope: integrity only, no privacy claim  
Deferred: K5 ZK/masking, true vector tuple leaves, default product routing  

---

## 0. Current State

The implementation currently has two major lines of work.

### K-series: full public-canonical accumulator route

Implemented:

- K1e.2 public-canonical manifest binding
- K2 accumulator instance and transition
- K3 authority profile hardening
- K4 public accumulator research API
- K4.5 source residual verifier batching
- K4.6 compressed public accumulator boundary
- K6a explicit opt-in NonZK accumulator integrity route
- K6b side-by-side product comparison benchmark

This route is the current full accumulator workload path.

Properties:

- full accumulator workload
- NonZK integrity only
- explicit opt-in
- not default `verify_public`
- public-canonical manifest
- no private manifest membership
- no native message-oracle authority
- no K5 masking

### N/M-series: native multi-oracle infrastructure

Implemented:

- N1 native multi-oracle WHIR envelope
- N1b canonical WHIR root serialization
- N2 native manifest/source equality
- N3 committed-private NonZK manifest membership
- N4 native CP round-message oracles
- N4b batch-axis-native message oracle layout `M_i(T,U_i)`
- N5 native NonZK folding-integrity metadata gate
- N6a integrated native folding-integrity proof wrapper
- N6b explicit native NonZK folding-integrity public route
- N6c route matrix/reporting layer
- M1a instrumented compatibility multi-oracle benchmark
- M1b same-domain RLC tuple-leaf multi-oracle benchmark

This route currently proves native-oracle plumbing and smoke/infrastructure claims, but it is not yet the full accumulator authority route.

---

## 1. Target Claim

The target claim is:

```text
verify_symbt3_native_accumulator_authority_non_zk(profile, instance, proof) = true
````

implies that there exist committed source columns, manifest oracle values, CP round message oracles, folded witness data, Ajtai openings, and accumulator witness data such that:

1. `old_accumulator + batch -> new_accumulator` under the declared accumulator transition law.
2. Manifest/source membership is enforced through native WHIR oracle roots.
3. CP round messages are native oracles `M_i(T,U_i)`, with one oracle per CP round.
4. The batch axis `T` lives inside each message oracle domain, not in the oracle count.
5. Folding challenges are derived from input-side native roots only.
6. Folded output and accumulator transition are correctly bound.
7. GR1CS/R1CS residual checks hold.
8. Ajtai commitment/opening algebra holds.
9. Norm/range constraints hold under the declared production-shaped range policy.
10. Native multi-oracle openings use one WHIR instance/root/query schedule via same-domain RLC tuple-leaf packing.
11. RLC tuple-leaf soundness is included in the authority profile.
12. The proof satisfies the declared WHIR, sumcheck, RLC, and Fiat-Shamir soundness profile.

This is **not** a ZK claim.

---

## 2. Non-Goals

Do not implement in this phase:

* K5 masking
* zero-knowledge
* privacy for witness-bearing columns
* true vector-valued tuple leaves
* default `verify_public` promotion
* silent monolithic fallback
* byte transcript reconstruction
* Poseidon digest-body reconstruction
* SYMBT2F-style family proof forests

---

## 3. Key Distinctions

### K6a

K6a is the current full accumulator route.

```text
K6a = full accumulator workload + public-canonical manifest + NonZK integrity
```

It is useful and report-worthy, but it is not native-oracle authoritative.

### N6b / M1b

N6b/M1b demonstrates native-oracle infrastructure.

```text
N6b/M1b = native oracle infrastructure + RLC tuple-leaf smoke/benchmark path
```

It is not yet the full accumulator route.

### N7 Target

N7 must combine both:

```text
N7 = K6a full accumulator workload + N/M native oracle infrastructure
```

---

## 4. Authority Requirements

A native accumulator authority proof must require:

```text
full_accumulator_workload = true
smoke_profile = false
native_multi_oracle = true
tuple_leaf_layout = same_domain_rlc_tuple_leaf_v1
whir_instance_count = 1
root_count = 1
query_schedule_count = 1
transcript_count = 1
family_columnar_subproof_count = 0
backend_table_count = 1
native_oracle_pcs_opening_count = rlc_repetition_count
rlc_repetition_count >= 4
total_rlc_batching_bits >= 120
effective_soundness_bits >= 100
accumulator_transition_claims = 1
source_r1cs_residual_verifier_evaluations = 1
```

The authority gate must reject:

* N7 smoke profile
* compatibility multi-oracle envelope
* single BabyBear RLC check with ~31 bits
* `PublicCanonicalManifestViewV1`
* `DigestOnlyMessageRootsV1`
* `DebugDevelopmentOnly` roots
* one-oracle-per-batch-item message layout
* missing native manifest/source/message policies
* missing `AccumulatorTransitionConsistency`
* missing production norm/range bundle
* `semantic_profile_version` too old
* `ZkRequired` without K5
* fallback flags
* family-columnar subproofs
* K6a proof kind
* monolithic proof kind

---

## 5. RLC Tuple-Leaf Soundness

M1b uses:

```text
same_domain_rlc_tuple_leaf_v1
```

The packed oracle is:

```text
F_tuple(x) = Σ_j γ_j · f_j(x)
```

This is not a true vector-valued tuple leaf.

Authority requires explicit RLC soundness accounting.

### BabyBear single check

BabyBear is about 31 bits, so a single RLC challenge gives only around:

```text
~31 bits
```

This is insufficient for a 100-bit authority target.

### Chosen implementation path

Use repeated independent BabyBear RLC checks:

```text
rlc_repetition_count >= 4
```

Approximate target:

```text
4 × 31 ≈ 124 bits
```

After union-bound overhead, require:

```text
effective_soundness_bits >= 100
```

### Future alternatives

Future work may replace repeated BabyBear RLC with:

* extension-field RLC challenges
* true vector tuple leaves
* a dedicated multi-oracle PCS interface

---

## 6. Milestone N7-0: Soundness Metadata and Gates

### Goal

Add the native accumulator authority profile and fail-closed gate.

### Add

```rust
Symbt3NativeAccumulatorAuthorityProfile
Symbt3NativeAccumulatorAuthorityCounters
Symbt3NativeAccumulatorAuthorityReport
Symbt3NativeAccumulatorAuthorityWorkload
```

Workload enum:

```rust
pub enum Symbt3NativeAccumulatorAuthorityWorkload {
    N7SmokeProfileV1,
    FullK6aAccumulatorV1,
}
```

Gate:

```rust
profile_meets_native_accumulator_authority(profile, metadata) -> bool
```

### Gate must require

* `FullK6aAccumulatorV1`
* `smoke_profile = false`
* `same_domain_rlc_tuple_leaf_v1`
* `rlc_repetition_count >= 4`
* `effective_soundness_bits >= 100`
* `total_rlc_batching_bits >= 120`
* native manifest/source policy
* native round-message policy
* canonical WHIR roots
* production norm/range bundle
* accumulator transition consistency
* no fallback
* no family subproofs

### Tests

Positive:

* valid full-authority metadata passes

Negative:

* smoke profile rejects
* missing RLC bits rejects
* low effective soundness rejects
* compatibility envelope rejects
* one-oracle-per-batch layout rejects
* public-canonical policy rejects
* digest-only message roots reject
* debug roots reject
* K6a proof kind rejects
* monolithic proof kind rejects

---

## 7. Milestone N7-1: Full Workload Proof Wrapper

### Goal

Add a native accumulator authority proof wrapper around:

1. the full K6a main SYMBT3 accumulator proof
2. the same-domain RLC tuple-leaf native multi-oracle proof
3. a binding digest tying both to the same statement

### Add

```rust
Symbt3NativeAccumulatorAuthorityProof
Symbt3NativeAccumulatorAuthorityWitness
Symbt3NativeAccumulatorAuthorityInstance
Symbt3NativeAccumulatorAuthorityCounters
```

### Binding digest

Add:

```text
native_accumulator_authority_binding_digest =
H(
  "SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_BINDING_V1",
  profile_digest,
  accumulator_instance_digest,
  public_statement_digest,
  whir_param_digest,
  main_symbt3_relation_id,
  main_symbt3_proof_digest,
  rlc_tuple_leaf_root,
  rlc_tuple_leaf_layout_digest,
  native_oracle_descriptor_digest,
  native_message_roots_digest,
  manifest_oracle_root,
  source_oracle_root,
  batch_manifest_root,
  old_accumulator_digest,
  new_accumulator_digest,
  batch_size,
  active_count
)
```

The verifier must recompute this and reject mismatch.

Current prerequisite status:

* The typed K6a native workload adapter exists. It extracts the K6a product
  profile digest, accumulator instance digest, public statement digest, WHIR
  parameter digest, relation id, main proof digest, old/new accumulator digests,
  batch manifest root, manifest/message roots, `batch_size`, and `active_count`
  from verified K6a objects.
* The N7b full wrapper layer now composes verified adapter fields with M1b
  native RLC tuple-leaf proof/profile parts and builds the full authority
  binding digest.
* N7b is still blocked because repeated RLC tuple-leaf proof evidence is not
  wired. The wrapper must report fail-closed until at least four independent RLC
  repetitions are verified without adding WHIR instances or roots.
* The fail-closed full helpers must keep rejecting smoke, missing tuple-leaf
  proof parts, binding mismatches, fallback use, family subproofs, and
  incomplete adapter state.

### Tests

Positive:

* honest wrapper verifies for small full workload

Negative:

* stale main proof rejects
* stale native proof rejects
* profile digest mutation rejects
* public statement digest mutation rejects
* WHIR param mutation rejects
* old accumulator digest mutation rejects
* new accumulator digest mutation rejects
* tuple root mutation rejects
* descriptor digest mutation rejects

---

## 8. Milestone N7-2: Full Workload Prover

### Goal

Implement:

```rust
prove_symbt3_native_accumulator_authority_non_zk(...)
```

It must:

1. Build the full K6a accumulator statement/witness.
2. Produce the main full SYMBT3 WHIR proof.
3. Build native logical oracles:

   * manifest
   * source
   * one native CP message oracle per round `M_i(T,U_i)`
4. Pack them with same-domain RLC tuple-leaf mode.
5. Repeat RLC packing independently `rlc_repetition_count` times.
6. Bind all roots/proofs/descriptors with the binding digest.
7. Return `Symbt3NativeAccumulatorAuthorityProof`.

### Requirements

* `full_accumulator_workload = true`
* no smoke relation
* no synthetic `main_whir_num_vars = 2`
* no `main_oracle_len = 4`
* no fallback to K6a-only proof
* no family subproofs
* no one-oracle-per-batch layout

---

## 9. Milestone N7-3: Full Workload Verifier

### Goal

Implement:

```rust
verify_symbt3_native_accumulator_authority_non_zk(...)
```

It must:

1. Check native accumulator authority gate.
2. Recompute profile digest.
3. Recompute accumulator instance digest.
4. Recompute public statement digest.
5. Recompute native binding digest.
6. Verify the full main SYMBT3 WHIR proof.
7. Verify RLC tuple-leaf native multi-oracle proof.
8. Check RLC packed values against logical claims.
9. Check manifest/source equality through RLC aggregate relation.
10. Check native CP message roots and prefix challenge schedule.
11. Check accumulator transition.
12. Reject stale/mismatched components.
13. Reject fallback flags.

### Tests

Positive:

* `k=1`, `round_count=1`
* `k=2`, `round_count=1`
* `k=4`, `round_count=1` if feasible

Negative:

* RLC challenge mutation
* tuple component order mutation
* manifest/source root swap
* message root swap
* message prefix challenge mutation
* folded output mutation
* old/new accumulator mutation
* proof kind mutation
* fallback flag mutation
* family subproof injection

---

## 10. Milestone N7-4: RLC Repetition Support

### Goal

Make RLC repetition real.

For repetition index `r`:

```text
γ_{r,j} = H(
  "SYMBT3_RLC_TUPLE_LEAF_GAMMA_V1",
  r,
  descriptor_digest,
  tuple_leaf_layout_digest,
  profile_digest,
  public_statement_digest,
  whir_param_digest
)
```

For every repetition, prove:

```text
F_tuple_r(z) = Σ_j γ_{r,j} · f_j(z)
```

### Counters

Add:

```text
rlc_repetition_count
rlc_batching_bits_per_repetition
total_rlc_batching_bits
effective_soundness_bits
native_oracle_pcs_opening_count
```

Expected:

```text
native_oracle_pcs_opening_count = rlc_repetition_count
```

not:

```text
native_oracle_pcs_opening_count = logical_oracle_count
```

---

## 11. Milestone N7-5: Benchmark

Add:

```text
symbt3_native_accumulator_authority_vs_k
```

Run:

```text
k = 1,2,4
round_count = 1
rlc_repetition_count = 4
```

Emit:

```text
NATIVE_ACCUMULATOR_AUTHORITY_CSV
```

Fields:

```text
k
round_count
prove_ms
verify_ms
proof_bytes
public_statement_bytes
main_whir_num_vars
main_oracle_len
full_accumulator_workload
smoke_profile
native_multi_oracle
tuple_leaf_layout
logical_oracle_count
rlc_repetition_count
total_rlc_batching_bits
effective_soundness_bits
whir_instance_count
root_count
query_schedule_count
transcript_count
native_oracle_pcs_opening_count
family_columnar_subproof_count
top_level_whir_proof_count
backend_table_count
accumulator_transition_claims
source_r1cs_residual_verifier_evaluations
fallback_used
```

Acceptance:

```text
full_accumulator_workload = true
smoke_profile = false
native_multi_oracle = true
tuple_leaf_layout = same_domain_rlc_tuple_leaf_v1
rlc_repetition_count >= 4
effective_soundness_bits >= 100
whir_instance_count = 1
root_count = 1
query_schedule_count = 1
transcript_count = 1
family_columnar_subproof_count = 0
fallback_used = false
```

---

## 12. Milestone N7-6: Documentation

Update:

* `docs/whir.md`
* `docs/whir_public_performance_north_star_plan.md`
* `docs/symbt3_accumulator_authoritative_roadmap.md`
* optional: `docs/symbt3_soundness_profile.md`

Must state:

* N7 is NonZK.
* N7 uses repeated BabyBear RLC.
* N7 is not privacy preserving.
* N7 is not true vector tuple leaves.
* K5 remains deferred.
* Default `verify_public` remains unchanged unless explicitly changed later.
* Full authority requires full workload + RLC soundness + native binding.
* Smoke profiles fail closed.

---

## 13. Milestone N7-7: Final Negative Matrix

Required negative tests:

### Profile and gate

* smoke profile rejects
* low RLC bits rejects
* missing RLC bits rejects
* wrong tuple layout rejects
* compatibility envelope rejects
* debug root rejects
* public-canonical manifest rejects
* digest-only message roots reject
* semantic profile too old rejects
* ZK-required without K5 rejects

### Proof binding

* binding digest mutation rejects
* profile digest mutation rejects
* accumulator instance digest mutation rejects
* public statement digest mutation rejects
* WHIR param digest mutation rejects
* native descriptor digest mutation rejects
* main proof digest mutation rejects
* tuple root mutation rejects

### Accumulator relation

* old accumulator digest mutation rejects
* new accumulator digest mutation rejects
* folded output mutation rejects
* accumulator transition mutation rejects

### Native oracle relation

* manifest/source root swap rejects
* message root swap rejects
* tuple component order swap rejects
* RLC challenge mutation rejects
* logical value mutation rejects
* packed value mutation rejects
* one-oracle-per-batch layout rejects
* wrong batch axis rejects
* wrong message axis rejects
* stale prefix challenge rejects

### Routing

* K6a proof rejected as N7
* N7 proof rejected as K6a unless explicitly converted
* monolithic proof rejected as N7
* fallback flag rejects
* family subproof injection rejects

---

## 14. Commands

Run after each major milestone:

```bash
cargo fmt
cargo check --features whir --tests
cargo test --features whir native_oracle -- --nocapture
cargo test --features whir symbt3 -- --nocapture
cargo test --features whir verify_public -- --nocapture
cargo bench --bench whir_scaling --features whir --no-run
cargo test --features whir
cargo test
git diff --check
```

Benchmark:

```bash
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4 \
cargo bench --bench whir_scaling --features whir -- "symbt3_native_accumulator_authority_vs_k"
```

---

## 15. Stop Conditions

Do not claim N7 authority unless all are true:

```text
full_accumulator_workload = true
smoke_profile = false
rlc_repetition_count >= 4
effective_soundness_bits >= 100
main proof is full K6a workload
native proof is bound to same statement
all negative tests pass
fallback_used = false
```

If any are false, the route must fail closed.

---

## 16. Final Claim If Successful

If successful, the honest claim is:

```text
We implement a NonZK native accumulator authority route for SYMBT3, using the full accumulator workload and same-domain RLC tuple-leaf native multi-oracle WHIR. The route uses one WHIR instance/root/query schedule for the native oracle batch, repeated RLC checks for soundness, and fail-closed authority gates. It is not zero-knowledge and does not claim privacy.
```
