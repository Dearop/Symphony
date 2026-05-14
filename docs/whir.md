# WHIR Backend

The WHIR backend (`WhirSnark`) implements the `BackendSnark` trait using Merkle-based polynomial commitments from [whir-p3](https://github.com/tcoratger/whir-p3), combined with a Spartan-style R1CS-to-sumcheck reduction over the BabyBear field.

**Plausibly post-quantum** — security relies only on collision-resistant hash functions (Poseidon2, Keccak), not on discrete logarithm or pairing assumptions.

**Feature-gated**: enable with `cargo build --features whir`.

---

## Architecture

```
src/snark/whir/
├── mod.rs          # WhirSnark: BackendSnark impl, sumcheck + WHIR PCS integration
├── field.rs        # BabyBear field conversions and limb splitting
└── serialize.rs    # WhirContext binary serialization
```

The module combines two layers:

1. **Spartan-style sumcheck** (implemented locally): Reduces R1CS satisfaction to a polynomial evaluation claim at a random challenge point `r*`.
2. **WHIR PCS** (from whir-p3): Commits to the witness polynomial via a Merkle tree and proves the evaluation claim `w(r*) = v` using WHIR's interactive oracle proof protocol.

---

## What is WHIR?

WHIR (Weighted Hash Interactive Reduction) is a polynomial commitment scheme built on interactive oracle proofs. It uses Merkle trees to commit to multilinear polynomial evaluations and achieves logarithmic proof size through recursive folding rounds.

In the context of Symphony, WHIR replaces the Pedersen + IPA approach used by Spartan. Instead of committing to witness vectors with elliptic curve points, WHIR commits to multilinear polynomials via Merkle trees and proves evaluations using hash-based opening proofs. The `whir-p3` crate provides the implementation on top of the Plonky3 framework.

---

## Key Types

### WhirSnark

Unit struct implementing `BackendSnark`. Routes to two paths:

- **Output SNARK path** (`is_output_snark = true`): full R1CS-to-sumcheck reduction + WHIR PCS opening proof.
- **CP-SNARK path** (no context): lightweight witness-binding sumcheck + WHIR PCS opening proof.

### WhirProvingKey / WhirVerifyingKey

```rust
pub struct WhirProvingKey {
    pub seed: u64,                      // Deterministic seed derived from relation hash
    pub context_hash: [u8; 32],         // SHA-256 binding (context swap detection)
    pub relation: RelationDescription,  // Stored for context access at prove time
}
```

WHIR infrastructure (`WhirConfig`, `DomainSeparator`, challenger) is constructed at prove/verify time from the seed, since `num_variables` depends on the witness size.

### WhirProof

```rust
pub struct WhirProof {
    pub sumcheck_rounds_3: Vec<[BabyBear; 3]>,             // CP path: degree-2 evals at {0,1,2}
    pub sumcheck_rounds_4: Vec<[BabyBear; 4]>,             // Output path: degree-3 evals at {0,1,2,3}
    pub evaluations: [BabyBear; 3],                        // [Az(r*), Bz(r*), Cz(r*)] or [w(r*), 0, 0]
    pub whir_pcs_proof: WhirPcsProof<F, EF, WhirMmcs>,    // Merkle commitment + opening proof
    pub z_eval: BabyBear,                                  // Polynomial evaluation verified by WHIR
    pub linear_checks: Vec<WhirLinearCheckProof>,          // R1CS paths: bind Az/Bz/Cz claims to z
    pub num_vars: usize,
    pub is_output: bool,
}
```

The proof is **succinct**: the `whir_pcs_proof` contains a Merkle root commitment and logarithmic-size opening proof. No full witness table is included.

---

## BabyBear Field

WHIR operates over the BabyBear prime field: `p = 2^31 - 2^27 + 1 = 2013265921`.

Since Symphony's ring elements are `i64` coefficients modulo a 64-bit prime `q`, values must be mapped into BabyBear. Two strategies are used:

### Limb splitting (CP-SNARK path)

Each `i64` value is split into two 30-bit limbs:
```
val = lo + hi * 2^30     where lo, hi < 2^30 < p
```
This ensures both limbs fit within BabyBear without overflow. A length sentinel is appended for injectivity.

### Direct conversion (Output SNARK path)

Values are reduced modulo BabyBear directly:
```
val mod p
```
Used for R1CS matrix coefficients and the combined assignment vector, where the R1CS relation is already defined over the reduced field.

---

## Plonky3 / WHIR Infrastructure

The `build_whir_infra(seed, num_variables)` function deterministically constructs the entire Plonky3 stack from a seed:

| Component | Type | Role |
|-----------|------|------|
| Permutation | `Poseidon2BabyBear<16>` | Core permutation (seeded via `SmallRng`) |
| Hash | `PaddingFreeSponge<Perm, 16, 8, 8>` | Sponge-based hash for Merkle leaves |
| Compression | `TruncatedPermutation<Perm, 2, 8, 16>` | 2-to-1 Merkle node compression |
| Challenger | `DuplexChallenger<F, Perm, 16, 8>` | Fiat-Shamir challenge derivation |
| MMCS | `MerkleTreeMmcs<...>` | Merkle tree commitment scheme |
| Extension field | `BinomialExtensionField<BabyBear, 4>` | Degree-4 extension for WHIR internals |
| DFT | `Radix2DFTSmallBatch<F>` | Discrete Fourier transform for polynomial ops |

Configuration:
- Folding factor: `min(num_variables, 4)`
- Security level: 100 bits by default
- Soundness type: `UniqueDecoding`
- Starting log inverse rate: 1

Both prover and verifier call `build_whir_infra` with the same seed to get identical configurations, ensuring Fiat-Shamir transcript consistency.

---

## WHIR PCS Integration

### Commit and Prove (`whir_commit_and_prove_multi`)

1. Build WHIR infrastructure from seed.
2. Wrap the witness evaluations as an `EvaluationsList` (multilinear polynomial in evaluation form).
3. Create an `InitialStatement` via `params.initial_statement(poly, SumcheckStrategy::Classic)`.
4. Call `statement.evaluate(&point)` for each requested evaluation constraint — WHIR computes and stores the actual evaluations internally.
5. Initialize a `DuplexChallenger` from the Poseidon2 permutation, feed the `DomainSeparator`.
6. `CommitmentWriter::commit()` — builds the Merkle tree and writes the commitment into the proof/challenger.
7. `WhirProver::prove()` — executes WHIR's folding rounds, producing Merkle opening proofs.

### Verify Opening (`whir_verify_opening_multi`)

1. Build identical WHIR infrastructure from same seed.
2. Initialize identical challenger with same `DomainSeparator`.
3. `CommitmentReader::parse_commitment()` — reads the Merkle root from the proof into the challenger.
4. Build an `EqStatement` with the claimed `(point, evaluation)` pairs.
5. `WhirVerifier::verify()` — checks the opening proof against the commitment and statement.

### Variable Ordering Convention

Plonky3 multilinear polynomials use the convention where `point[0]` is the **slowest** variable (controls the top-half split), while Symphony's `mle_eval_bb` has `point[0]` as the **fastest** variable. The WHIR interface reverses the challenge point before passing it to Plonky3:

```rust
let ef_point: Vec<EF> = point.iter().rev().map(|&x| EF::from(x)).collect();
```

This reversal is applied consistently on both the prover and verifier sides.

---

## Proving Flow (Output SNARK)

1. **Parse & flatten**: Instance and witness bytes are converted to BabyBear (direct conversion). Ring R1CS is flattened: each ring constraint becomes `d` scalar constraints over BabyBear.

2. **Compute Az, Bz, Cz**: Sparse matrix-vector products over BabyBear.

3. **Pad**: `z_flat` is padded to the next power of 2 (minimum 2 elements, required by WHIR).

4. **Transcript setup**: Domain-separated transcript `"whir-output-v2"` with seed and instance binding.

5. **Sumcheck**: Derive random `tau`, build `eq(tau, x)` table, run degree-3 sumcheck:
   ```
   F(x) = eq(tau, x) * [Az(x) * Bz(x) - Cz(x)]
   ```
   Round polynomials are evaluated at `{0, 1, 2, 3}` with Lagrange interpolation.

6. **Evaluation claims**: Extract `az_eval`, `bz_eval`, `cz_eval` at the sumcheck challenge point `r*`.

7. **Linear binding checks**: For each sparse R1CS matrix `M in {A,B,C}`, run a degree-2 inner-product sumcheck proving that the claimed `Mz(r*)` equals the multilinear matrix row `M(r*, .)` applied to the same committed assignment polynomial `z`. Each check produces one additional `z` evaluation point.

8. **WHIR PCS proof**: Commit to `z_flat` as a multilinear polynomial. Add the main evaluation constraint `z(r*) = z_eval` and the three linear-binding evaluation constraints, then prove all openings in one WHIR proof.

9. **Return**: Proof containing `sumcheck_rounds_4`, the claimed `Az/Bz/Cz` evaluations, the linear-binding sumchecks, and the WHIR PCS proof.

---

## Proving Flow (CP-SNARK)

1. Convert witness bytes to BabyBear with limb splitting (two 30-bit limbs per value).
2. Pad to power of 2 (minimum 2 elements).
3. Transcript: `"whir-cp-v2"` + seed + instance.
4. Run degree-2 sumcheck: `F(x) = eq(tau, x) * w(x)` to get challenge point `r*`.
5. Compute `w_eval = w(r*)` via multilinear extension evaluation.
6. Commit to witness polynomial and prove `w(r*) = w_eval` via WHIR PCS.
7. Return proof with `sumcheck_rounds_3` and WHIR PCS proof.

Unlike Spartan's CP path (which includes the full witness table), the WHIR CP path is **succinct** — the Merkle commitment replaces the need to transmit the witness.

---

## Verification

### Output path

1. Rebuild transcript and derive `tau`.
2. Verify sumcheck rounds: check `p(0) + p(1) == claimed_sum` at each round, derive challenges.
3. At the final round, verify `eq(tau, r*) * [az_eval * bz_eval - cz_eval] == last_claim`.
4. Recompute `z_padded_len` and `z_num_vars` from R1CS dimensions.
5. Verify the three linear-binding sumchecks for `A`, `B`, and `C` using sparse matrix MLE evaluation at verifier-known points.
6. Verify one WHIR PCS proof containing the main `z(r*)` opening and the three linear-binding openings.

### CP path

1. Rebuild transcript and derive `tau` challenges.
2. Verify sumcheck product rounds: `p(0) + p(1) == claimed_sum` at each round.
3. Check final evaluation: `eq(tau, r*) * w_eval == last_round_eval`.
4. Verify WHIR PCS opening for the witness polynomial at `r*`.

The CP-R1CS encoding range-constrains the Phase-A q-wraps that bind folded
commitments and public inputs. Phase-B q-wraps remain part of the legacy
embedded Hadamard verifier and are not a standalone authoritative typed CP
relation; the validated modular WHIR path keeps the explicit algebraic
`CpRelation::check_with_algebra` check mandatory.

---

## Spartan vs WHIR Comparison

| Aspect | Spartan | WHIR |
|--------|---------|------|
| **Field** | Ristretto scalar (~2^252) | BabyBear (~2^31) |
| **Commitment** | Pedersen (elliptic curve) | Merkle tree (Poseidon2/Keccak) |
| **Opening proof** | Bulletproofs IPA (log n rounds) | WHIR PCS (Merkle folding rounds) |
| **Post-quantum** | No | Yes |
| **CP-SNARK succinctness** | No (includes witness table) | Yes (Merkle commitment) |
| **Setup** | Pedersen generator derivation | Deterministic WHIR infra from seed |
| **Dependencies** | `curve25519-dalek` | `whir-p3`, Plonky3 (`p3-*` crates) |
| **Field conversion** | i64 -> Scalar (trivial, large field) | i64 -> BabyBear (limb splitting for CP) |
| **Variable ordering** | Native (point[0] = fastest) | Reversed (Plonky3: point[0] = slowest) |

---

## Context Serialization (`serialize.rs`)

Binary format with header `"WHIR"`:

```rust
pub struct WhirContext {
    pub r1cs: R1CSMatrices,
    pub q: u64,
    pub d: usize,
    pub n_pub: usize,
    pub is_output_snark: bool,
}
```

Same COO sparse format as Spartan's serializer, with a different header for type safety.

---

## Integration with Symphony

During `SymphonyProver::<WhirSnark>::setup(params)`:

1. **CP-SNARK relation**: No context. WHIR takes the CP path with limb-split witness encoding and succinct Merkle-based proofs.
2. **Output SNARK relation**: Serialized `WhirContext` with R1CS. WHIR takes the output path with direct field conversion and full R1CS-to-sumcheck reduction.

The `SymphonyProof<WhirSnark>` contains both proofs, and the verifier checks both independently.

---

## N1 Native Multi-Oracle WHIR Evaluation Layer

`src/snark/whir/native_oracles.rs` adds the SYMBT3-N1 native multi-oracle
evaluation layer. It is infrastructure only: it does not change
`verify_public`, does not promote product routing, does not implement K5/ZK,
and does not implement private manifest membership or native CP message
semantics.

N1 uses one logical native-oracle proof envelope:

```rust
WhirNativeMultiOracleProof {
    root_policy,
    descriptors,
    eval_claims,
    native_oracle_eval_claims_digest,
    native_multi_oracle_envelope_digest,
    pcs_openings,
    counters,
    ...
}
```

Each descriptor binds:

- `oracle_id`;
- `role` (`Manifest`, `Source`, `MessageRound`, `Accumulator`,
  `FoldedBoundary`, or `Auxiliary`);
- `layout_digest`;
- `num_vars`;
- `root`;
- `opening_schedule`.

Because the current whir-p3 integration commits and opens one polynomial per
PCS proof, N1 stores one internal WHIR PCS opening payload per native oracle
inside the single logical envelope. These payloads are counted as
`native_oracle_pcs_opening_count`, not as `family_columnar_subproof_count`; N1
does not create a SYMBT2F-style proof forest.

The descriptor digest is:

```text
H("SYMBT3_NATIVE_ORACLE_DESCRIPTORS_V1", ordered descriptors)
```

Descriptors must be strictly sorted by `oracle_id`; duplicates and unsorted
descriptors reject. Opening challenge derivation binds the proof relation id,
public statement digest, WHIR parameter digest, ordered descriptor/root digest,
root policy, opening schedule, and claim kind.

For equality checks, use `WhirNativeEvalClaimKind::EqualitySide` on all compared
oracles with `TranscriptDerived { domain_separator }`. This derives a shared
domain-separated point from the ordered descriptor/root digest, so a future
check such as:

```text
ManifestOracle(zeta) = SourceOracle(zeta)
```

opens both sides at the same `zeta`. Use `PerOraclePoint` only for independent
claims. `SamePoint` has a fixed N1 domain label
`SYMBT3_NATIVE_ORACLE_SAME_POINT_V1`.

SYMBT3-N1b hardens descriptor roots and envelope metadata:

- the default root policy is `NativeOracleRootPolicy::CanonicalWhirRootV1`;
- the WHIR initial commitment is serialized canonically from the typed
  `MerkleCap<BabyBear, [BabyBear; 8]>` roots, using canonical BabyBear words;
- `DebugDevelopmentOnly` remains as an explicit quarantined policy for
  development fixtures only;
- product, authority, native-manifest, and native-message verification profiles
  reject `DebugDevelopmentOnly`;
- role, schedule, specs, descriptors, eval requests, eval claims, and envelope
  metadata all have stable canonical bytes and digest helpers.

## N2 Native Manifest/Source Membership Development Path

SYMBT3-N2 uses the N1 native multi-oracle envelope to implement the
`NativeManifestOracleOpeningV1` development path. It proves the NonZK semantic
check:

```text
ManifestOracle(zeta_manifest_source) = SourceOracle(zeta_manifest_source)
```

The N2 smoke profile keeps the N1 logical proof shape:

- `top_level_whir_proof_count = 1`;
- `family_columnar_subproof_count = 0`;
- `native_oracle_count = 2`;
- `native_oracle_pcs_opening_count = 2`.

The manifest oracle uses role `Manifest`; the source oracle uses role `Source`.
Both descriptors use `WhirNativeEvalClaimKind::EqualitySide`, stable oracle IDs
1 and 2, and the N2 transcript domain
`SYMBT3_N2_MANIFEST_SOURCE_EQUALITY`. N2 v1 requires equal `num_vars` for the
manifest and source layouts; mismatched domains reject rather than applying a
layout map.

N2 adds the public manifest binding:

```text
batch_manifest_root = H(
    "SYMBT3_NATIVE_MANIFEST",
    manifest_layout_digest,
    manifest_oracle_root,
    native_oracle_root_policy_digest
)
```

The verifier recomputes this root from the manifest descriptor root and rejects
mismatches. The equality-point transcript binds the proof relation id, public
statement digest, WHIR parameter digest, ordered native descriptor/root digest,
manifest/source layout digests, `batch_manifest_root`, the canonical root policy
digest, and the `NativeManifestOracleOpeningV1`/N2 domain. This challenge is a
proof-checking challenge; it is not beta and does not affect folded output beta.

N2 is deliberately not a product route:

- it does not change `verify_public` or the current v2 public verifier route;
- it does not replace the existing K6a `PublicCanonicalManifestViewV1` route;
- it does not implement K5/ZK or masking;
- it does not claim private-manifest product authority;
- it is the prerequisite infrastructure for committed/private manifest
  membership in N3;
- native CP message oracles remain deferred to N4.

## N3 Committed-Private NonZK Manifest Membership

SYMBT3-N3 builds on the N2 native manifest/source opening path and adds a
committed-private manifest/source development policy. In this milestone,
private means only "not serialized as full values in the public API boundary."
It is not a privacy claim: WHIR verifier openings may reveal queried coordinates.

N3 introduces `Symbt3ManifestVisibility::CommittedPrivateNonZk` and typed
manifest/source component rows backed by BabyBear values. The prover supplies
the full public and committed-private rows as witness-side native oracle
evaluations. The public statement serializes only roots, layout digests,
component metadata, value counts, and public-boundary component values.
Committed-private component values are omitted from public canonical bytes, and
the N3 smoke fixture reports `committed_private_public_bytes = 0`.

Authority gates are intentionally narrow:

- `PublicCanonicalManifestViewV1` rejects committed-private components;
- `NativeManifestOracleOpeningV1` plus `NativeSourceOracleOpeningV1` accepts
  `CommittedPrivateNonZk` only with `NonZkIntegrityOnly` or explicit NonZK
  research status;
- ZK-required status rejects committed-private components until K5 masking
  exists;
- `DebugDevelopmentOnly` roots remain rejected under native-manifest authority.

N3 keeps the N2 native opening shape. The manifest and source native oracles
still use equal `num_vars`, two `EqualitySide` claims, and the same
`batch_manifest_root` binding. The smoke counters remain:

- `top_level_whir_proof_count = 1`;
- `family_columnar_subproof_count = 0`;
- `native_oracle_count = 2`;
- `native_oracle_pcs_opening_count = 2`.

N3 does not change `verify_public`, does not replace K6a, and does not promote a
private-manifest product route. K5 masking is still required for any future ZK
claim, and native CP message oracles remain deferred to N4.

## N4 Native CP Round-Message Oracles

SYMBT3-N4 adds native CP round-message oracles as a development and
infrastructure path. Each CP round message `M_i(T, U_i)` is committed as its own
native WHIR oracle with role `MessageRound { round: i }`, stable oracle id
`1000 + i`, and a `MessageView` opening under the
`SYMBT3_N4_ROUND_MESSAGE_VIEW` domain.

N4 introduces:

- `Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1`;
- `Symbt3NativeRoundMessageOracleLayoutV1`;
- compressed `message_oracle_roots_digest`;
- compressed `message_round_layouts_digest`;
- `message_oracle_policy_digest`;
- prefix-derived native round challenges.

N4b fixes the batch-axis shape: each round oracle is `M_i(T, U_i)`, where `T`
is the batch item axis inside the native oracle domain and `U_i` is the typed
coordinate axis for round `i`. The layout records `batch_axis_log_size`,
`message_axis_log_size`, and `total_num_vars = batch_axis_log_size +
message_axis_log_size`. There is one native oracle per CP round, not one native
oracle per batch item.

Round message oracles may have different `message_axis_log_size`; unlike N2
manifest/source membership, N4 does not require equal domains across rounds.
For fixed `round_count`, increasing batch size only increases the round
oracle's `total_num_vars`. The N1 envelope is unchanged: there is one logical
native multi-oracle proof, no `family_columnar_subproofs`, and no
SYMBT2F-style per-family proof forest.

Round challenges are derived from ordered input-side prefix roots:

```text
round_challenge_i = H(
    "SYMBT3_ROUND_CHALLENGE_V1",
    folding_protocol_id,
    input_public_boundary_digest,
    batch_manifest_root,
    source_roots_digest,
    native_message_oracle_roots[0..=i],
    round_index = i,
    round_layout_digest_i,
    active_count,
    batch_size
)
```

Changing root `j <= i` changes challenge `i`; changing a later root does not
affect earlier challenges. Folded output and WHIR PCS opening payloads are not
inputs to these folding challenges. Native proof-checking opening challenges
remain separate and continue to bind the proof relation id, public statement
digest, WHIR parameter digest, descriptor/root digest, root policy, schedule,
and claim kind.

N4 is deliberately not a product route:

- it does not change `verify_public` or v2 product routing;
- it does not replace K6a or the `PublicCanonicalManifestViewV1` route;
- it does not implement K5/ZK or masking;
- it does not prove byte transcript reconstruction;
- it does not add `message_trace_values`, `message_trace_col`, or
  message-to-trace reconstruction bindings;
- its native-oracle count scales with CP round count, not batch size;
- it prepares the native message layer needed before a future
  `Symbt3NonZkFoldingIntegrityV1` promotion.

## N5 Native NonZK Folding-Integrity Profile Gate

SYMBT3-N5 adds `Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1` as a
metadata gate for a future versioned native product route. It is still
infrastructure only: it does not change `verify_public`, does not promote a
default route, does not implement K5/ZK, and does not add byte transcript
reconstruction.

The gate requires the native stack assembled by N2/N3/N4b:

- manifest policy `NativeManifestOracleOpeningV1`;
- source policy `NativeSourceOracleOpeningV1`;
- message policy `NativeRoundMessageOraclesV1`;
- native root policy `CanonicalWhirRootV1`;
- committed-private components only in `NonZkIntegrityOnly` or explicit NonZK
  research status;
- no `DebugDevelopmentOnly` roots;
- no `PublicCanonicalManifestViewV1` under the native profile;
- no row-byte or digest-only message-root policy;
- one logical native-oracle envelope;
- `top_level_whir_proof_count = 1`;
- `family_columnar_subproof_count = 0`;
- manifest/source native oracle count `= 2`;
- native message oracle count `= round_count`, not batch size.

N5 also gates semantic readiness for folding accumulator integrity. The profile
must report the N2 manifest evaluation claim, accumulator transition
consistency, K1/K2/K3/K4 semantic families, and the production-shaped norm/range
bundle. A monolithic fallback flag or product-default route attempt rejects.

The implementation exposes:

- `Symbt3NonZkFoldingIntegrityProfileMetadata`;
- `Symbt3NonZkFoldingIntegrityProfileReport`;
- `profile_meets_native_non_zk_folding_integrity`;
- `symbt3_non_zk_folding_integrity_profile_report`.

K6a remains the existing explicit `PublicCanonicalManifestViewV1` route. Future
N6 is expected to add a versioned proof envelope and opt-in native route if the
native profile is promoted. K5 masking remains required for any ZK claim.

---

## Dependencies

All WHIR-specific dependencies are feature-gated behind `whir`:

- `whir-p3` — WHIR polynomial commitment scheme (commit, prove, verify).
- `p3-baby-bear` — BabyBear field implementation + Poseidon2 permutation.
- `p3-field` — Field traits and extension field (`BinomialExtensionField`).
- `p3-challenger` — `DuplexChallenger` for Fiat-Shamir.
- `p3-merkle-tree` — `MerkleTreeMmcs` for Merkle commitments.
- `p3-keccak` — Keccak hash (available for Merkle compression variants).
- `p3-symmetric` — `PaddingFreeSponge`, `TruncatedPermutation`.
- `p3-dft` — `Radix2DFTSmallBatch` for polynomial DFT operations.
- `p3-matrix` — Dense/row-major matrix types.
- `p3-util`, `p3-maybe-rayon`, `p3-multilinear-util`, `p3-commit` — Supporting utilities.
- `rand` — `SmallRng` for deterministic Poseidon2 permutation seeding.

All Plonky3 crates are pinned to revision `b0fa5139`.
