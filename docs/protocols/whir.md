# WHIR Backend

The WHIR backend (`WhirSnark`) implements the `BackendSnark` trait using Merkle-based polynomial commitments from [whir-p3](https://github.com/tcoratger/whir-p3), combined with a Spartan-style R1CS-to-sumcheck reduction over the BabyBear field.

**Plausibly post-quantum** — security relies only on collision-resistant hash functions (Poseidon2, Keccak), not on discrete logarithm or pairing assumptions.

**Feature-gated**: enable with `cargo build --features whir`.

---

## Architecture

```
src/snark/whir/
├── mod.rs                  # module root and orchestration facade
├── backend_impl.rs         # BackendSnark impl and typed CP/output routing
├── batched_cp_columnar.rs  # SYMBT2C/SYMBT2F columnar batched-CP proof checks
├── batched_cp_context.rs   # batched-CP relation context decoding and dispatch
├── core_protocol.rs        # shared WHIR PCS, CP, sumcheck, and MLE helpers
├── field.rs                # BabyBear field conversions and limb splitting
├── output.rs               # typed output proof helpers
├── serialize.rs            # WhirContext binary serialization
├── symbt3_columns.rs       # SYMBT3 algebraic columns and claims
├── symbt3_verify.rs        # SYMBT3 verifier profile and accumulator route checks
└── tests.rs                # WHIR module tests
```

The module combines two layers:

1. **Spartan-style sumcheck** (implemented locally): Reduces R1CS satisfaction to a polynomial evaluation claim at a random challenge point `r*`.
2. **WHIR PCS** (from whir-p3): Commits to the witness polynomial via a Merkle tree and proves the evaluation claim `w(r*) = v` using WHIR's interactive oracle proof protocol.

`mod.rs` owns the public module surface and shared imports/types. The split
files above are included into that module scope, so existing paths such as
`crate::snark::whir::WhirSnark`, canonical WHIR proof payload helpers, and
public profile helpers remain stable.

Related split modules:

```
src/modular/batched_cp/
├── columnar_layouts.rs     # SYMBT2C/SYMBT2F columnar layouts and traces
├── evaluator.rs            # batched CP evaluator and field arithmetic helpers
├── relation_contexts.rs    # structured/semantic context encode/decode impls
├── semantic_codes.rs       # semantic/SYMBT3 discriminants and code mappings
├── serialization.rs        # canonical statement, relation, and layout codecs
├── shape.rs                # accumulator and batch shape builders
├── symbt3_layouts.rs       # SYMBT3 layout descriptors and authority profiles
├── symbt3_public.rs        # SYMBT3 public statements, witnesses, manifests
└── types.rs                # public batched CP and SYMBT3 data types

src/snark/cp_snark/typed_r1cs/
├── digest_builder.rs       # full typed CP digest R1CS assembly
├── digest_constraints.rs   # digest body, beta, and folded-output constraints
├── encoding_witness.rs     # typed CP instance/witness encoders
├── gr1cs_range.rs          # GR1CS range-message byte/shape constraints
├── helpers.rs              # shared arithmetic, byte, and Poseidon helpers
├── layouts.rs              # public layout, audit, and shape structs
├── monomial_constraints.rs # monomial/range semantic constraints
├── monomial_witness.rs     # monomial semantic witness construction
├── poseidon.rs             # Poseidon2/BabyBear software and R1CS gadgets
├── statement.rs            # original/typed CP statement R1CS builders
└── tests.rs                # typed CP R1CS tests
```

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
    pub seed: [u8; 32],                 // Deterministic seed derived from relation hash
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
| Permutation | `Poseidon2BabyBear<16>` | Core permutation (seeded via `ChaCha20Rng` from the full 32-byte relation seed) |
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

The public verifier boundary also has Poseidon2/BabyBear digest scaffolding for
the typed CP relation. These field-native digests serialize as eight canonical
BabyBear `u32` limbs. Fiat-Shamir message commitments in that scheme are
`Poseidon2BabyBear("fs-commit" || len(message) || message || opening)`. WHIR
public proofs use this scheme now that typed CP is authoritative.

`WhirSnark::public_digest_scheme()` returns `Poseidon2BabyBear`, and
`WhirSnark::has_authoritative_typed_cp()` returns true. The public verifier
path reconstructs `CpPublicStatement` from public inputs, public FS
commitments, public roots/digests, and the folded output, then verifies the
typed CP WHIR proof without witness-side data.

The public output proof is a WHIR transcript-binding proof over the public
folded-output bytes. The semantic folded-output derivation is enforced by the
authoritative typed CP proof.

## Product Routing

The product WHIR verifier API is `prove_public` / `verify_public` over
`PublicProofBundle<WhirSnark, WhirSnark>` or
`PublicSymphonyProof<WhirSnark>`. That route is public-only: it reconstructs
`CpPublicStatement` from caller-supplied public inputs, R1CS metadata, public
FS commitments, public digests, and the folded output, then verifies the WHIR
typed CP and typed output proofs. It does not read FS openings, FS messages,
fold inputs, original witnesses, folding proof internals, folded witnesses, or
CP witness bundles.

The older `prove_v2` / `verify_v2` names are compatibility aliases for the same
public boundary. Legacy `prove` / `verify` remain compatibility/debug paths for
full proof objects and may inspect witness-side data. SHA-256 is compatibility
only for non-WHIR and legacy/full verifier routes; WHIR public verification
uses Poseidon2/BabyBear and must not fall back to SHA-256 or explicit
witness-side soundness checks.

The security review package for this boundary is
`docs/whir_public_security_review.md`. It maps public soundness claims to code,
tests, audit row blocks, public proof fields, and digest bodies.

The current typed CP digest layer reconstructs the Poseidon absorption bodies
from structured private/public variables instead of leaving them as arbitrary
private bytes:

- FS commitment bodies bind `len(message) || message || opening`, with the
  message length fixed by setup and message bytes tied to the fold-root
  GR1CS-evaluation message bytes.
- `fs_root` body bytes bind to the public FS commitment BabyBear limbs, with
  canonical count and per-commitment length prefixes.
- `fold_root` body bytes bind to CP-core commitment columns, public input
  columns, and the structured GR1CS message bytes, with canonical per-entry
  length prefixes.
- Per-round `challenge` Poseidon blocks bind transcript bytes to public inputs,
  R1CS metadata, public FS commitments, and the static canonical transcript
  frame bytes.
- `challenge_digest` body bytes bind to the private per-round challenge digest
  outputs and canonical per-challenge length prefixes.
- Each 32-byte per-round `Poseidon2BabyBear("challenge", ...)` output is bound
  to the CP-R1CS folding challenge `beta` for the same round. The mapping is
  fixed-shape and circuit-native: every challenge byte is decomposed as
  `byte = d0 + 5*d1 + 25*q` with `d0,d1 in 0..=4`, then the two beta
  coefficients are `d0 - 2` and `d1 - 2`, yielding 64 coefficients in
  `{-2,-1,0,1,2}`.
- `transcript_seed_digest` body bytes bind to the public inputs and R1CS
  metadata in the typed CP statement, with canonical input counts and metadata
  lengths.
- The Hadamard prefix of `encode_gr1cs_round_message` is bound to existing
  CP-R1CS Hadamard columns: round counts, per-round evaluation counts,
  sumcheck evaluations, and evaluation-matrix values.
- For GR1CS messages with private proof data available at setup/proving time,
  the range-proof section shape is parsed and its canonical count/length
  prefixes are constrained in-circuit: monomial commitment count and element
  lengths, monomial vector count and lengths, monomial sumcheck round/evaluation
  counts, monomial evaluation count, square-evaluation count, and projected
  value count.
- Range-proof payload sections now have structured private columns, and their
  canonical serialized bytes are constrained to match those columns: monomial
  commitments, monomial vectors, monomial sumcheck evaluations, monomial
  evaluation tensors, square evaluations, and `projected_values`.
- The structured monomial vectors now have local semantic constraints: each
  coefficient has a boolean square, each ring element has at most one nonzero
  coefficient, and projected values are reconstructed from the monomial
  decomposition digits with `d_prime = D - 2`.
- Range-proof monomial commitments now use deterministic
  verifier-reconstructable Ajtai matrices, and the typed CP R1CS constrains
  each structured monomial commitment to open to its structured monomial vector.
- The typed CP witness bundle carries monomial sumcheck seed/challenge material
  in addition to the Hadamard challenges, and the typed CP R1CS now constrains
  the monomial verifier equations against those variables: degree-4 sumcheck
  round consistency, final evaluation consistency, coefficient cubic checks,
  and square-evaluation boolean consistency.
- The monomial evaluation claims are constrained to equal the multilinear
  evaluations of the structured monomial-vector coefficient tables at the
  monomial sumcheck point. The square-evaluation claims are constrained to
  equal the multilinear evaluations of the structured square tables at the same
  point.

This layer is now routed as WHIR's authoritative typed CP relation. It proves canonical byte
reconstruction, digest correctness, monomial-vector well-formedness, and
projected-value reconstruction, monomial commitment opening validity, monomial
sumcheck/evaluation consistency, and Poseidon challenge-to-beta binding. It
also proves the monomial sumcheck verifier equations over the structured
monomial evaluation and square-evaluation claims, and binds those claims back
to the structured monomial-vector tables. The folded output checkpoint is also
arithmetized at the typed CP R1CS level: CP-core rows derive the folded
commitment and folded public input from the bound beta values, and dedicated
folded-evaluation rows derive the public folded evaluation tensors from the
same beta-weighted GR1CS evaluation matrices. Typed folded-output consistency is
checked at the statement boundary by requiring `folded_output.folded_instance`
to equal `x_folded`. WHIR setup/prove/verify now routes direct typed CP proofs
through this full typed CP digest R1CS; the verifier encodes the public typed
CP instance from `CpPublicStatement`, including public FS commitments, and does
not require witness-side CP data.
Consequently `WhirSnark::public_digest_scheme()` is `Poseidon2BabyBear` and
`has_authoritative_typed_cp()` is true.

The typed CP arithmetization now has an audit harness exposed through the
WHIR-gated CP R1CS module. `generate_typed_cp_digest_r1cs_with_audit` returns
the generated R1CS, layout, and `TypedCpAuditReport`; the legacy
`generate_typed_cp_digest_r1cs` wrapper still returns only the R1CS and layout.
The report records dimensions plus contiguous row blocks by security category:
CP folding core, byte constraints, Poseidon digest gadgets, GR1CS message
reconstruction, range/monomial semantics, challenge-to-beta binding,
folded-output derivation, Ajtai opening checks, original R1CS validity, and
public-input binding.

Each audit block lists the `CpFieldRelation` responsibility it enforces. The
current small range-shaped snapshot has these row totals by category:

| Audit block kind | Rows | Primary check |
|---|---:|---|
| CP folding core | 11,520 | Folded commitment/input and Hadamard CP-core consistency |
| Byte constraints | 138,742 | Canonical byte packing, length framing, and transcript body binding |
| Poseidon digest gadgets | 368,340 | Poseidon2/BabyBear digest correctness |
| GR1CS message reconstruction | 7,889 | FS/fold GR1CS message bytes reconstruct from structured variables |
| Range/monomial semantics | 2,704 | Monomial openings, monomiality, sumcheck/evaluation, square checks, projected values |
| Challenge-to-beta binding | 872 | Poseidon challenge bytes map to CP `beta` coefficients |
| Folded-output derivation | 896 | Public folded evaluation tensors derive from beta-weighted GR1CS evaluations |
| Ajtai opening checks | 128 | Original witness commitments open under Ajtai |
| Original R1CS validity | 64 | Original assignments satisfy the source R1CS |
| Public-input binding | 99 | Public inputs and R1CS metadata bind statement/digest bodies |

Tests assert that these blocks cover every typed CP R1CS row, that targeted
mutations report the expected block kind, and that software `CpFieldRelation`
checks agree with typed CP R1CS satisfaction over the standard mutation corpus.

### Public verifier profiling baseline

`benches/whir_scaling.rs` now prints typed CP relation/proof metadata alongside
the public verifier benchmark. The `public_verify_v2_vs_k` Criterion timing
measures only `verify_public`; proof construction, relation profiling, proof
serialization, and envelope sizing happen before the timed loop. The default
curve remains `k = [1]`; set `SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,...` when an
explicit broader curve is needed.

The printed profiling fields are:

| Field | Meaning |
|---|---|
| `typed_cp_public_inputs` | Number of public BabyBear slots in the typed CP R1CS |
| `typed_cp_witness_variables` | Number of private BabyBear witness slots in the typed CP R1CS |
| `typed_cp_rows` | Number of typed CP R1CS constraints |
| `compressed_typed_cp_public_inputs` | Number of public BabyBear slots in the compressed-FS development typed CP R1CS |
| `compressed_typed_cp_witness_variables` | Number of private BabyBear witness slots in the compressed-FS development typed CP R1CS |
| `compressed_typed_cp_rows` | Number of constraints in the compressed-FS development typed CP R1CS |
| `typed_cp_whir_num_vars` | WHIR multilinear variable count for the typed CP proof |
| `cp_proof_bytes` | Canonical WHIR CP proof payload bytes |
| `output_proof_bytes` | Canonical WHIR typed-output proof payload bytes |
| `public_envelope_bytes` | Versioned public proof envelope bytes |
| `audit_rows` | Row totals by `TypedCpAuditBlockKind` |
| `split_rows` | Row totals attributed to the planned typed CP leaf, accumulator, and leaf/accumulator binding components |

Optional component benchmark groups are also available:
`typed_cp_prove_only_vs_k`, `typed_cp_verify_only_vs_k`,
`typed_output_verify_only_vs_k`, and `public_proof_size_vs_k`. These groups
reuse prebuilt valid public fixtures and are selected through the normal
Criterion filter.

Initial local baseline:

| Item | Value |
|---|---|
| Date | 2026-05-03 08:25:47 CEST |
| Machine | Darwin 25.3.0 arm64 (`pauls-macbook-pro-9.home`) |
| Rust | `rustc 1.93.1`, `cargo 1.93.1` |
| Command | `cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"` |
| k values | `[1]` |
| Public verify time | 3.8789 s - 3.9313 s, mean 3.9059 s |
| Throughput | 0.2544 - 0.2578 elem/s, mean 0.2560 elem/s |
| Typed CP dimensions | 618 public, 1,117,125 witness variables, 1,127,260 rows |
| WHIR typed CP `num_vars` | 21 |
| Proof sizes | CP 1,205,322 bytes; output 951 bytes; envelope 1,221,492 bytes |

Audit row totals for this baseline:

| Audit block kind | Rows |
|---|---:|
| CP folding core | 11,520 |
| Byte constraints | 307,623 |
| Poseidon digest gadgets | 780,060 |
| GR1CS message reconstruction | 17,781 |
| Range/monomial semantics | 8,217 |
| Challenge-to-beta binding | 872 |
| Folded-output derivation | 896 |
| Ajtai opening checks | 128 |
| Original R1CS validity | 64 |
| Public-input binding | 99 |

Criterion compares against any existing local history under `target/criterion`.
Reset that directory before recording a new clean baseline, or treat the
reported `change` block as a local-history comparison rather than a protocol
regression claim.

Milestone E optimization pass:

- WHIR now caches generated typed CP relations by serialized context hash and
  typed CP relation descriptions by descriptor hash. Repeated public
  verification no longer regenerates the typed CP R1CS/layout on every call.
- The typed CP Poseidon digest composition now absorbs the canonical packed
  byte-template linear expressions directly. This removes the duplicated
  private packed-input columns and input-equality rows while preserving the
  exact documented `digest_core` byte semantics.
- Standalone Poseidon gadget APIs remain unchanged for regression tests.

Post-optimization local baseline:

| Item | Before Milestone E | After Milestone E |
|---|---:|---:|
| Public verify mean (`k=1`) | 3.9059 s | 2.0178 s |
| Public verify interval | 3.8789 s - 3.9313 s | 1.9993 s - 2.0357 s |
| Typed CP public inputs | 618 | 618 |
| Typed CP witness variables | 1,117,125 | 1,106,068 |
| Typed CP rows | 1,127,260 | 1,116,203 |
| WHIR typed CP `num_vars` | 21 | 21 |
| CP proof bytes | 1,205,322 | 1,202,970 |
| Output proof bytes | 951 | 953 |
| Public envelope bytes | 1,221,492 | 1,219,142 |

Post-optimization audit row totals for the public benchmark fixture:

| Audit block kind | Rows |
|---|---:|
| CP folding core | 11,520 |
| Byte constraints | 296,566 |
| Poseidon digest gadgets | 780,060 |
| GR1CS message reconstruction | 17,781 |
| Range/monomial semantics | 8,217 |
| Challenge-to-beta binding | 872 |
| Folded-output derivation | 896 |
| Ajtai opening checks | 128 |
| Original R1CS validity | 64 |
| Public-input binding | 99 |

Post-optimization component timings for `k=1`:

| Benchmark group | Time |
|---|---:|
| `typed_cp_verify_only_vs_k` | 1.8436 s - 1.8661 s, mean 1.8557 s |
| `typed_cp_prove_only_vs_k` | 1.4766 s - 1.4998 s, mean 1.4883 s |
| `typed_output_verify_only_vs_k` | 43.698 us - 45.599 us, mean 44.460 us |
| `public_proof_size_vs_k` envelope serialization | 55.575 us - 59.592 us, mean 57.404 us |

### Public verifier performance north star

The authoritative WHIR public verifier is now multi-statement, but the current
cost model is still a linear typed-CP baseline rather than the final north-star
performance profile. After fixing the `ell_np > 1` typed CP witness layout,
the public verifier benchmark succeeds for `k = 1, 2`:

| k | `verify_public` mean | Typed CP rows | CP proof bytes | Public envelope bytes |
|---:|---:|---:|---:|---:|
| 1 | 2.0219 s | 1,116,203 | 1,202,354 | 1,218,527 |
| 2 | 4.1157 s | 2,221,456 | 1,254,768 | 1,270,994 |

Command:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
```

The near-doubling from `k = 1` to `k = 2` is expected for the current
monolithic typed CP R1CS. The public route is authoritative and public-only,
but the CP proof still proves a relation whose rows grow with
`params.ell_np`. The largest `k = 2` row blocks are:

| Audit block kind | Rows |
|---|---:|
| Poseidon digest gadgets | 1,559,524 |
| Byte constraints | 594,512 |
| GR1CS message reconstruction | 35,562 |
| Range/monomial semantics | 16,434 |

The current optimization target is documented in
[`whir_public_performance_north_star_plan.md`](whir_public_performance_north_star_plan.md):
compress the public boundary first, then replace the monolithic linear typed CP
proof with a same-shape structured batched CP relation.

The typed CP audit report now classifies every row into the planned split
architecture components:

- `Leaf`: per-statement FS commitment opening/message checks, GR1CS message
  reconstruction, range/monomial semantics, Ajtai opening validity, and
  original R1CS validity.
- `Accumulator`: CP folding core, root/digest checks, challenge-to-beta
  binding, folded-output derivation, public input/R1CS metadata binding, and
  per-round challenge transcript checks.
- `LeafAccumulatorBinding`: rows that explicitly tie leaf-origin bytes to
  accumulator bodies, such as FS-message/fold-root byte equality.

This classification is profiling only. The product verifier still checks one
authoritative monolithic typed CP proof until the P3/P4 structured batched CP
proof path is implemented.

For the current default `k = 1` public fixture, the split attribution is:

| Planned component | Rows |
|---|---:|
| Leaf | 523,374 |
| Accumulator | 577,117 |
| Leaf/accumulator binding | 15,712 |

The structured batched CP work now has a non-authoritative `SYMBTC1` relation
context for same-shape batches. That context carries the shape id, product
domain size, public statement byte size, witness-oracle row length, and
per-round message-oracle lengths. It deliberately reports zero R1CS
constraints so it cannot be confused with a flattened/appended typed CP R1CS.
There is also a non-authoritative semantic relation description for the next
P4 step. It binds the same shape to typed product-oracle byte ranges, an Ajtai
parameter digest plus indexed Ajtai matrix, an original R1CS matrix digest, the
input bound, and the semantic constraint families that a future WHIR
structured-constraint verifier must enforce: Poseidon digest correctness,
manifest membership, round-message binding, challenge derivation,
challenge-to-beta binding, folded-output derivation, Ajtai opening validity,
original R1CS validity, and active padding policy. WHIR now consumes this
semantic description through a structured block interface. The currently
enabled blocks are manifest membership, challenge-derivation body binding,
challenge-to-beta binding, folded-output accumulator body binding, sampled
Ajtai opening equations, sampled original R1CS equations, round-message
binding, and active padding policy: sampled typed product-oracle byte-equality
constraints bind manifest item
tags/public statements to the typed witness rows; public packed-value
constraints bind the batch challenge body to the public shape, manifest digest,
round-message commitments, WHIR parameter digest, and batch dimensions; another
public packed-value block binds the challenge digest to its canonical base-5
beta ring element; the folded-output block binds each active item's folded
output contribution in the typed witness row to the folded-output accumulator
body, checks that the public `x_folded` copy equals the folded instance
embedded in the item's `FoldedOutputInstance`, and binds that accumulator body
to the public accumulator-root bytes; the same block now duplicates each active
item's `FoldInput` fields in a fold-input
reconstruction body and checks that commitment bytes, public-input bytes, and
GR1CS eval-message bytes agree with the typed witness row, with the eval
message also tied to the corresponding `M_i(T,U_i)` row. The same structured
round-message block now exposes the witness-row FS message ranges and samples
equalities tying those bytes to the corresponding `M_i(T,U_i)` row; FS opening
ranges are also typed in the product-oracle layout. The
`PoseidonDigestCorrectness` block now includes a canonical
`fs-commit` body section with `len(message) || message || opening`, and samples
equalities tying that body back to the witness-row FS message/opening ranges.
For Poseidon2/BabyBear shapes, the product oracle also carries private
Poseidon trace columns for each FS commitment: digest output limbs, canonical
Poseidon input limbs, and the x^7 S-box auxiliary values used by the same
private-digest R1CS gadget as monolithic typed CP. WHIR samples rows from that
Poseidon private-digest R1CS's full row domain and checks `A(z) * B(z) = C(z)`
over opened trace variables, while byte equalities bind the trace output limbs
to the FS commitment bytes. This removes the earlier first/last-row candidate
surface and gives the Poseidon block a proximity-style full-domain challenge
surface, but it is still sampled development coverage rather than complete
authoritative hash proof composition. For
Poseidon2/BabyBear shapes, the product-oracle layout exposes folded
public-input, folded commitment, and folded Hadamard-evaluation algebra offsets,
and a BabyBear-modulus regression checks those offsets directly against the
canonical oracle bytes. The WHIR sampled-opening path now samples those folded
public-input, commitment, and evaluation algebra constraints as part of the
non-authoritative SYMBTC1 proof, but this sampled development coverage is not
counted as semantic authority. Sampled byte
equalities bind `M_i(T,U_i)` round-message rows to
their duplicated digest-body bytes; and active-marker equalities bind each
witness/message/digest-body row to the manifest marker for the same batch item.
The `AjtaiOpeningValidity` block samples original commitment-opening equations
over the indexed Ajtai matrix: for each sampled `(item, original statement,
Ajtai row, ring coefficient)`, WHIR opens the public-input scalars,
original-witness ring coefficients, and commitment coefficient from the product
oracle and checks the BabyBear cyclotomic equation `A_row * [x || w] = c`.
The `OriginalR1csValidity` block samples source-R1CS equations from the same
product oracle: for each sampled `(item, original statement, R1CS row, ring
coefficient)`, WHIR opens assignment coefficients and checks
`(Az) * (Bz) = Cz` over BabyBear, with public inputs interpreted as constant
ring elements. Poseidon digest correctness has sampled full-row-domain R1CS
coverage for FS commitments, Ajtai opening validity has sampled linear opening
coverage, and original R1CS validity now has sampled source-relation coverage,
but this is still sampled development coverage rather than complete
proximity-style semantic authority over the whole committed oracle. Current
product public routing does not consume this batched path.

The P4 candidate has a separate `SYMBTC2` relation context. `SYMBTC2` wraps the
semantic relation with an explicit versioned layout and WHIR treats it as a
full-selection structured candidate: all currently exposed semantic equalities,
public packed-value claims, folded-output algebra equations, Poseidon
private-digest R1CS rows, Ajtai opening equations, and original source-R1CS
equations are selected instead of sampled. The context still reports
`num_constraints = 0` and is still not a flattened/appended typed CP R1CS. This
path is intentionally development-only and currently expensive; it is useful for
auditing coverage and for the `batched_cp_semantic_whir_v2_vs_k` benchmark, but
it is not promoted to product public routing.

There is also a first columnar SYMBTC2 skeleton under the `SYMBT2C` context.
This path commits to a typed semantic table and checks bounded residual openings
for `ActiveOrDummyPolicy`, `ManifestMembership`, `RoundMessageBinding`,
`ChallengeDerivation`, `ChallengeToBetaBinding`, `PoseidonDigestCorrectness`,
`FoldedOutputDerivation`, `AjtaiOpeningValidity`, and
`OriginalR1csValidity` when the selected shape has non-empty constraints for
those families. Equality-style checks use two-column residuals; Poseidon and
original-R1CS checks use product residuals `a * b = c`. This remains a
development-only sampled/proximity candidate and is not promoted to product
public routing. Audit and benchmark tooling can derive a SYMBT2C
private-opening profile that maps proof eval spans back to residual families;
this is used for targeted negative tests and performance reporting only, not as
public verifier input. The default `batched_cp_semantic_columnar_v2_vs_k`
benchmark uses a fast SHA-shaped same-shape CP fixture for this development
profile; Poseidon/BabyBear-specific columnar semantics remain in focused tests
and in the separate `batched_cp_semantic_columnar_poseidon_v2_vs_k` benchmark,
which defaults to `k = 1` and instantiates all nine residual families. The
Poseidon/BabyBear SYMBT2C WHIR proof-profile test passes but is ignored by
default because it is a heavy audit path.

`SYMBT2F` is the family-local columnar successor to the rectangular `SYMBT2C`
baseline. It preserves the same residual equations and exact-byte
Poseidon2/BabyBear semantics, but semantic families now produce one or more
compact labeled tables, each with its own row domain and internal WHIR PCS
subproof. The dominant-domain split partitions `RoundMessageBinding` by CP
round and byte-binding direction, and partitions `FoldedOutputDerivation` into
contribution binding, self-consistency, fold-input reconstruction, and folded
linear/ring-mul equation tables. This reduces the largest local table from
`num_vars = 19` to `num_vars = 17`, while increasing the number of internal
development subproofs.

The message-section shrink further partitions round-message and fold-input
round-message reconstruction equalities by canonical GR1CS message section:
`header`, `hadamard-evals`, `range-payload`, `monomial-payload`,
`square-evals`, `projected-values`, and `trailing-frame`. Any section exceeding
`8192` rows is split into stable chunk tables. This caps the targeted
two-column message equality tables at `num_vars <= 14`; the current overall
maximum is `num_vars = 16`, from manifest membership and folded-output
contribution binding. Benchmark output includes a `family_attribution` profile
that reports subproof count, approximate proof bytes, query proxies, row
counts, and max `num_vars` per semantic family. Current measurements show that
`RoundMessageBinding` and `FoldedOutputDerivation` dominate proof size and
subproof count, so the next P4 performance lever is shared family-level WHIR
verification or multi-proof aggregation, not more blind table splitting. This
is still a development-only, non-authoritative path. Product public
verification still uses the authoritative monolithic typed CP route.

`SYMBT3` is the CP-aware WHIR oracle relation target. It is not a byte/table
proof path: CP round messages `M_i(T,U_i)` are modeled as first-class
committed message oracles, their roots are public CP commitments, and
Fiat-Shamir challenges are derived outside the proven relation. `SYMBT3-I`
extends the first algebraic blocks with a versioned `Symbt3AlgebraLawV1`,
`RqNegacyclicConvolutionV1` product law, `RingCoefficientActionV1` beta
action, a versioned `Symbt3AjtaiLinearAlgebraLayoutV1`, folded Ajtai opening
algebra, source-R1CS residual columns, folded-GR1CS boundary residual columns,
and a direct folded GR1CS product-residual zero-check over public folded `L/R/O`
ring-coordinate chunks. It also adds `Symbt3AjtaiNormRangeLayoutV1` with a
direct development projection/range predicate over the folded Ajtai opening,
and `Symbt3BatchManifestLayoutV1` with typed source/manifest membership
columns. It also adds `Symbt3MessageSemanticLayoutV1`, which treats round
messages as typed algebraic oracle coordinates and binds those coordinates to
the SYMBT3 trace columns consumed by the development folding checks.
`relation_id` binds stable relation metadata plus the
`Symbt3RingModuleLayout`, `AjtaiCommitLayoutV1`,
`Symbt3R1csEvaluatorLayoutV1`, `Symbt3Gr1csResidualLayoutV1`,
`Symbt3AlgebraLawV1`, `Symbt3AjtaiLinearAlgebraLayoutV1`, and
`Symbt3AjtaiNormRangeLayoutV1`, `Symbt3BatchManifestLayoutV1`,
`Symbt3MessageSemanticLayoutV1`, and
`Symbt3FoldedGr1csProductResidualLayoutV1`;
`folding_transcript_digest` binds the input/public boundary, source assignment
roots, source Ajtai opening roots, source commitment boundary, batch manifest
root, message oracle roots, WHIR parameter digest, batch size, and active count
before beta is sampled. Folded/output fields are bound later through
`proof_public_statement_digest`, so they do not change beta.

The WHIR development hook still produces one top-level proof object with no
family-columnar subproofs. It checks q-wrapped ring/module folded commitment
and opening identities plus the sampled folded Ajtai residual
`A * o_fold - c_fold = 0` over the indexed Ajtai evaluator embedded in the
development relation context. It also checks source-R1CS residual columns
computed from setup-bound sparse evaluator metadata and folded-GR1CS boundary
residual columns. `SYMBT3-F` additionally exposes folded GR1CS product columns
under the declared algebra law and checks the Boolean-domain residual
`sum_g eq(g, rho) * sel(g) * (ProductLaw(L,R)(g) - O(g)) = 0` with a degree-3
sumcheck plus final WHIR/PCS openings. The default development profile uses
`RqNegacyclicConvolutionV1` over `R_F = F[X]/(X^D + 1)` in the WHIR check
field. This is a semantic upgrade from D2's field-coordinate product scaffold,
but authority over integer/lattice `R_q` semantics still requires explicit
modulus, range, reduction, zero-knowledge, and soundness treatment.

`SYMBT3-F` proves the Ajtai commitment/opening linear algebra currently
enforced by the single SYMBT3 table: folded openings and folded commitments are
ring-beta linear combinations of the source opening/commitment columns, and
the folded Ajtai map residual `A * f_fold - c_fold = 0` is checked through the
direct development matrix-vector evaluator. `SourceAjtaiMapConsistency` remains
deferred as a separate optional source-opening authority block.

`SYMBT3-J` upgrades the folded Ajtai norm/range layer from the old development
identity projection/direct signed range scaffold to a production-shaped
structured projection plus monomial-embedding range profile. The default
cumulative profile now uses `StructuredBlockProjectionV1` with `{0, +/-1}`
entries, `MonomialEmbeddingRangeV1`, and relation-bound representative policy
metadata. Projection/range/monomial layout digests are bound into the proof
relation and public statement digest; folded opening, projection, and range
data affect proof-checking challenges, but do not affect the input-side folding
beta. This remains a development check-field range path, not final
integer/mod-q lattice range authority.

`SYMBT3-J2` keeps the same default J semantics but compresses deterministic
range-evaluator columns. The monomial witness and representative residual are
now virtual verifier-side consequences of the projected opening/range layout
rather than separately committed table columns. This keeps `k=2` in the
32-column padded table bucket (`num_vars = 17`) while preserving one top-level
WHIR proof, zero family-columnar subproofs, one backend table, and zero
message-to-trace copy bindings.

`SYMBT3-H` adds typed manifest/source-column membership. The first profile
builds a typed manifest row per active batch item with public-input,
source-commitment, source-evaluation, accumulator-boundary, source-Ajtai
commitment, source-assignment-root, and message-root components. The same
single SYMBT3 table opens source and manifest columns and checks their
membership residual; metadata binds the batch manifest root, manifest layout
digest, and source-column layout digest into the input-side challenge path.
This is a typed algebraic/oracle boundary check, not a byte transcript replay.

`SYMBT3-I2` refines CP message semantic validity for the development profile.
The message semantic layout records typed round-message sections plus native
message-oracle view maps. If a trace value is just a typed coordinate of
`M_r(T,U)`, the relation consumes that view directly instead of allocating a
duplicate trace column and proving `Message = Trace` with per-coordinate copy
constraints. The prover still commits message-oracle rows whose roots match the
public CP message roots, and prefix round challenges are still verifier-derived
outside the relation. This remains algebraic/oracle binding, not byte
transcript reconstruction.

`SYMBT3-J` proves only development algebraic consistency, production-shaped
structured projection/range evidence in the WHIR check field, typed
source/manifest membership, and typed message-oracle view binding: it does not
prove full integer/mod-q lattice range authority, production sumcheck
transcript authority, hash-byte construction, FS openings, message digest byte
equality, canonical message-section reconstruction, zero knowledge, or final
production WHIR/Σ-IOP soundness.

`SYMBT3-J` is explicitly `NonAuthoritativeDevelopment` and `NonZkDevelopment`.
`SYMBT3-K` adds `Symbt3AuthorityProfileV1` as a profile gate, not a product
routing change. The profile canonically binds the enabled semantic families,
WHIR parameters, ring/module law, production projection/range/monomial policy,
challenge schedules, Fiat-Shamir domain separators, union-bound accounting,
accepted shape, ZK status, and authority status. The authority verifier gate
intentionally rejects the current SYMBT3-J2 development relation because it is
still base-field/single-check, `NonAuthoritativeDevelopment`, and
`NonZkDevelopment`.

`SYMBT3-K2` adds a second, explicitly research-only gate:
`ResearchAuthorityCandidate`. It allows a SYMBT3-J2 proof to pass an
authority-style semantic check only when the profile says
`SoundnessCandidate`, `NonZkDevelopment`, `ResearchOnly`, and
`product_eligible=false`. This is suitable for benchmarks, paper prototypes,
and internal comparison. It is distinct from `ProductAuthority`, which still
rejects non-ZK profiles, development range/projection modes, missing J2
families, and any profile marked product-ineligible.
The opt-in benchmark
`symbt3_research_vs_product_verify_vs_k` compares product `verify_public` with
`verify_symbt3_research_authority_candidate` side by side. It does not change
product routing and prints `non_zk_research_only=true` in its benchmark log.
Product public verification still uses the authoritative monolithic typed CP
route until `SYMBT3` has all CP algebraic blocks, negative coverage, a
zero-knowledge story, and benchmark data. The first `symbt3_c_vs_k`
architecture benchmark, recorded on 2026-05-06 for `k=1,2`, confirmed the
guard that the development proof has one top-level WHIR proof and zero
family-columnar subproofs. It measured `k=1` at 340,749 proof bytes,
3.6701 ms prove mean, and 4.4679 ms verify mean; `k=2` at 419,997 proof
bytes, 5.5698 ms prove mean, and 6.1235 ms verify mean. These are
development-path architecture numbers, not product public-verifier
performance claims. The first `symbt3_d_vs_k` architecture benchmark, recorded
on 2026-05-07 for `k=1,2`, preserved the same proof-shape guard:
`top_level_whir_proof_count=1` and `family_columnar_subproof_count=0`. It
measured `k=1` at 330,836 proof bytes, 4.7096 ms prove mean, and 5.3228 ms
verify mean; `k=2` at 404,215 proof bytes, 7.0489 ms prove mean, and
7.0847 ms verify mean.
The first `symbt3_d2_vs_k` benchmark preserved the same proof-shape guard while
adding the direct folded GR1CS product-residual sumcheck: `k=1` measured
394,767 proof bytes, 6.2087 ms prove mean, and 6.4224 ms verify mean; `k=2`
measured 401,147 proof bytes, 7.4955 ms prove mean, and 7.2242 ms verify mean.
`SYMBT3-K2a` is implemented as a structural accumulator API only: typed
`Symbt3AccumulatorInstance` / `Symbt3AccumulatorWitness` wrappers exist, the
public statement binds `old_accumulator_digest` and `new_accumulator_digest`,
and the accumulator instance has stable canonical digesting and
`to_public_statement()` conversion. These digests are not part of the folding
beta input-side challenge; they are bound through the public-statement/proof
transcript, and K2b's accumulator-update challenge will bind the old/new
boundary for transition checking. K2a does not add
`AccumulatorTransitionConsistency`, `rho_acc`, or accumulator-transition WHIR
constraints; those remain K2b.
`SYMBT3-K2b` adds `AccumulatorTransitionConsistency` and the domain-separated
`SYMBT3_ACC_TRANSITION` challenge. The transition profile is profile-bound,
and the verifier checks the constant-size accumulator boundary law
`new[i] = rho_acc * old[i] + (1 - rho_acc) * folded_batch[i]` without looping
over batch leaves or manifest rows. Folding beta remains input-side-only.
`SYMBT3-K3` hardens the authority profile gate without promoting SYMBT3 to the
product route. Version `0` remains the existing research authority-candidate
profile; version `1` is the research-only
`AccumulatorSoundnessAuthorityCandidateV1` profile requiring K1 manifest
evaluation, K2 accumulator transition consistency, public-canonical manifest
binding, production-shaped norm/range policy, populated policy digests, and a
union-bound effective soundness floor. ProductAuthority still rejects the
current NonZK profile, and product `verify_public` remains unchanged. The K3
verifier helper is only a profile-gate helper over the existing SYMBT3 public
statement/proof shape.
`SYMBT3-K4` adds the named NonZK research public accumulator API:
`prove_public_symbt3_accumulator_research_non_zk(...)` and
`verify_public_symbt3_accumulator_research_non_zk(...)`. This route takes a
`Symbt3AccumulatorInstance` as the public accumulator boundary, checks
`AccumulatorSoundnessAuthorityCandidateV1` / semantic profile version 1, rejects
`ProductAuthority` and `product_eligible` profiles, converts to the existing
`BatchedCpSymbt3PublicStatement`, and delegates to the same one-proof SYMBT3
WHIR verifier. It is not a zkSNARK, may reveal WHIR-queried private
coordinates, and does not alter product `verify_public`; K6 product route
promotion remains future work.
`SYMBT3-K4.5/K3b` compresses verifier-side source R1CS residual evaluation:
the verifier derives a domain-separated `SYMBT3_SOURCE_R1CS_RESIDUAL_BATCH`
point bound to source assignment boundary, source layout, R1CS evaluator layout,
folded GR1CS boundary, relation/profile statement digest, and WHIR parameters.
The logical `source_r1cs_residual_claims` count remains visible for audit, but
the benchmark/profile counter `source_r1cs_residual_verifier_evaluations` is
`1` for the current nonempty profiles. Proof shape and product routing remain
unchanged.
`SYMBT3-K4.6` compresses the public accumulator boundary bytes used by the K4
research API. `Symbt3AccumulatorInstance::canonical_bytes()` now commits to
expanded batch-item/source/message boundary data by digest (`batch_items_digest`,
`public_source_boundary_digest`, `source_assignment_roots_digest`,
`source_ajtai_opening_roots_digest`, and `message_oracle_roots_digest`) instead
of serializing the expanded vectors directly. The expanded vectors remain
available to the current research prover/dev adapter and are consistency-checked
against those digests before delegation. Product `verify_public` remains
unchanged.
`SYMBT3-K6a` adds an explicit opt-in ProductAuthority NonZK integrity route:
`prove_public_symbt3_accumulator_non_zk_integrity(...)` and
`verify_public_symbt3_accumulator_non_zk_integrity(...)`. This route requires
`ProductProofKind::Symbt3AccumulatorNonZkIntegrity`,
`Symbt3ProductPolicy::Symbt3NonZkIntegrityOptIn`,
`zk_status=NonZkIntegrityOnly`, `product_eligible=true`, semantic profile
version 1, the K3 accumulator-soundness gate, and the K1/K2 proof shape
guards. It rejects research profiles, ZK-required profiles, legacy SYMBT2F /
SYMBT2C / SYMBTC / monolithic proof-kind markers, and failed gates without
falling back to monolithic typed CP. It is product-integrity only, not a
zkSNARK route, and the default monolithic product `verify_public` path remains
unchanged.
`SYMBT3-K6b` adds a side-by-side product route comparison benchmark:
`product_route_comparison_vs_k`. The benchmark joins the current monolithic
typed-CP product route (`public_verify_v2_vs_k`) with the explicit opt-in
SYMBT3 K6a NonZK integrity route (`symbt3_accumulator_authority_vs_k`) and
emits `PRODUCT_COMPARISON_CSV` rows. The monolithic public-byte column is the
compressed public envelope with backend proof payloads omitted; the SYMBT3
public-byte column is `Symbt3AccumulatorInstance::canonical_bytes()`.
The CSV schema is stabilized for cleanup/reporting consumers and includes
verify/prove timing, proof/public byte ratios, and the SYMBT3 shape counters:
one top-level WHIR proof, zero family subproofs, and one backend table.

| k | monolithic verify | SYMBT3 K6a verify | verify speedup | monolithic prove | SYMBT3 prove | prove speedup | monolithic proof bytes | SYMBT3 proof bytes | proof ratio | monolithic public bytes | SYMBT3 public bytes | public ratio | SYMBT3 shape | notes |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 1 | 2,109.052 ms | 17.656 ms | 119.45x | 3,664.787 ms | 17.491 ms | 209.52x | 1,206,465 | 311,568 | 0.258 | 15,171 | 18,715 | 1.234 | 1 WHIR / 0 family / 1 table | one-shot comparison row |
| 2 | 6,232.810 ms | 24.180 ms | 257.77x | 7,519.404 ms | 49.591 ms | 151.63x | 1,256,159 | 335,935 | 0.267 | 15,187 | 18,715 | 1.232 | 1 WHIR / 0 family / 1 table | one-shot comparison row |
| 4 | 13,326.962 ms | 24.348 ms | 547.36x | 23,325.334 ms | 25.078 ms | 930.11x | 1,556,795 | 329,707 | 0.212 | 15,219 | 18,715 | 1.230 | 1 WHIR / 0 family / 1 table | one-shot comparison row |
| 8 | 51,182.449 ms | 30.702 ms | 1,667.09x | 43,438.693 ms | 67.128 ms | 647.10x | 1,613,175 | 387,417 | 0.240 | 15,283 | 18,715 | 1.225 | 1 WHIR / 0 family / 1 table | one-shot comparison row |

K6b is a reporting/regression milestone only. SYMBT3 K6a remains NonZK
integrity only, explicit opt-in, and not the default `verify_public` route. It
does not implement K5 masking and does not support private manifest
membership. Product `verify_public` remains unchanged, and K5/private
manifest/native multi-oracle product work remains deferred.
The SYMBT3 instrumented benchmark baseline (originally tracked as multi-oracle
roadmap Milestone 0) is complete on this branch as the single-oracle K6a
accumulator instrumentation baseline. Multi-oracle WHIR implementation is
intentionally out of scope here and lives on a separate branch. In addition to
the existing `SYMBT3_CSV` rows, `symbt3_accumulator_authority_vs_k` emits
`SYMBT3_INSTRUMENTED_BENCHMARK_JSON` rows and writes stable JSONL to
`benchmarks/symbt3_instrumented_benchmark.jsonl` using schema
`symphony.symbt3.instrumented_benchmark.v1`. The top-level comparison contract
for the multi-oracle branch is: `schema`, `k_table`, `prove_ms`, `verify_ms`,
`proof_bytes`, `public_bytes`, `proof_bytes_by_section`,
`public_bytes_by_section`, `counters`, `verifier_timers`, and
`prover_timers`. Each row records proof-shape counters fixed to one top-level
WHIR proof, zero family subproofs, one backend table, one oracle, and one root,
plus query/Merkle/hash/field-operation estimates and coarse prover/verifier
timers. `scripts/analyze_symbt3_instrumented_benchmark.py` summarizes the JSONL
baseline.
These are benchmark attribution counters only; WHIR payload bytes,
`ProofBundleV2`, `PublicProofBundle`, public proof payload bytes, authority
flags, product `verify_public`, and the explicit K6a NonZK integrity security
boundary are unchanged. Product `verify_public` remains on the authoritative
monolithic WHIR typed-CP route and is expected to pass there; malformed
SYMBT3/K6a profile or proof-kind inputs still fail closed in the explicit
opt-in route.
The first `symbt3_e_vs_k` benchmark preserved the one-proof guard while
switching the default product law to `RqNegacyclicConvolutionV1` and beta action
to `RingCoefficientActionV1`: `k=1` measured 395,418 proof bytes, 6.4393 ms
prove mean, and 7.1004 ms verify mean; `k=2` measured 406,431 proof bytes,
8.2783 ms prove mean, and 7.4959 ms verify mean. These are still
development-path architecture numbers, not product public-verifier performance
claims.
The first `symbt3_f_vs_k` benchmark adds the explicit Ajtai algebra layout while
preserving the one-proof guard: `k=1` measured 407,284 proof bytes, 7.1685 ms
prove mean, and 6.7837 ms verify mean; `k=2` measured 422,389 proof bytes,
8.0666 ms prove mean, and 7.7776 ms verify mean. These are still
development-path architecture numbers, not product public-verifier performance
claims.
The first `symbt3_g_vs_k` benchmark adds the folded Ajtai projection/range
layout while preserving the one-proof guard: `k=1` measured 412,101 proof
bytes, 7.3181 ms prove mean, and 7.1763 ms verify mean; `k=2` measured 416,389
proof bytes, 8.6389 ms prove mean, and 8.0182 ms verify mean. The projection
mode is `DirectDevDenseProjectionV1`, range mode is `DirectSignedRangeDevV1`,
and monomial embedding is disabled. These remain development-path architecture
numbers, not product public-verifier performance claims.
The first `symbt3_h_vs_k` benchmark adds the typed manifest/source membership
layout while preserving the one-proof guard: `k=1` measured 735,652 proof
bytes, 25.906 ms prove mean, and 13.482 ms verify mean; `k=2` measured 801,784
proof bytes, 44.825 ms prove mean, and 19.817 ms verify mean. It reports 7
manifest component kinds and 1 membership challenge; manifest coordinates are
1,218 for `k=1` and 2,436 for `k=2`. These remain development-path
architecture numbers, not product public-verifier performance claims.
The first `symbt3_i_vs_k` benchmark target exposed the over-materialized
message-to-trace copy path: `k=2` measured 1,100,993 proof bytes and
51.712 ms verify mean with 7,856 message-to-trace bindings. `SYMBT3-I2`
replaces that path with native message-oracle views. The `symbt3_i2_vs_k`
benchmark preserves the one-proof guard while reducing message view coordinates
to 6 for `k=1` and 12 for `k=2`, with `message_to_trace_binding_count=0` and
`sumcheck_transition_count=2`. It measured `k=1` at 747,339 proof bytes,
26.364 ms prove mean, and 14.600 ms verify mean; `k=2` at 807,042 proof bytes,
48.393 ms prove mean, and 20.824 ms verify mean. These remain development-path
architecture numbers; the hard guard is still one top-level WHIR proof object
and zero family-columnar subproofs.
The first `symbt3_j_vs_k` benchmark replaces the range scaffold with
structured block projection and monomial-embedding range metadata while
preserving the same proof-shape guard. After the J2 range-column compression it
measured `k=1` at 735,444 proof bytes, 27.255 ms prove mean, and 14.270 ms
verify mean; `k=2` at 801,392 proof bytes, 49.314 ms prove mean, and
20.919 ms verify mean. After the K0/J3 manifest/source-view refactor, the same
`symbt3_j_vs_k` profile keeps per-item source, manifest, and message views out
of the backend table.
`SYMBT3-K1` additionally compresses the research public boundary: the
canonical SYMBT3 development public statement now serializes the manifest root,
layout digests, boundary digests, message roots, and folded output boundary,
but not every active manifest/source coordinate or per-source private root. The
verifier no longer reconstructs the full typed manifest from public data.
K1a adds the root-linking layer for that boundary: `manifest_oracle_root` is
public, `batch_manifest_root` is recomputed as
`H("SYMBT3_MANIFEST", batch_manifest_layout_digest, manifest_oracle_root)`, and
the authority profile binds the selected manifest commitment policy digest.
K1b adds the research `ManifestEvaluationClaim`: the public statement carries a
canonical BabyBear `manifest_eval_claim`, the verifier derives a distinct
`manifest_membership_challenge`, and the one top-level SYMBT3 WHIR proof opens
manifest/source membership columns at that point. Mutating the claim,
manifest-oracle root, manifest layout, source layout, or stale proof data now
rejects.
K1c removes full manifest-row reconstruction from the verifier side of this
membership check: the verifier now streams the canonical source coordinates
from the compressed public statement to derive the source evaluation claim, and
only the prover-side sanity path reconstructs complete manifest rows.
K1 authority also checks that `manifest_oracle_root` is exactly the canonical
manifest root streamed from the public source boundary before any transcript or
claim derivation, so relinking `batch_manifest_root` to an arbitrary manifest
root fails closed without adding a second WHIR proof or
`family_columnar_subproof`.
K1e.2 keeps this manifest binding out of the backend table entirely. The
verifier computes `ManifestView(zeta)` and the matching virtual
`SourceView(zeta)` from compressed public boundary data; no source-view column
or full source-view vector is committed to WHIR. There is no dense
manifest-oracle column, no source-view backend column, no manifest residual
column, no trusted `manifest_eval_claim` fact, and no private manifest witness
component under the `PublicCanonicalManifestViewV1` policy. The SYMBT3 proof
shape remains one top-level WHIR proof, one backend table, and zero family
subproofs.

The 2026-05-10 `k=1,2,4,8,16,32,64` run measured `k=64` at 700,328 proof
bytes, 97.545 ms prove mean, and 16.197 ms verify mean. It reports
`StructuredBlockProjectionV1`, `MonomialEmbeddingRangeV1`, monomial embedding
enabled, projection output length 3, `message_to_trace_binding_count=0`, flat
`opened_field_elements=21`, and flat `public_statement_bytes=10,256` for all
measured `k`. Backend `oracle_len` is 8,192, 8,192, 8,192, 16,384, 32,768,
65,536, 131,072 for `k=1,2,4,8,16,32,64`, so the K0/J3 structural gate passes
with at most 2x growth per k doubling. The generated scaling summary reports
log-log slopes of about 0.223 for verify time, 0.621 for prove time, 0.167 for
proof bytes, 0.000 for public statement bytes, and 0.714 for oracle length.
These are semantic-coverage architecture numbers for the development path, not
product public-verifier performance claims.
SYMBT3-K0/J3 is the current evaluator-succinctness refactor. The first slice
keeps manifest/source membership as a typed root/layout/public-boundary
evaluator check instead of materializing manifest source/value/residual columns
inside the WHIR backend table. The batch manifest root and source-column layout
remain beta-bound input-side data, but `manifest_coordinate_count` no longer
chooses the backend table row domain. The verifier profile now breaks the
combined final evaluator into family buckets:
`verify_final_eval_manifest_ms`, `verify_final_eval_source_r1cs_ms`,
`verify_final_eval_folded_boundary_ms`,
`verify_final_eval_product_residual_ms`, `verify_final_eval_ajtai_ms`,
`verify_final_eval_range_ms`, and `verify_final_eval_message_view_ms`. The
benchmark guard requires the backend oracle length to grow by at most 2x when
`k` doubles. Source R1CS residual compression remains the next K0/J3 target if
the new attribution shows it dominates the final evaluator.
WHIR can now prove and verify a `SYMBTC1` product-domain oracle proof for this
context: one WHIR commitment to the canonical batch oracle and one
transcript-bound opening, plus openings for all verifier-known packed oracle
chunks. Those public chunks cover the oracle domain tags, shape/context bytes,
indices, active markers, inactive padding lengths, round framing,
round-message digest-body framing, manifest digest-body framing, batch
challenge digest-body framing, the concrete public manifest digest, concrete
public round-message commitments, and final length sentinel. This is
deliberately not CP-authoritative yet; it binds the product-domain oracle and
its public framing and enforces sampled byte equality between selected
structured byte ranges, including round-message oracle rows and folded-output
accumulator body contributions, and sampled Poseidon private-digest R1CS rows
for FS commitment traces. It does not enforce the full structured CP predicate
or complete Poseidon hash authority over that oracle. Product public
verification therefore still uses the authoritative monolithic typed CP proof.

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

### Typed output authority

At the public boundary, the WHIR output proof is a transcript-binding proof over
the verifier-visible `FoldedOutputInstance`. The semantic claim that this output
was derived correctly from the original statements is owned by authoritative
typed CP, including FS commitment/message binding, fold replay, challenge digest
binding, beta binding, original Ajtai/R1CS validity, and folded-output
derivation.

### Typed CP status

`CpFieldRelation` is now the software source of truth for the field-native typed
CP relation. It takes `CpPublicStatement` directly, so public inputs and R1CS
dimensions are public data instead of values recovered from a SHA transcript. It
checks scheme-aware FS openings, GR1CS message reconstruction, fold root,
challenge digest, folded output consistency, Ajtai openings, and original R1CS
satisfaction.

This relation is arithmetized inside WHIR. The code has
tested R1CS building blocks for the Poseidon2/BabyBear digest gadget, Ajtai
opening validity, original R1CS satisfaction, exact-byte digest-body packing,
canonical digest-body framing, transcript metadata binding, FS/fold-root public
payload binding, and Hadamard-message prefix reconstruction from CP-R1CS
Hadamard columns. It also constrains the fixed range-proof serialization shape
prefixes when a GR1CS proof is present, reconstructs the range-proof payloads
from structured variables, enforces monomial sumcheck/evaluation semantics,
binds Poseidon-derived challenge outputs to CP-R1CS `beta` columns, and derives
the public folded commitment, public input, and evaluation tensors from those
bound beta values. WHIR direct typed CP setup/prove/verify now uses this full
typed CP R1CS, and public routing selects it because
`has_authoritative_typed_cp()` is true.

Digest-binding checkpoint: the typed CP R1CS layer now has canonical
fixed-shape Poseidon2/BabyBear digest composition for the public CP statement.
It composes the statement wrapper with exact-byte private-input digest gadgets
for:

- FS commitments;
- `fs_root`;
- `fold_root`;
- `challenge_digest`;
- `transcript_seed_digest`.

The public side exposes the serialized eight-limb BabyBear digests, public
inputs, R1CS dimensions, and folded CP instance coordinates. The private side
carries body bytes, byte-decomposition bits, and Poseidon auxiliary values. Each
body byte is 8-bit range constrained, and every private Poseidon absorption
limb is constrained to the exact `digest_core` byte packing:
`"symphony-v2" || len(domain) || domain || len(body) || body`, chunked in
3-byte little-endian BabyBear limbs with the final length sentinel. The witness
encoder checks the setup-derived input lengths and rejects non-canonical
variable-length bodies.

The FS root body is additionally constrained to the verifier-visible FS
commitment limbs, and the digest bodies now constrain internal length prefixes,
R1CS metadata, and static transcript framing. The Hadamard section of the GR1CS
message is no longer arbitrary bytes when the CP-R1CS layout has Hadamard
columns: its serialized evaluations and evaluation matrix are tied directly to
those columns. Range-proof section boundaries and payloads are fixed to the
parsed private proof shape, the monomial range payload has semantic constraints,
and Poseidon-derived challenges are bound to the CP-R1CS `beta` columns through
the documented base-5 byte mapping. The folded output checkpoint adds public
folded-evaluation tensor slots and constrains them to beta-weighted GR1CS
evaluation matrices, complementing the CP-core folded commitment and public
input rows.

Routing checkpoint: typed CP relation descriptions are wired through setup and
cached by the modular and single-backend orchestrators. WHIR advertises
`has_authoritative_typed_cp()`, so public proving and verification use the typed
CP proof path; legacy SHA/full verifier compatibility paths remain available
for non-authoritative backends.

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

## N1bench Native Multi-Oracle WHIR Costs

SYMBT3-N1bench isolates the N1 native multi-oracle WHIR layer from K6a, K6b,
and N6b routing. It adds three benchmark groups:

| Benchmark | Purpose |
| --- | --- |
| `symbt3_native_multi_oracle_vs_oracle_count` | Scales the number of native WHIR oracles at fixed domain size. |
| `symbt3_native_multi_oracle_vs_num_vars` | Scales each oracle domain while keeping native oracle count fixed. |
| `symbt3_native_multi_oracle_batch_axis_vs_k` | Validates the N4b shape where batch size grows inside `num_vars`, not oracle count. |

The current whir-p3 integration exposes one internal PCS opening payload per
native oracle, so `native_oracle_pcs_opening_count` scales with
`native_oracle_count`. This is expected for N1bench and is reported separately
from `family_columnar_subproof_count`, which remains zero. The batch-axis
benchmark validates that batch size can live inside the oracle domain axis,
keeping native oracle count and PCS opening count constant for fixed
`round_count`.

N1bench is an infrastructure benchmark only. It is NonZK, does not implement
K5, does not change product routing, and is not K6a or an N6b full accumulator
benchmark.

## M1a Instrumented Multi-Oracle Benchmark Schema

M1a adds `symbt3_instrumented_multi_oracle`, a JSONL benchmark report for the
native multi-oracle layer itself. Rows are emitted with prefix
`SYMBT3_INSTRUMENTED_MULTI_ORACLE_JSON` to
`benchmarks/symbt3_instrumented_multi_oracle.jsonl` under schema
`symphony.symbt3.instrumented_multi_oracle.v1`.

The current implementation is honestly labeled as a logical compatibility
envelope:

- `native_multi_oracle = false`;
- `logical_envelope = true`;
- `compat_internal_pcs_payloads = true`;
- `whir_instance_count = root_count = logical_oracle_count`;
- `tuple_leaf_layout = "none"`;
- `product_verify_public_allowed = false`.

Future tuple-leaf WHIR can use the reserved shape
`tuple_leaf_layout = "same_domain_tuple_leaf_v1"` only when
`native_multi_oracle = true`, `whir_instance_count = 1`, and `root_count = 1`
are actually true. M1a does not change protocol semantics, K6a/K6b/N6b
routing, product verification, or K5/ZK status.

## M1b Same-Domain RLC Tuple-Leaf Multi-Oracle WHIR

M1b adds the true one-WHIR-instance benchmark/proof shape for same-domain
logical oracles. Because the current whir-p3 API commits to one scalar
evaluation vector rather than vector-valued Merkle leaves, M1b uses an honest
RLC tuple-leaf simulation:

```text
F_tuple(x) = sum_j gamma_j * f_j(x)
```

The verifier-derived `gamma_j` challenges and same-domain opening point `zeta`
are derived independently for each repetition under the domain label
`SYMBT3_RLC_TUPLE_LEAF_PACKING_V1`. The transcript binds the repetition index,
relation id, public statement digest, WHIR parameter digest, ordered logical
oracle descriptor digest, tuple-leaf layout digest, logical oracle count, and
shared `num_vars`. M1b rows are labeled
`tuple_leaf_layout = "same_domain_rlc_tuple_leaf_v1"`, not
`same_domain_tuple_leaf_v1`.

For `logical_oracle_count > 1`, M1b rows must report:

- `native_multi_oracle = true`;
- `logical_envelope = false`;
- `compat_internal_pcs_payloads = false`;
- `whir_instance_count = query_schedule_count = transcript_count = 1`;
- `root_count = native_oracle_pcs_opening_count = 1`;
- `rlc_repetition_count = 4`;
- `rlc_batching_bits_per_repetition = 31`;
- `total_rlc_batching_bits = effective_soundness_bits = 124`;
- `same_domain = same_field = same_rate = same_folding_parameter = true`;
- `product_verify_public_allowed = false`.

M1b only supports same-domain BabyBear logical oracles with identical
`num_vars`, compatible shared schedules, and the same WHIR parameters. Mixed
domains, duplicate/unsorted descriptors, and per-oracle schedules reject. RLC
mode has random-linear-combination collision soundness and carries repeated RLC
soundness counters before any authority use. The repetitions reuse the same
tuple-leaf root and one WHIR proof; `packed_eval_claims` grows with repetition
count, not `root_count` or `whir_instance_count`.

M1b is a dev benchmark/proof path only. It does not replace the M1a
compatibility-envelope rows, change product `verify_public`, alter K6a/K6b/N6b
behavior, implement K5/ZK, or claim privacy.

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

K6a remains the existing explicit `PublicCanonicalManifestViewV1` route. K5
masking remains required for any ZK claim.

## N6a Integrated Native Folding-Integrity Proof

SYMBT3-N6a adds `Symbt3NativeFoldingIntegrityProof`, an additive wrapper around
the existing WHIR proof and one N1 native multi-oracle envelope. The wrapper
contains the main SYMBT3 WHIR proof, native manifest/source openings, native CP
round-message openings, counters, and
`native_folding_integrity_binding_digest(...)`.

The N6a smoke shape is:

- one main WHIR proof;
- one logical native-oracle envelope;
- manifest/source oracle count `= 2`;
- native message oracle count `= round_count`;
- total native oracle and PCS opening count `= 2 + round_count`;
- `family_columnar_subproof_count = 0`;
- `message_to_trace_binding_count = 0`;
- one accumulator transition claim.

The verifier requires the N5 native NonZK folding-integrity gate, recomputes the
public statement and binding digests, verifies the main WHIR proof, verifies the
combined native envelope, checks manifest/source equality, and checks the N4b
round-message prefix challenge schedule. N2 and N4 claims are in one native
envelope ordered by oracle id (`1`, `2`, then `1000 + round`).

N6a is still NonZK and development/infrastructure only. It does not change
product `verify_public`, does not alter K6a, does not add byte transcript
reconstruction, does not implement K5/masking, and does not make a privacy
claim for committed-private data. N6b, below, adds the explicit opt-in native
route before any product-default promotion.

## N6b Explicit Native NonZK Public Route

SYMBT3-N6b adds an explicit opt-in public route for the N6a wrapper. The route
uses `Symbt3NativeFoldingProofKind::Symbt3NativeNonZkFoldingIntegrityV1` and the
public helpers:

- `prove_public_symbt3_native_folding_integrity_non_zk`;
- `verify_public_symbt3_native_folding_integrity_non_zk`;
- `Symbt3NativeFoldingIntegrityPublicProfile`;
- `Symbt3NativeFoldingIntegrityRouteStatus`.

The public verifier dispatches only on the native proof kind and requires the
explicit native NonZK or research-only route status. It still requires the N5
gate, `CanonicalWhirRootV1`, native manifest/source policies, native round
message policies, valid wrapper binding, a verified main WHIR proof, a verified
native envelope, and the native-oracle counters
`native_oracle_count = native_oracle_pcs_opening_count = 2 + round_count`.

K6a separation is explicit: `PublicCanonicalManifestViewV1` / K6a proof-kind
discriminators do not verify as N6b, and an N6b proof-kind discriminator does
not verify as K6a or monolithic typed CP. N6b is still not the default
`verify_public` route, does not implement K5/ZK masking, does not claim privacy,
and never falls back to a monolithic proof. N7 may consider default-route
candidacy only after a broader negative matrix and benchmark review.

## K6a vs N6b Route Distinction

K6b real product comparison:

| Route | Benchmark | Scope |
| --- | --- | --- |
| Public product verifier | `public_verify_v2_vs_k` | Real product public-verifier comparison target. |
| K6a | K6a public-canonical accumulator benchmark | Explicit `PublicCanonicalManifestViewV1` full accumulator NonZK integrity route. |

N6c route matrix:

| Route | Benchmark label | Scope |
| --- | --- | --- |
| typed CP smoke | `typed_cp_smoke` | Standalone typed CP smoke baseline, not `public_verify_v2`. |
| K6a | `k6a=full_accumulator_public_canonical` | Explicit public-canonical full accumulator workload. |
| N6b | `n6b=native_oracle_smoke_not_full_accumulator` | Explicit native-oracle folding-integrity route boundary and smoke profile. |

N6c route matrix is for route-shape comparison; it is not the heavy monolithic
product benchmark unless explicitly using public_verify_v2.

K6a remains the current full accumulator NonZK integrity route. N6b proves the
native manifest/source/message oracle envelope binding and route separation, but
the current smoke benchmark must not be read as a full K6a workload replacement.
Neither K6a nor N6b is ZK, neither is default `verify_public`, and typed CP smoke
does not replace the compatibility/product-authoritative baseline.

## N7 Native Accumulator Authority Smoke Route

SYMBT3-N7 currently exposes a native NonZK accumulator-authority smoke profile:
`prove_symbt3_native_accumulator_authority_non_zk` and
`verify_symbt3_native_accumulator_authority_non_zk`. This is explicitly
`workload_kind = N7SmokeProfileV1`, with
`full_accumulator_workload = false` and `smoke_profile = true`. It is not the
full K6a accumulator workload.

The proof wrapper is `Symbt3NativeAccumulatorAuthorityProof`; it binds a tiny
synthetic main WHIR proof to the M1b `same_domain_rlc_tuple_leaf_v1`
multi-oracle proof with `native_accumulator_authority_binding_digest`.

The native side is RLC tuple-leaf, not true vector tuple leaves. The expected
shape is:

- `native_multi_oracle = true`;
- `tuple_leaf_layout = same_domain_rlc_tuple_leaf_v1`;
- `whir_instance_count = root_count = query_schedule_count = transcript_count = 1`;
- `native_oracle_pcs_opening_count = 1`;
- `logical_oracle_count = 2 + round_count`;
- `family_columnar_subproof_count = 0`.

N7 uses `profile_meets_native_accumulator_authority` to require canonical WHIR
roots, native manifest/source policies, native round-message oracles, NonZK
status, production semantic families, accumulator transition consistency, and
RLC batching soundness bits in the profile. The route rejects
`PublicCanonicalManifestViewV1`, digest-only message roots, `DebugDevelopmentOnly`,
compatibility-envelope shapes, monolithic fallback, K6a proof kinds, and
`ZkRequired` without K5.

The benchmark is `symbt3_native_accumulator_authority_vs_k` and emits
`NATIVE_ACCUMULATOR_AUTHORITY_SMOKE_CSV` plus the explicit note:
"N7 smoke profile, not full accumulator workload". It is still not default
`verify_public`. N7 is NonZK only, not privacy-preserving, uses RLC tuple-leaf
batching rather than vector tuple leaves, and leaves K5 masking deferred.

## N7b Full Workload Status

SYMBT3-N7b is reserved for
`Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1`. The full route
must integrate the native RLC tuple-leaf multi-oracle envelope with the real K6a
accumulator WHIR relation and repeated RLC soundness accounting. A typed K6a
native workload adapter now extracts the K6a profile digest, accumulator
instance digest, public statement digest, WHIR parameter digest, relation id,
main proof digest, old/new accumulator digests, batch manifest root,
manifest/message roots, and batch counters from verified K6a objects. The full
wrapper now composes those adapter fields with M1b tuple-leaf proof/profile
parts and builds the full N7b binding digest. M1b now carries repeated RLC
tuple-leaf proof evidence, and the wrapper gate advances past
`RepeatedRlcSoundnessMissingOrWeak` only when that evidence verifies. The
product-facing helpers `prove_symbt3_native_accumulator_authority_full_non_zk`
and `verify_symbt3_native_accumulator_authority_full_non_zk` are wired through
the K6a adapter, repeated-RLC tuple-leaf proof, and wrapper verifier. They still
fail closed for smoke, missing components, stale components, fallback use, or
weak RLC evidence.

The full-profile gate `profile_meets_native_accumulator_authority_full` rejects
`smoke_profile = true`, requires `full_accumulator_workload = true`, requires
`workload_kind = FullK6aAccumulatorV1`, and requires at least four RLC
repetitions with sufficient total/effective soundness before a full authority
claim can be reported. The wrapper also rejects missing tuple-leaf parts,
binding mismatches, fallback use, family subproofs, and stale K6a adapter/proof
matches. The current M1b
tuple-leaf route is RLC batching, not true vector tuple leaves. It is not
privacy-preserving, K5 remains deferred, default `verify_public` remains
unchanged, and external cryptographic review is still required before any
production claim.

N7b canonical proof serialization stores the tuple-leaf WHIR PCS proof with the
compact canonical payload `WHIR_PCS_COMPACT_JSON_CBOR_V1`. The full helper's
`proof_bytes` counter is therefore the actual canonical N7b proof byte length,
not a compact-size estimate or size hint. A serialization regression test
requires the reported section total to equal the actual canonical byte length
exactly and rebuilds a proof from the decoded compact PCS payload before
running the full verifier.

Latest local `symbt3_native_accumulator_authority_full_vs_k` rows:

| k | prove ms | verify ms | proof bytes | tuple-leaf native proof | legacy tuple PCS JSON | compact tuple PCS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 34.214 | 33.697 | 722,833 | 376,857 | 738,035 | 373,364 |
| 2 | 42.467 | 35.658 | 742,230 | 406,327 | 799,038 | 402,834 |
| 4 | 58.223 | 42.941 | 768,420 | 431,087 | 850,049 | 427,594 |

The remaining proof-size bottleneck is verifier-needed MMCS opening material in
the tuple-leaf PCS proof: Merkle authentication paths and opened query values.
Whole Merkle proof payloads and opened-value payloads were not duplicated in the
measured rows, so the next reduction requires a shared/batched MMCS opening
representation rather than another metadata-only encoding.

## N8 Integrated K6a Native WHIR Prototype

SYMBT3-N8 is the planned non-additive successor to N7b. The target shape is one
WHIR proof whose relation includes the K6a accumulator constraints, the native
tuple-leaf repeated-RLC constraints, and the accumulator transition/binding
link. The repository now has a strict real integrated claim-row evaluator,
committed-table layout builder, K6a verifier-facing semantic rows, tuple-RLC
semantic rows, and transition/binding semantic rows:

- `IntegratedK6aNativeClaimPlanV1`;
- `IntegratedK6aNativeCommittedTableV1`;
- `N8IntegratedK6aSemanticConstraintsV1`;
- `N8IntegratedTupleRlcSemanticConstraintsV1`;
- `N8IntegratedTransitionBindingSemanticConstraintsV1`;
- `N8IntegratedSemanticCompletionFlagsV1`;
- `N8SemanticBatchingV1`;
- `N8K6aSourceRowBatchingV1`;
- `RealIntegratedK6aNativeEvaluatorV1`;
- `Symbt3IntegratedK6aNativeWhirRelationV1`;
- `Symbt3N8IntegratedConstraintDescriptor`;
- `N8IntegratedWhirProofInputs`;
- `N8IntegratedWhirProofPlan`;
- `build_integrated_k6a_native_claim_plan_v1`;
- `build_integrated_k6a_native_committed_table_v1`;
- `build_n8_semantic_inputs_from_k6a_witness`;
- `build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor`;
- `build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_from_semantic_inputs`;
- `build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_with_k6a_semantics`;
- `build_n8_integrated_whir_proof_plan`;
- `prove_symbt3_n8_integrated_whir_non_zk`;
- `verify_symbt3_n8_integrated_whir_non_zk`;
- `verify_symbt3_n8_integrated_k6a_native_whir_relation_gate`.

N8 is now also exposed through a first-class NonZK accumulation API:

```text
ACC.P(batch, old_accumulator, witness) -> (new_accumulator, proof)
ACC.V(public_batch, old_accumulator_public, new_accumulator_public, proof)
    -> accept/reject
```

The typed API separates `Symbt3AccumulatorObject`,
`Symbt3AccumulatorPublicInstance`, `Symbt3AccumulatorWitness`,
`Symbt3AccumulationBatch`, `Symbt3AccumulationProof`, and
`Symbt3AccumulationVerificationReport`. `accumulate_symbt3_n8_non_zk` derives
the new accumulator object from the public batch and old accumulator, builds the
existing N8 integrated descriptor/proof, and returns the object plus proof.
`verify_symbt3_n8_accumulation_non_zk` recomputes the public accumulator
context and calls the audited N8 authority-candidate verifier/backend path. The
proof binds the old and new accumulator digests, batch size, active count,
public statement digest, accumulator instance digest, K6a/N8 relation digests,
tuple root/layout/native descriptor/message-root digests, table/claim-plan
digests, and semantic completion flags.

`Symbt3AccumulatorPublicInstance` is a role-neutral accumulator state object:
its `accumulator_digest` is the Poseidon2/BabyBear `state` coordinate digest.
The public statement and `Symbt3AccumulationProof` continue to bind the
role-specific `old` and `new` coordinate digests used by the K6a/N8 transition
relation. This lets the `new_accumulator` returned by one successful call be
used directly as the `old_accumulator` of the next call while preserving the
old/new digest checks inside each transition proof.

The accumulation API audit tests cover `acc0 -> acc1 -> acc2`, independent
verification of both transitions, replay/swaps across batches and old/new
accumulators, malformed public accumulators, proof old/new digest mutation,
empty public-batch rejection, active-count and batch-size mismatch rejection,
and honest `k = 1, 2, 4`. Empty prover batches remain unsupported at the
underlying batch-shape construction boundary. The verifier accepts only the real
integrated N8 output: N7b proof material, synthetic N8 output, split delegation
material, N7 smoke proof material, and the default K6a product proof all reject
when presented through the N8 accumulation verifier.

This API is a research authority-candidate wrapper around the existing N8
integrated NonZK proof. It is not production authority, does not implement
K5/ZK masking, does not make a privacy claim, does not accept N7b/split
delegation as N8, and leaves default `verify_public` unchanged.

The planner records `integrated_num_vars = max(k6a_num_vars,
tuple_packed_num_vars)`, the deterministic K6a zero-extension policy, the
tuple-leaf repetition axis appended after the logical axes, and combined logical
oracle, constraint, and claim descriptors. The descriptor also records real K6a
verifier opening/evaluation rows extracted directly from the accumulator
witness/public claim plan, K6a semantic rows derived through
`symbt3_c_table_and_claims(...)`, tuple packed and logical repeated-RLC claim
rows, per-repetition tuple RLC residual rows, representative deterministic
padding rows, and accumulator transition/binding semantic rows. The old
source-proof extraction path is retained only as a test/reference path and is
checked for row equivalence. Those transition rows bind the old/new
accumulator digests, accumulator instance and public statement digests, K6a
semantic source digest, tuple root/layout digests, native descriptor/message
roots digest, manifest/source/batch roots, batch size, active count, workload
kind, and N8 plan/table/layout digests. The
transcript binds the K6a relation id and public statement digest, K6a semantic
descriptor digest, tuple-leaf descriptor/layout digest, RLC repetition metadata,
integrated shape, padding policy, evaluator digests, transition semantic
descriptor digest, semantic completion flags, and workload kind under
`SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_V1`.

The table builder records the single integrated oracle layout for a future
one-WHIR proof. It maps K6a source rows into the integrated domain, records K6a
zero-padding rows from the planner policy, maps tuple-leaf repeated-RLC rows
into the same integrated domain, and records axis ownership for K6a source
axes, K6a padding axes, tuple logical axes, tuple repetition axes, and tuple
integrated-padding axes. It emits deterministic `layout_digest` and
`table_digest` values plus counters for `integrated_num_vars`,
`integrated_oracle_len`, `k6a_padded_rows`, `tuple_rows`, and
`combined_constraint_count`. It introduces no WHIR root or proof.

The current bridge representation is same-domain multiple logical columns. K6a
and tuple-leaf rows/axes overlap in the integrated domain because they are
separate logical columns in the future one-WHIR relation. Treating the same
layout as one scalar oracle with selector-gated regions is ambiguous and is
rejected. `N8IntegratedWhirProofPlan` builds bridge descriptors for K6a
accumulator constraints, native tuple-leaf repeated-RLC constraints, and the
accumulator transition/binding link. Its transcript binds those descriptors,
the table/layout digests, `integrated_num_vars`, the workload kind, and
`N8SemanticBatchingV1`. Semantic batching binds the descriptor transcript,
claim/table/evaluator digests, the K6a source-row descriptor, and the three
semantic row-family descriptors before deriving separate source, K6a semantic,
tuple-RLC, and transition/binding challenge points.

N8 remains research prototype only and makes no production authority or
performance claim. The product gate now accepts descriptor, plan,
committed-table, representation, evaluator, claim-bridge, K6a semantic
descriptor/row consistency, tuple-leaf repeated-RLC semantic descriptor/row
consistency, and transition/binding semantic descriptor/row consistency only
when all three semantic completion flags are true.
`k6a_semantics_complete=true` is set only for descriptors carrying the real
K6a semantic rows; `tuple_rlc_semantics_complete=true` is set only for
descriptors carrying the real tuple-RLC rows; and
`transition_semantics_complete=true` is set only when the integrated
transition/binding semantic rows are present and checked. Missing flags,
synthetic backend proofs, split delegation material, N7b proof-as-N8 shapes,
fallback smoke proofs, and family subproofs remain rejected. The low-level
prover entry point now emits a single real WHIR PCS proof over the real
integrated evaluator, with mode `RealIntegratedK6aNativeEvaluatorV1`; this is
a NonZK research authority-candidate path, not production authority. A separate
`SyntheticNonAuthoritativeV1` backend-plumbing prover remains available for
shape tests and is rejected by the N8 authority gate. The verifier-side backend
shape is explicit:
`verify_symbt3_integrated_whir_backend_from_verifier_input` consumes an
`N8IntegratedWhirVerifierInput` with one integrated descriptor/plan/table
digest set, combined bridge descriptors, exactly one WHIR root/proof, and one
`N8IntegratedWhirQueryScheduleV1`. It wraps the existing
`whir_verify_opening_multi` PCS verifier over `integrated_num_vars`. The
schedule opens one domain-separated K6a source-row batch plus three
domain-separated semantic batch openings for K6a semantic rows, tuple-RLC rows,
and transition/binding rows. `N8K6aSourceRowBatchingV1` binds the 52 K6a
source rows before sampling that source batching point; those rows break down
as 15 verifier opening rows, 3 final residual rows, 1 `z_eval` row, 32
product-sumcheck coefficient rows, and 1 deterministic padding row. It rejects
missing schedules, num-var mismatches, root mismatches, extra proof material,
split K6a+tuple material, and real-mode
schedule values that do not match the descriptor's evaluator rows and semantic
batching descriptor.

Local feasibility is partial. The field, root policy, WHIR security mode, rate,
and folding counters are compatible, and the planner now normalizes the K6a and
tuple-leaf shapes to one future WHIR domain. Current production APIs still
verify K6a and tuple-leaf claims through two independent
`whir_verify_opening_multi` calls. The current N8 K6a semantic slice covers the
verifier-facing public/opening claims, final residual-zero checks, `z_eval`
binding, product-sumcheck acceptance, and deterministic K6a padding zero row
from the same `symbt3_c_table_and_claims(...)` path used by K6a verification,
without first constructing a full K6a source proof in the direct N8 prover path.
The current N8 tuple-RLC semantic slice covers repeated gamma/zeta derivation,
logical oracle order, packed/logical claim digests, residual-zero rows, padding
rows, and the one-WHIR/no-tuple-PCS shape. The current N8 transition semantic
slice covers the accumulator digest transition and the binding of the
accumulator instance, public statement, K6a semantic source digest, tuple root/layout,
native descriptor/message roots, manifest/source/batch roots, batch size,
active count, workload kind, and N8 plan/table/layout digests into the
integrated relation. The remaining blockers are review, audit, and
productionization of the complete integrated relation.

The benchmark target `symbt3_n8_integrated_authority_vs_k` emits
`N8_INTEGRATED_AUTHORITY_CSV` rows for the N8 one-WHIR NonZK research
authority-candidate path. Rows are emitted only after the audited
authority-candidate gate accepts; failures are emitted as `BLOCKED` rows with a
reason. The `proof_bytes` column is the actual serialized N8 output payload
containing the plan, root, one WHIR proof, query schedule, and counters. The
same target also emits `N8_INTEGRATED_OPENING_BREAKDOWN_CSV` rows and
`N8_K6A_SOURCE_ROW_BREAKDOWN_CSV` rows. After source-row batching the audited
opening surface is four PCS openings total: one K6a source batch plus the three
semantic family batches. `N8_INTEGRATED_TIMER_CSV` rows separate direct K6a
claim extraction, tuple-RLC input construction, descriptor/table construction,
semantic row construction, WHIR proving, WHIR verification, query-opening
verification, and authority-gate time.

The feasibility API boundary is now named explicitly:
`prove_symbt3_integrated_whir_from_claim_plan`,
`verify_symbt3_integrated_whir_from_claim_plan`, and the lower-level verifier
backend `verify_symbt3_integrated_whir_backend_from_verifier_input`. The prover
uses `whir_commit_and_prove_multi` once and returns one root, one WHIR proof,
one query schedule, and counters with no tuple PCS proof or split delegation.
N8 remains a NonZK research authority-candidate path pending review and
productionization; it is not production authority.

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
- `ciborium` — Compact canonical tuple-leaf PCS payload encoding for N7b proof bytes.
- `rand` — `ChaCha20Rng` for deterministic Poseidon2 permutation seeding.

All Plonky3 crates are pinned to revision `b0fa5139`.
