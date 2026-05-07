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
Fiat-Shamir challenges are derived outside the proven relation. `SYMBT3-G`
extends the first algebraic blocks with a versioned `Symbt3AlgebraLawV1`,
`RqNegacyclicConvolutionV1` product law, `RingCoefficientActionV1` beta
action, a versioned `Symbt3AjtaiLinearAlgebraLayoutV1`, folded Ajtai opening
algebra, source-R1CS residual columns, folded-GR1CS boundary residual columns,
and a direct folded GR1CS product-residual zero-check over public folded `L/R/O`
ring-coordinate chunks. It also adds `Symbt3AjtaiNormRangeLayoutV1` with a
direct development projection/range predicate over the folded Ajtai opening.
`relation_id` binds stable relation metadata plus the
`Symbt3RingModuleLayout`, `AjtaiCommitLayoutV1`,
`Symbt3R1csEvaluatorLayoutV1`, `Symbt3Gr1csResidualLayoutV1`,
`Symbt3AlgebraLawV1`, `Symbt3AjtaiLinearAlgebraLayoutV1`, and
`Symbt3AjtaiNormRangeLayoutV1`, and
`Symbt3FoldedGr1csProductResidualLayoutV1`;
`folding_transcript_digest` binds the input/public boundary, source assignment
roots, source Ajtai opening roots, source commitment boundary, message oracle
roots, WHIR parameter digest, batch size, and active count before beta is
sampled. Folded/output fields are bound later through
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

`SYMBT3-G` adds development low-norm/range evidence for the folded Ajtai
opening. The first profile uses `DirectDevDenseProjectionV1`, which projects
`flatten(f_fold)` by the identity development evaluator, and
`DirectSignedRangeDevV1`, which checks the projected coefficients against the
declared signed bound inside the same single SYMBT3 table. Monomial embedding
range authority is not enabled yet.

`SYMBT3-G` proves only development algebraic consistency and a development
check-field range predicate: it does not prove full integer/mod-q lattice range
authority, manifest membership, CP message semantic validity, hash-byte
construction, FS openings, message digest byte equality, canonical
message-section reconstruction, zero knowledge, or final production WHIR/Σ-IOP
soundness.

`SYMBT3-G` is explicitly `NonAuthoritativeDevelopment` and `NonZkDevelopment`.
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
- `rand` — `ChaCha20Rng` for deterministic Poseidon2 permutation seeding.

All Plonky3 crates are pinned to revision `b0fa5139`.
