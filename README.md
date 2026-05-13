# Symphony

**Scalable lattice-based SNARKs via high-arity folding — no hash-in-circuit overhead.**

Symphony is a Rust implementation of the folding-based SNARK construction from
[*"Symphony: Scalable SNARKs in the Random Oracle Model from Lattice-Based High-Arity Folding"*](https://eprint.iacr.org/2025/) (Binyi Chen, Stanford, 2025).

It replaces Merkle-tree commitments and hash-in-circuit gadgets with **module-Ajtai lattice commitments** and a **commit-and-prove compiler** that never embeds Fiat-Shamir hashes into the proven statement.

## Current status

- Core Symphony pipeline is implemented end-to-end in Rust.
- Standalone CP-SNARK module is implemented (`src/cp_snark/mod.rs`).
- Backend SNARK is pluggable through `BackendSnark` (demo backends: `DummySnark`, `SumcheckSnark`; concrete backends: `SpartanSnark`, `WhirSnark`).
- **WHIR backend** (feature-gated `whir`): post-quantum SNARK using WHIR PCS (Merkle-based polynomial commitments) from [whir-p3](https://github.com/tcoratger/whir-p3) / Plonky3 over BabyBear. Succinct proofs via Poseidon2-based Merkle commitment + opening — no witness table in proof.
- **Spartan backend**: R1CS-to-sumcheck reduction with Pedersen commitments and IPA over Ristretto (curve25519-dalek).
- **Privacy-preserving v2 proof boundary**: `SymphonyProofV2` carries only backend proofs, public Fiat-Shamir commitments/digests, and the folded output instance. Public-only verification fails closed unless a backend advertises authoritative typed CP and output support. WHIR typed output is authoritative for the final folded R1CS statement; WHIR typed CP remains the open security milestone.
- **Field-native typed CP specification**: `CpFieldRelation` defines the Poseidon2/BabyBear-friendly CP checks that WHIR must eventually prove, without proving SHA-256 inside WHIR.
- **Modular CP pipeline** (`src/modular/`): backend-agnostic, split-backend prover/verifier architecture with `ModularProver`/`ModularVerifier` and `ProofBundle` / `ProofBundleV2`, decoupling transcript, digest, folding, and backend concerns into reusable components.
- Audit-driven robustness fixes are integrated across ring/FS/folding/ROK/sumcheck layers.
- Integration test suite is split into focused files for maintainability and debugging.

## Key properties

- **No hash-in-circuit** — the SNARK statement is free of random-oracle evaluations, eliminating the dominant cost in existing folding schemes.
- **Plausibly post-quantum core** — the folding and commitment layers rely on Module-SIS over cyclotomic rings; the WHIR backend uses hash-based polynomial commitments.
- **Streaming prover** — memory-efficient, multi-pass prover architecture.
- **High-arity folding** — folds an arbitrary number of R1CS statements in a single shot (not binary).
- **Pluggable backend** — the final proof system is abstracted behind a `BackendSnark` trait. Included: `SpartanSnark` (Ristretto/IPA) and `WhirSnark` (post-quantum, Merkle/Plonky3). Swap in LaBRADOR, HyperPlonk+KZG, or your own.

## Architecture

```
symphony/
├── src/
│   ├── ring/              # Rq = Zq[X]/<X^64+1> arithmetic, NTT, extension field K = Fq^2, tensor E = K⊗Rq
│   ├── commitment/        # Module-Ajtai commitment: commit, strict/relaxed/fine-grained opening
│   │   ├── mod.rs         #   Core commitment logic
│   │   ├── params.rs      #   Commitment parameter sets
│   │   └── opening.rs     #   Strict/relaxed/fine-grained opening modes
│   ├── decomposition/     # Gadget decomposition and monomial embedding (exp map, table polynomial)
│   ├── sumcheck/          # Interactive sumcheck prover + verifier over K
│   ├── rok/               # Reductions of Knowledge
│   │   ├── hadamard.rs    #   Πhad: Hadamard relation → linear relation
│   │   ├── monomial.rs    #   Πmon: monomial check via degree-4 sumcheck
│   │   ├── range_proof.rs #   Πrg:  approximate range proof (projection + Πmon)
│   │   └── gr1cs.rs       #   Πgr1cs: single-instance R1CS reduction (Πhad + Πrg)
│   ├── folding/           # High-arity folding
│   │   ├── mod.rs         #   Πfold: fold ℓ_np statements into one
│   │   ├── streaming.rs   #   Memory-efficient streaming prover
│   │   ├── two_layer.rs   #   Two-layer extension for very large statement counts
│   │   ├── challenge.rs   #   Folding challenge set S ⊂ Rq
│   │   └── digest.rs      #   Fold-root digest computation
│   ├── r1cs/              # Sparse R1CS matrices, generalized committed R1CS, Kronecker expansion
│   ├── fiat_shamir/       # SHA-256 transcript + HashCommitment FS commitment scheme
│   ├── snark/             # Top-level SNARK pipeline
│   │   ├── mod.rs         #   BackendSnark trait, SymphonyProver/Verifier, SymphonyProof/V2, DummySnark
│   │   ├── prover.rs      #   Full proof generation orchestration
│   │   ├── cp_snark.rs    #   Commit-and-prove encoding helpers and CP R1CS exports
│   │   ├── cp_snark/      #   CP instance/witness encoding and CP R1CS layout
│   │   │   └── typed_r1cs/ #  Typed CP R1CS layout, Poseidon, constraints, witness, tests
│   │   ├── sumcheck_snark.rs # Sumcheck-backed demo backend (consistency/soundness checks)
│   │   ├── spartan/       #   Spartan backend (R1CS-to-sumcheck + Pedersen + IPA)
│   │   │   ├── mod.rs     #     SpartanSnark implementing BackendSnark
│   │   │   ├── commitment.rs # Pedersen vector commitment
│   │   │   ├── ipa.rs     #     Inner Product Argument (Bulletproofs-style)
│   │   │   ├── r1cs_sumcheck.rs # R1CS-to-sumcheck reduction over Fp
│   │   │   ├── scalar_field.rs  # Ristretto scalar field ops
│   │   │   ├── serialize.rs     # SpartanContext serialization
│   │   │   └── sumcheck.rs      # Sumcheck over Fp
│   │   └── whir/          #   WHIR backend (feature-gated, post-quantum PCS)
│   │       ├── mod.rs     #     Module root / orchestration facade
│   │       ├── backend_impl.rs # BackendSnark impl and typed CP/output routing
│   │       ├── batched_cp_columnar.rs # Batched CP columnar proof checks
│   │       ├── batched_cp_context.rs # Batched CP relation context decoding
│   │       ├── core_protocol.rs # WHIR PCS, CP, sumcheck, and MLE helpers
│   │       ├── output.rs   #     Typed output proof helpers
│   │       ├── symbt3_columns.rs # SYMBT3 algebraic columns and claims
│   │       ├── symbt3_verify.rs # SYMBT3 verifier profile checks
│   │       ├── field.rs   #     BabyBear byte packing and i64 field conversions
│   │       └── serialize.rs #   WhirContext serialization
│   ├── cp_snark/          # Standalone commit-and-prove SNARK API (generic over backend + FS commitment)
│   ├── modular/           # Reusable modular CP pipeline components
│   │   ├── batched_cp/        # Structured batched CP and SYMBT3 split sections
│   │   ├── transcript_core/   # Canonical transcript schema/codec and challenge derivation
│   │   ├── digest_core/       # Digest/root helpers for transcript and fold bindings
│   │   ├── folding_core/      # Folding-domain traits and adapters
│   │   ├── cp_relation_core/  # CP public/witness model and relation checks
│   │   ├── cp_backend_api/    # CP backend trait abstraction
│   │   ├── output_backend_api/# Output backend trait abstraction
│   │   ├── proof_orchestrator/# End-to-end split-backend prover/verifier (ModularProver/Verifier)
│   │   └── adapter_symphony/  # Compatibility mapping with legacy SymphonyProof
│   ├── params.rs          # Global parameters (Table 1 of the paper)
│   └── lib.rs             # Crate root and public exports
├── tests/
│   ├── ring.rs            # Ring + extension field + NTT + tensor tests
│   ├── commitment.rs      # Module-Ajtai commitment tests
│   ├── decomposition.rs   # Gadget decomposition + monomial embedding tests
│   ├── fiat_shamir.rs     # Transcript and challenge derivation tests
│   ├── sumcheck.rs        # Sumcheck + eq polynomial tests
│   ├── rok.rs             # Πhad / Πmon / Πrg / Πgr1cs tests
│   ├── r1cs.rs            # R1CS and conversion tests
│   ├── generalized_r1cs.rs # Generalized R1CS tests
│   ├── folding.rs         # Folding, streaming, and two-layer tests
│   ├── snark.rs           # Full Symphony pipeline tests
│   ├── cp_snark.rs        # Standalone CP-SNARK tests
│   ├── hash_commitment.rs # Hash-based commitment verification tests
│   ├── modular_cp_pipeline.rs # Modular pipeline component tests
│   ├── security_soundness.rs  # Tamper/replay/splice attack detection tests
│   └── common/mod.rs      # Shared integration test helpers
├── benches/
│   ├── folding.rs         # Folding scaling benchmarks with heap tracking and CSV reporting
│   ├── cp_succinct.rs     # CP-SNARK and output proof succinctness benchmarks
│   └── whir_scaling.rs    # WHIR backend scaling benchmark (requires feature = "whir")
└── docs/
    ├── symphony_crate_spec.md    # Full implementation specification
    ├── spartan.md                # Spartan backend documentation
    ├── whir.md                   # WHIR backend documentation
    ├── public_proof_v2.md        # Canonical public verifier proof boundary
    ├── linear_verifier_spec.md   # Linear verifier specification
    ├── lin_verif_design.md       # Linear verifier design notes
    └── modular_cp_pipeline_plan.md # Modular pipeline planning document
```

## Quick start

```rust
use symphony::{
    SymphonyParams, SymphonyProver, DummySnark,
    R1CSMatrices,
};
use symphony::ring::{RingElement, RingVector};

// 1. Define parameters
let params = SymphonyParams {
    q: 257, d: 64, kappa: 2, ell_np: 2, ell_h: 64,
    lambda_pj: 4, n_bar: 4, m: 4, b: 16, k_cs: 1,
    n_in: 1, ntt: None,
};

// 2. Setup prover and verifier
let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

// 3. Build an R1CS: z[1] * z[2] = z[3]
let mut r1cs = R1CSMatrices::new(4, 4, 1);
r1cs.a.insert(0, 1, 1);
r1cs.b.insert(0, 2, 1);
r1cs.c.insert(0, 3, 1);

// 4. Commit and prove
let z = vec![1i64, 3, 5, 15];
let full = RingVector {
    elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
};
let (c, _) = prover.commit_witness(&full);

let witness_part = RingVector {
    elements: z[1..].iter().map(|&v| RingElement::from_constant(v)).collect(),
};
let stmts = vec![
    (c.clone(), vec![z[0]], witness_part.clone()),
    (c, vec![z[0]], witness_part),
];
let proof = prover.prove(&stmts, &r1cs);

// 5. Verify
let pubs = vec![vec![z[0]], vec![z[0]]];
assert!(verifier.verify(&pubs, &proof, &r1cs));
```

## Pluggable backend SNARK

Symphony is generic over the final proof system. Implement `BackendSnark` to plug in your own:

```rust
use symphony::BackendSnark;
use symphony::snark::RelationDescription;

struct MySnark;

impl BackendSnark for MySnark {
    type ProvingKey = /* ... */;
    type VerifyingKey = /* ... */;
    type Proof = /* ... */;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) { /* ... */ }
    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof { /* ... */ }
    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool { /* ... */ }
}

let (prover, verifier) = SymphonyProver::<MySnark>::setup(params);
```

Included backends:
- **`WhirSnark`** *(feature = `whir`)* — Post-quantum Merkle-based polynomial commitment using [whir-p3](https://github.com/tcoratger/whir-p3) and Plonky3 over BabyBear (p = 2^31 − 2^27 + 1). Uses Poseidon2 for Merkle hashing/compression and WHIR's polynomial commitment scheme. Poseidon2 parameters are derived deterministically from the full 32-byte SHA-256 setup seed via `ChaCha20Rng`. See [`docs/whir.md`](docs/whir.md).
- **`SpartanSnark`** — R1CS-to-sumcheck reduction with Pedersen commitments and Bulletproofs-style IPA over Ristretto (curve25519-dalek). See [`docs/spartan.md`](docs/spartan.md).
- **`SumcheckSnark`** — Demo backend with transcript binding and tamper-detection checks.
- **`DummySnark`** — Trivial backend for API testing (no soundness).

Possible external backends:
- **Post-quantum**: LaBRADOR (50–100 KB proofs)
- **Pairing-based**: HyperPlonk + KZG (< 50 KB proofs, not PQ)

## Standalone CP-SNARK usage

You can use commit-and-prove independently of the full folding pipeline:

```rust
use symphony::cp_snark::{CPSnark, IdentityRelation};
use symphony::HashCommitment;
use symphony::snark::DummySnark;
use symphony::fiat_shamir::FSCommitment;

let scheme = HashCommitment::new();
let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 32);

let (c, o) = scheme.commit(b"secret-message");
let proof = cp
    .prove(
        &scheme,
        &[b"secret-message".as_slice()],
        &[o],
        &[c],
        b"",
        &IdentityRelation,
    )
    .unwrap();

assert!(cp.verify(&scheme, &[c], b"", &IdentityRelation, &proof));
```

## Modular CP pipeline

The `modular` module provides a backend-agnostic, split-backend architecture that decouples the CP-SNARK and output SNARK into independently swappable components:

```rust
use symphony::{ModularProver, ModularVerifier, ProofBundle, PublicProofBundle};
```

Key components:
- **`ModularProver` / `ModularVerifier`** — end-to-end prover and verifier that orchestrate the full pipeline using separate CP and output backends.
- **`ProofBundle` / `PublicProofBundle`** — unified proof containers produced by the modular pipeline. `PublicProofBundle` is the canonical public-only verifier boundary; `ProofBundleV2` remains as a compatibility name. See [`docs/public_proof_v2.md`](docs/public_proof_v2.md).
- **`transcript_core`** — canonical transcript schema, codec, and challenge derivation.
- **`digest_core`** — digest and root helpers for transcript and fold bindings.
- **`folding_core`** — folding-domain traits and adapters.
- **`cp_relation_core`** — CP public/witness model and relation checks.
- **`cp_backend_api` / `output_backend_api`** — trait abstractions for pluggable CP and output backends.
- **`adapter_symphony`** — compatibility mapping with the legacy `SymphonyProof` format.

## Feature flags

| Flag | What it enables |
|------|-----------------|
| `whir` | WHIR backend SNARK (`WhirSnark`), pulls in `whir-p3` + Plonky3 dependencies |

```bash
cargo build                     # default (Spartan, DummySnark, SumcheckSnark)
cargo build --features whir     # also builds the WHIR backend
```

## Testing

```bash
cargo test                       # default backends
cargo test --features whir       # include WHIR backend tests
cargo test -- -q                 # quiet output
```

The test suite covers every protocol layer:

| Layer | What's tested |
|-------|---------------|
| Ring + extension field + NTT + tensor | Algebraic laws, edge cases, overflow safety, NTT correctness, tensor arithmetic |
| Commitment | Roundtrip, wrong witness rejection, norm bounds, strict/relaxed/fine-grained openings, homomorphic properties |
| Decomposition | Recompose correctness, bounded digits, monomial embedding, overflow fix coverage |
| Fiat-Shamir | Determinism, domain separation, bias/range checks, rejection-sampled challenges |
| Hash commitment | Hash-based commitment scheme verification |
| Sumcheck + eq polynomial | Valid/invalid claims, degree/round checks, table/direct consistency, partition of unity |
| RoK protocols (Πhad/Πmon/Πrg/Πgr1cs) | Completeness and soundness across base and extended settings |
| R1CS + generalized R1CS | Sparse matrix operations, conversion, generalized committed R1CS |
| Folding + streaming + two-layer | Consistency, transcript binding, projection seed derivation, cross-layer checks |
| SNARK pipeline | End-to-end flow, CP encoding consistency, transcript/public-input binding, tamper checks |
| WHIR backend | CP roundtrip, output SNARK roundtrip, wrong/short-instance rejection, proof succinctness (Merkle commitment present), WHIR PCS opening verification, linear binding checks |
| Spartan backend | CP roundtrip, witness-table hash binding, wrong-instance rejection, IPA correctness |
| Standalone CP-SNARK | `HashCommitment`, `Identity`/`Preimage`/`Transcript`/`FnRelation`, builder API, soundness-oriented checks |
| Modular CP pipeline | Modular prover/verifier orchestration, split-backend component tests, public-only v2 proof checks |
| Security & soundness | Tamper attacks, replay attacks, splice attacks, wrong-key checks, folded-instance rebinding checks |

## Notes on cryptographic backends

- `DummySnark` is intended for API/testing and does not provide production soundness.
- `SumcheckSnark` provides stronger tamper-detection and transcript binding checks, but is not a production succinct SNARK backend.
- `SpartanSnark` implements a full R1CS-to-sumcheck reduction with Pedersen vector commitments and a Bulletproofs-style Inner Product Argument (IPA) over the Ristretto group (`curve25519-dalek`). It provides real cryptographic guarantees and is suitable for CP-SNARK integration testing. Not post-quantum.
- `WhirSnark` *(feature-gated)* implements a post-quantum SNARK using WHIR PCS (Merkle-based polynomial commitments) from whir-p3 over BabyBear. Uses Poseidon2 hashing/compression in Plonky3's `MerkleTreeMmcs`; Poseidon2 parameters are deterministically derived from a full SHA-256 relation seed using `ChaCha20Rng`. Proofs are succinct (Merkle root + logarithmic opening proof). Plausibly post-quantum since it relies only on hash function security.
- Backends can optionally provide typed CP and typed output proving/verification. Public-only v2 verification requires these typed paths to be authoritative; otherwise it rejects instead of falling back to witness-side checks. WHIR currently has authoritative typed output, a non-authoritative typed CP hook over the existing CP-R1CS core, and a software `CpFieldRelation` spec for typed CP. Public WHIR verification still fails closed because the full typed CP relation is not yet proved inside WHIR.
- The architecture is ready for plugging in additional backends via `BackendSnark`.
- For production deployment, run backend-specific security review/benchmarks.

## References

- Binyi Chen. *Symphony: Scalable SNARKs in the Random Oracle Model from Lattice-Based High-Arity Folding.* Cryptology ePrint Archive, 2025.
- Albrecht et al. *LaBRADOR: Compact Proofs for R1CS from Module-SIS.* CRYPTO 2024.
- Chen & Chiesa. *LatticeFold: A Lattice-Based Folding Scheme and its Applications to Succinct Proof Systems.* 2024.
- Gur, Hajiabadi, & Mahmoody. *WHIR: Reed-Solomon Proximity Testing with Super-Fast Verification.* 2024.
- Sethuraman, Lund, & Thaler. *Spartan: Efficient and General-Purpose zkSNARKs Without Trusted Setup.* CRYPTO 2020.
- Bunz, Bootle, Boneh, Poelstra, Wuille, & Maxwell. *Bulletproofs: Short Proofs for Confidential Transactions and More.* S&P 2018.

## License

MIT
