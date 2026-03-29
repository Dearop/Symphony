# Symphony

**Scalable lattice-based SNARKs via high-arity folding — no hash-in-circuit overhead.**

Symphony is a Rust implementation of the folding-based SNARK construction from
[*"Symphony: Scalable SNARKs in the Random Oracle Model from Lattice-Based High-Arity Folding"*](https://eprint.iacr.org/2025/) (Binyi Chen, Stanford, 2025).

It replaces Merkle-tree commitments and hash-in-circuit gadgets with **module-Ajtai lattice commitments** and a **commit-and-prove compiler** that never embeds Fiat-Shamir hashes into the proven statement.

## Current status

- Core Symphony pipeline is implemented end-to-end in Rust.
- Standalone CP-SNARK module is implemented (`src/cp_snark/mod.rs`).
- Backend SNARK is pluggable through `BackendSnark` (demo backends: `DummySnark`, `SumcheckSnark`; concrete backend: `SpartanSnark`).
- Audit-driven robustness fixes are integrated across ring/FS/folding/ROK/sumcheck layers.
- Integration test suite is split into focused files for maintainability and debugging.

## Key properties

- **No hash-in-circuit** — the SNARK statement is free of random-oracle evaluations, eliminating the dominant cost in existing folding schemes.
- **Plausibly post-quantum** — security relies on Module-SIS over cyclotomic rings.
- **Streaming prover** — memory-efficient, multi-pass prover architecture.
- **High-arity folding** — folds an arbitrary number of R1CS statements in a single shot (not binary).
- **Pluggable backend** — the final proof system is abstracted behind a `BackendSnark` trait. Swap in LaBRADOR, WHIR, HyperPlonk+KZG, or your own.

## Architecture

```
symphony/
├── src/
│   ├── ring/              # Rq = Zq[X]/<X^64+1> arithmetic, NTT, extension field K = Fq^2, tensor E = K⊗Rq
│   ├── commitment/        # Module-Ajtai commitment: commit, strict/relaxed/fine-grained opening
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
│   │   └── challenge.rs   #   Folding challenge set S ⊂ Rq
│   ├── r1cs/              # Sparse R1CS matrices, generalized committed R1CS, Kronecker expansion
│   ├── fiat_shamir/       # SHA-256 transcript + HashCommitment FS commitment scheme
│   ├── snark/             # Top-level SNARK pipeline
│   │   ├── mod.rs         #   BackendSnark trait, SymphonyProver/Verifier/Proof, DummySnark
│   │   ├── prover.rs      #   Full proof generation orchestration
│   │   ├── cp_snark.rs    #   Commit-and-prove encoding helpers
│   │   ├── sumcheck_snark.rs # Sumcheck-backed demo backend (consistency/soundness checks)
│   │   └── spartan/       #   Spartan backend (R1CS-to-sumcheck + Pedersen + IPA)
│   │       ├── mod.rs     #     SpartanSnark implementing BackendSnark
│   │       ├── commitment.rs # Pedersen vector commitment
│   │       ├── ipa.rs     #     Inner Product Argument
│   │       ├── r1cs_sumcheck.rs # R1CS-to-sumcheck reduction over Fp
│   │       ├── scalar_field.rs  # Ristretto scalar field ops
│   │       ├── serialize.rs     # SpartanContext serialization
│   │       └── sumcheck.rs      # Sumcheck over Fp
│   ├── cp_snark/          # Standalone commit-and-prove SNARK API (generic over backend + FS commitment)
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
│   ├── folding.rs         # Folding, streaming, and two-layer tests
│   ├── snark.rs           # Full Symphony pipeline tests
│   ├── cp_snark.rs        # Standalone CP-SNARK tests
│   ├── security_soundness.rs # Tamper/replay/splice attack detection tests
│   └── common/mod.rs      # Shared integration test helpers
├── benches/
│   └── folding.rs         # Criterion benchmarks
└── docs/
    └── symphony_crate_spec.md  # Full implementation specification
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
    ntt: None,
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
- **`SpartanSnark`** — R1CS-to-sumcheck reduction with Pedersen commitments and IPA over Ristretto (curve25519-dalek). Suitable for integration testing with real cryptographic guarantees.
- **`SumcheckSnark`** — Demo backend with transcript binding and tamper-detection checks.
- **`DummySnark`** — Trivial backend for API testing (no soundness).

Possible external backends:
- **Post-quantum**: LaBRADOR, WHIR (50–100 KB proofs)
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

assert!(cp.verify(&[c], b"", &proof));
```

## Testing

```bash
cargo test          # run the full unit/integration/doc test suite
cargo test -- -q    # quiet output
```

The test suite covers every protocol layer:

| Layer | What's tested |
|-------|---------------|
| Ring + extension field + NTT + tensor | Algebraic laws, edge cases, overflow safety, NTT correctness, tensor arithmetic |
| Commitment | Roundtrip, wrong witness rejection, norm bounds, strict/relaxed/fine-grained openings, homomorphic properties |
| Decomposition | Recompose correctness, bounded digits, monomial embedding, overflow fix coverage |
| Fiat-Shamir | Determinism, domain separation, bias/range checks, rejection-sampled challenges |
| Sumcheck + eq polynomial | Valid/invalid claims, degree/round checks, table/direct consistency, partition of unity |
| RoK protocols (Πhad/Πmon/Πrg/Πgr1cs) | Completeness and soundness across base and extended settings |
| Folding + streaming + two-layer | Consistency, transcript binding, projection seed derivation, cross-layer checks |
| SNARK pipeline | End-to-end flow, CP encoding consistency, transcript/public-input binding, tamper checks |
| Standalone CP-SNARK | `HashCommitment`, `Identity`/`Preimage`/`Transcript`/`FnRelation`, builder API, soundness-oriented checks |
| Security & soundness | Tamper attacks, replay attacks, splice attacks under SumcheckSnark backend |

## Notes on cryptographic backend

- `DummySnark` is intended for API/testing and does not provide production soundness.
- `SumcheckSnark` provides stronger tamper-detection and transcript binding checks, but is not a production succinct SNARK backend.
- `SpartanSnark` implements a full R1CS-to-sumcheck reduction with Pedersen vector commitments and an Inner Product Argument (IPA) over the Ristretto group (`curve25519-dalek`). It provides real cryptographic guarantees and is suitable for CP-SNARK integration testing.
- The architecture is ready for plugging in additional backends via `BackendSnark`.
- For production deployment, integrate a concrete post-quantum backend and run backend-specific security review/benchmarks.

## References

- Binyi Chen. *Symphony: Scalable SNARKs in the Random Oracle Model from Lattice-Based High-Arity Folding.* Cryptology ePrint Archive, 2025.
- Albrecht et al. *LaBRADOR: Compact Proofs for R1CS from Module-SIS.* CRYPTO 2024.
- Chen & Chiesa. *LatticeFold: A Lattice-Based Folding Scheme and its Applications to Succinct Proof Systems.* 2024.

## License

MIT
