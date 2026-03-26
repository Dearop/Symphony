# Symphony

**Scalable lattice-based SNARKs via high-arity folding — no hash-in-circuit overhead.**

Symphony is a Rust implementation of the folding-based SNARK construction from
[*"Symphony: Scalable SNARKs in the Random Oracle Model from Lattice-Based High-Arity Folding"*](https://eprint.iacr.org/2025/) (Binyi Chen, Stanford, 2025).

It replaces Merkle-tree commitments and hash-in-circuit gadgets with **module-Ajtai lattice commitments** and a **commit-and-prove compiler** that never embeds Fiat-Shamir hashes into the proven statement.

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
│   ├── fiat_shamir/       # SHA-256-based Fiat-Shamir transcript with domain separation
│   ├── snark/             # Top-level SNARK pipeline
│   │   ├── mod.rs         #   BackendSnark trait, SymphonyProver/Verifier/Proof, DummySnark
│   │   ├── prover.rs      #   Full proof generation orchestration
│   │   └── cp_snark.rs    #   Commit-and-prove encoding helpers
│   ├── params.rs          # Global parameters (Table 1 of the paper)
│   └── lib.rs             # Crate root and public exports
├── tests/
│   └── comprehensive.rs   # 62 integration tests (completeness + soundness)
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

Possible backends:
- **Post-quantum**: LaBRADOR, WHIR (50–100 KB proofs)
- **Pairing-based**: HyperPlonk + KZG (< 50 KB proofs, not PQ)

## Testing

```bash
cargo test          # 91 tests: 29 unit + 62 integration
cargo test -- -q    # quiet output
```

The test suite covers every protocol layer:

| Layer | What's tested |
|-------|---------------|
| Ring algebra | Commutativity, associativity, distributivity, NTT consistency, cyclotomic reduction, extension field inverses |
| Commitment | Commit/verify roundtrip, wrong witness rejection, norm bounds, strict/relaxed/fine-grained openings |
| Decomposition | Gadget recomposition, monomial embedding full range, monomial decompose consistency |
| Fiat-Shamir | Determinism, domain separation, order dependence, challenge range |
| Sumcheck | Valid proofs, wrong sum/degree/round count rejection |
| Πmon | Multi-layer monomial check, soundness (non-monomials rejected) |
| Πhad | Valid R1CS accepted, wrong witness rejected |
| Πrg | Range proof with various witness sizes |
| Πgr1cs | Full single-instance reduction |
| Folding | Two-statement fold, public input consistency, challenge set properties |
| Two-layer | Layer 1 → split → decompose → Layer 2 → verify |
| SNARK pipeline | End-to-end with DummySnark, tampered proof rejection |

## References

- Binyi Chen. *Symphony: Scalable SNARKs in the Random Oracle Model from Lattice-Based High-Arity Folding.* Cryptology ePrint Archive, 2025.
- Albrecht et al. *LaBRADOR: Compact Proofs for R1CS from Module-SIS.* CRYPTO 2024.
- Chen & Chiesa. *LatticeFold: A Lattice-Based Folding Scheme and its Applications to Succinct Proof Systems.* 2024.

## License

MIT
