# Spartan Backend

The Spartan backend (`SpartanSnark`) implements the `BackendSnark` trait using
an R1CS-to-sumcheck reduction over the Ristretto scalar field with Pedersen
vector commitments and a Bulletproofs-style Inner Product Argument (IPA).

**Not post-quantum** — security relies on the discrete logarithm problem over Curve25519.

**Current implementation status:** Spartan is a classical compatibility and
testing backend. It exposes typed CP/output hooks, but
`SpartanSnark::has_authoritative_typed_cp()` and
`SpartanSnark::has_authoritative_typed_output()` are both false. Product
`verify_public` / v2 public verification therefore fails closed when Spartan is
used for either required authoritative backend; it does not fall back to
witness-side checks.

---

## Architecture

```
src/snark/spartan/
├── mod.rs            # SpartanSnark: BackendSnark impl, dual-path prove/verify
├── commitment.rs     # Pedersen vector commitments over Ristretto
├── ipa.rs            # Bulletproofs-style Inner Product Argument
├── r1cs_sumcheck.rs  # Ring R1CS flattening + sparse MLE evaluation
├── scalar_field.rs   # i64 <-> Scalar conversions
├── serialize.rs      # SpartanContext binary serialization
└── sumcheck.rs       # Degree-3 sumcheck prover/verifier over Fp
```

---

## Key Types

### SpartanSnark

Unit struct implementing `BackendSnark`. Routes to one of two proving paths:

- **Output SNARK path** (`SpartanContext::is_output_snark = true`): full
  R1CS-to-sumcheck reduction with IPA proofs. Used for proving the folded R1CS
  statement in legacy/full verification and for direct typed-output tests.
- **CP-SNARK path** (`is_output_snark = false` or no context): Pedersen
  witness commitment plus sumcheck and IPA over the witness table. Used for
  compatibility CP proofs and typed-CP hook tests, but not advertised as
  authoritative public CP.

### SpartanProvingKey / SpartanVerifyingKey

```rust
pub struct SpartanProvingKey {
    pub pedersen_key: PedersenKey,       // Generator vectors G_0..G_{n-1}, H
    pub seed: [u8; 32],                   // Deterministic seed for challenges
    pub context: Option<SpartanContext>, // R1CS metadata and route flag
    pub context_hash: [u8; 32],          // SHA-256 binding hash
}
```

The `context_hash` binds the R1CS relation at setup time, preventing context-swap attacks.

### SpartanProof

```rust
pub struct SpartanProof {
    pub witness_commitment: RistrettoPoint,  // Pedersen commitment to z
    pub sumcheck_proof: SumcheckProofFp,     // Polynomial sumcheck transcript
    pub evaluations: [Scalar; 3],            // [Az(r*), Bz(r*), Cz(r*)]
    pub ipa_proofs: [IPAProof; 3],          // IPA proofs for evaluation claims
    pub blinding_r: Scalar,
    pub num_vars: usize,
    pub typed_output_instance: Option<FoldedOutputInstance>,
    pub typed_output_witness_summary: Option<SpartanTypedOutputWitnessSummary>,
}
```

The old CP-path `witness_table` / `witness_hash` fields are no longer present.
CP proofs keep only the commitment, sumcheck, IPA data, blinding, and round
metadata; `cp_snark_no_witness_table_in_proof` covers this regression.

---

## Proving Flow (Output SNARK)

1. **Parse & flatten**: Instance and witness bytes are converted to `Scalar` (Ristretto field, ~2^252). Ring R1CS constraints are flattened: each ring constraint over `Rq` becomes `d` scalar constraints, yielding `m*d` constraints over `n*d` variables.

2. **Compute Az, Bz, Cz**: Sparse matrix-vector products over the flattened matrices and the combined assignment vector `z = (instance || witness)`.

3. **Pedersen commitment**: Commit to `z_padded` (padded to power of 2) using the Pedersen key: `C = sum_i z_i * G_i + r * H`.

4. **Sumcheck**: Derive random point `tau` from transcript. Build the equality table `eq(tau, x)` and run a degree-3 sumcheck for:
   ```
   F(x) = eq(tau, x) * [Az(x) * Bz(x) - Cz(x)]
   ```
   The sumcheck produces round polynomials evaluated at `{0, 1, 2, 3}` with Lagrange interpolation.

5. **Evaluation claims**: At the sumcheck challenge point `r*`, compute `az_eval = <a_row, z>`, `bz_eval = <b_row, z>`, `cz_eval = <c_row, z>` where `a_row`, `b_row`, `c_row` are the MLE evaluations of the sparse matrices at `r*`.

6. **IPA proofs**: Three Bulletproofs-style IPA proofs verify `<a_row, z> = az_eval`, etc. Each IPA runs in `O(log n)` rounds, halving the vector at each step.

---

## Proving Flow (CP-SNARK)

1. Map witness bytes to `Scalar`, append a byte-length sentinel, and pad to a
   power of two.
2. Commit to the padded witness table using the Pedersen key and a deterministic
   blinding factor derived from the instance.
3. Build the CP transcript under the `"spartan-cp-v2"` domain separator.
4. Run the shared Spartan sumcheck implementation for
   `F(x) = eq(tau, x) * (w(x) * 1 - 0)`. The proof format still stores four
   evaluations per round because the helper is the generic degree-3 R1CS
   sumcheck.
5. Prove the witness MLE evaluation with one IPA. Verification uses
   `ipa_verify_eq`, avoiding allocation of the full equality table for the IPA
   verifier side, though the generator-side IPA work remains linear in the
   committed vector length.

This path is succinct with respect to the witness table contents. It remains a
compatibility proof, not the product-authoritative typed CP route.

---

## Pedersen Commitments (`commitment.rs`)

```rust
pub struct PedersenKey {
    pub generators: Vec<RistrettoPoint>,  // G_0, ..., G_{n-1}
    pub blinding_gen: RistrettoPoint,     // H
}
```

- Generators are derived deterministically via SHA-256 hash-to-point.
- Supports dynamic extension up to 2^24 generators.
- Commitment: `C = sum_i v_i * G_i + r * H` (Pedersen vector commitment).
- Binding under discrete log; perfectly hiding.

---

## Inner Product Argument (`ipa.rs`)

Bulletproofs-style IPA proving `<a, b> = claimed_ip` given commitment `C = commit(a, r)`.

```rust
pub struct IPAProof {
    pub lr_pairs: Vec<(RistrettoPoint, RistrettoPoint)>,  // log(n) halving rounds
    pub final_a: Scalar,
    pub final_r: Scalar,
}
```

Each round:
1. Split `a`, `b`, generators into left/right halves.
2. Compute cross-terms `L = commit(a_lo, b_hi)`, `R = commit(a_hi, b_lo)`.
3. Verifier sends challenge `x`.
4. Fold: `a' = a_lo + x * a_hi`, `b' = b_lo + x^{-1} * b_hi`.

After `log(n)` rounds, the final scalar `final_a` is checked directly.

**Verification**: Recomputes the folded generator and `b` vector, then checks `final_a * G_folded + final_r * H + final_a * <b_folded> * U == C_folded`.

---

## R1CS Flattening (`r1cs_sumcheck.rs`)

Converts ring R1CS over `Rq` to scalar R1CS over `Fp`:

- Each ring element contributes `d` scalar variables (its coefficients).
- Each matrix entry is copied onto the matching coefficient column for each of
  the `d` coefficient rows. The current Spartan flattener does not implement a
  general negacyclic convolution gadget for arbitrary ring multiplications; it
  checks the coefficient-wise generalized R1CS matrices supplied in the
  `SpartanContext`.
- Sparse matrices stored in COO format (`FlatSparseMatrix`).

Key functions:
- `flatten_ring_r1cs()` — expands ring constraints to scalar constraints.
- `compute_matrix_vector_products()` — sparse Az, Bz, Cz computation.
- `compute_matrix_mle_at_point()` — evaluates sparse matrix MLE at a point.
- `mle_eval()` — evaluates multilinear extension from truth table.

---

## Context Serialization (`serialize.rs`)

Binary format with header `"SPRT"`:

```rust
pub struct SpartanContext {
    pub r1cs: R1CSMatrices,
    pub q: u64,
    pub d: usize,
    pub n_pub: usize,
    pub is_output_snark: bool,
}
```

Serializes sparse matrices in COO format (row, col, value triples). Used to bind the R1CS relation at setup and reconstruct it during proving.

---

## Integration with Symphony

During `SymphonyProver::<SpartanSnark>::setup(params)` and the modular
`Prover<SpartanSnark, SpartanSnark>` setup:

1. **CP-SNARK relation**: Spartan can use no context for the legacy CP path,
   or a serialized `SpartanContext` with `is_output_snark = false` through
   `serialize_cp_context`.
2. **Output SNARK relation**: `RelationDescription` with serialized
   `SpartanContext` containing the R1CS, modulus `q`, ring dimension `d`, and
   `is_output_snark = true`. Spartan takes the output path.
3. **Typed hooks**: `prove_typed_cp` / `verify_typed_cp` encode the typed CP
   statement and witness into the compatibility CP path. `prove_typed_output`
   / `verify_typed_output` validate and bind `FoldedOutputInstance` plus a
   small witness summary before using the output path.

The legacy/full `SymphonyProof<SpartanSnark>` contains both a
`cp_proof: SpartanProof` and a `snark_proof: SpartanProof`. The public-only v2
route is expected to fail closed with Spartan because the authority flags are
false.

---

## Dependencies

- `curve25519-dalek` — Ristretto group, scalar field arithmetic, constant-time operations.
- `sha2` — SHA-256 for hash-to-point, transcript hashing, context binding.
