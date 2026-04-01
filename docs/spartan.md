# Spartan Backend

The Spartan backend (`SpartanSnark`) implements the `BackendSnark` trait using an R1CS-to-sumcheck reduction over the Ristretto scalar field with Pedersen vector commitments and a Bulletproofs-style Inner Product Argument (IPA).

**Not post-quantum** — security relies on the discrete logarithm problem over Curve25519.

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

Unit struct implementing `BackendSnark`. Routes to one of two proving paths depending on whether a `SpartanContext` is present:

- **Output SNARK path** (`is_output_snark = true`): full R1CS-to-sumcheck reduction with IPA proofs. Used for proving the folded R1CS statement.
- **CP-SNARK path** (`is_output_snark = false` or no context): lightweight witness-binding proof using hash commitment. Used for proving folding transcript correctness.

### SpartanProvingKey / SpartanVerifyingKey

```rust
pub struct SpartanProvingKey {
    pub pedersen_key: PedersenKey,       // Generator vectors G_0..G_{n-1}, H
    pub seed: [u8; 32],                   // Deterministic seed for challenges
    pub context: Option<SpartanContext>, // R1CS metadata (output path only)
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
    pub witness_table: Option<Vec<Scalar>>, // CP path only (non-succinct)
    pub witness_hash: Option<[u8; 32]>,     // CP path only
}
```

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

1. Map witness bytes to `Scalar`, pad to power of 2.
2. Compute SHA-256 hash of witness table for binding.
3. Run a degree-2 sumcheck for `F(x) = eq(tau, x) * w(x)`.
4. Return proof including the full witness table (non-succinct) and hash.

This path prioritizes simplicity and correctness over succinctness, since the CP-SNARK is proving the folding transcript which is relatively small.

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
- Ring multiplication `a * b mod (X^d + 1)` expands to `d` scalar constraints via convolution with negacyclic wrap.
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

During `SymphonyProver::<SpartanSnark>::setup(params)`:

1. **CP-SNARK relation**: `RelationDescription` with no context. Spartan takes the CP path.
2. **Output SNARK relation**: `RelationDescription` with serialized `SpartanContext` containing the R1CS, modulus `q`, ring dimension `d`. Spartan takes the output path.

The `SymphonyProof<SpartanSnark>` contains both a `cp_proof: SpartanProof` (folding correctness) and a `snark_proof: SpartanProof` (folded R1CS statement).

---

## Dependencies

- `curve25519-dalek` — Ristretto group, scalar field arithmetic, constant-time operations.
- `sha2` — SHA-256 for hash-to-point, transcript hashing, context binding.
