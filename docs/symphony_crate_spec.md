# Symphony Crate — Rust Implementation Specification

> Context document for implementing a Rust crate based on *"Symphony: Scalable SNARKs in the Random Oracle Model from Lattice-Based High-Arity Folding"* by Binyi Chen (Stanford, October 2025). This crate is intended to replace hash-based Merkle tree constructions in ZK repositories.

---

## 1. What Symphony Is and Why It Replaces Merkle Trees

Symphony is a **folding-based SNARK** that avoids embedding hash functions (random oracles) into SNARK circuits. Existing ZK systems that use Merkle trees pay a heavy price: each hash gadget costs thousands of R1CS constraints, and SNARK-friendly hashes still cost hundreds. Symphony eliminates this by using **lattice-based commitments (Ajtai)** combined with a **high-arity folding scheme** and a **commit-and-prove compiler** that never places Fiat-Shamir hashes inside the proven statement.

**Key properties of the resulting system:**

- Memory-efficient, parallelizable, streaming-friendly prover
- Plausibly post-quantum secure
- Polylogarithmic proof size and verification
- Prover cost dominated only by witness commitments
- No hash-in-circuit overhead

**Drop-in replacement model:** Where existing ZK repos use Merkle tree commitments for witness binding and folding verification, Symphony uses module-Ajtai commitments over cyclotomic rings. Where existing repos embed hash verification circuits (for Fiat-Shamir or Merkle openings) into R1CS/CCS constraints, Symphony's commit-and-prove compiler eliminates those circuits entirely.

---

## 2. Core Algebraic Primitives

### 2.1 Cyclotomic Rings

The fundamental algebraic object is the power-of-two cyclotomic ring:

```
R  := Z[X] / <X^d + 1>       (d = 2^k, paper uses d = 64)
Rq := R / qR = Zq[X] / <X^d + 1>   (q is a 64-bit prime)
```

**Rust representation:**

```rust
/// A polynomial in Rq, stored as d coefficients in [−q/2, q/2)
struct RingElement {
    coeffs: [i64; D],  // D = 64 in the paper's instantiation
}
```

**Key operations needed:**

| Operation | Description |
|---|---|
| `ring_mul(a, b) -> RingElement` | Polynomial multiplication mod (X^d + 1, q) — use NTT |
| `ring_add(a, b) -> RingElement` | Coefficient-wise addition mod q |
| `ring_sub(a, b) -> RingElement` | Coefficient-wise subtraction mod q |
| `ct(f) -> i64` | Extract constant term (first coefficient) |
| `cf(f) -> [i64; D]` | Extract coefficient vector (identity for this repr) |
| `cf_inv(v) -> RingElement` | Interpret integer vector as ring element |

### 2.2 Extension Field (for Sumcheck)

```
K := Fq^t    (paper uses t = 2, so K = Fq^2)
```

The extension field is used exclusively for sumcheck operations. Elements of K are pairs of Zq elements with multiplication defined by an irreducible degree-2 polynomial over Fq.

### 2.3 Tensor Ring E

```
E := K ⊗_{Fq} Rq
```

An element of E is representable as a t × d matrix over Zq. It has two interpretations:

- **As K^d (K-vector space):** Each column is a K-element. Useful for sumcheck.
- **As Rq^t (Rq-module):** Each row is an Rq-element. Useful for folding with low-norm challenges.

```rust
/// Element of the tensor ring E = K ⊗ Rq
struct TensorElement {
    /// t rows, d columns — matrix over Zq
    data: [[i64; D]; T],  // T = 2, D = 64
}
```

### 2.4 Norms

Two norms are used throughout:

```
‖F‖_∞ := max |F_{i,j}|           (max absolute coefficient)
‖F‖_2  := sqrt(Σ F_{i,j}^2)     (Euclidean norm of all coefficients)
```

For a ring vector f ∈ Rq^n, the norm is the norm of its coefficient matrix cf(f) ∈ Z^{n×d}.

**Operator norm** of a ∈ R: `‖a‖_op := sup_{y∈R} ‖a·y‖_2 / ‖y‖_2`

### 2.5 Monomial Embedding

The monomial set:

```
M := {0, 1, X, X^2, ..., X^{d-1}} ⊆ Rq
```

The table polynomial:

```
t(X) := Σ_{i ∈ [1, d/2)} i · (X^i + X^{-i})    where X^{-i} = X^{d-i} since X^d = -1
```

The mapping `Exp(a)` for a ∈ (−d/2, d/2):

```
Exp(a) = sgn(a) · X^{|a|}   for a ≠ 0
Exp(0) ∈ {0, 1, X^{d/2}}
```

**Critical property (Lemma 2.1):** For all a ∈ (−d/2, d/2) and b ∈ Exp(a), the constant term `ct(b · t(X)) = a`. This is the lookup mechanism that converts norm-bounding into a simple linear relation.

### 2.6 Gadget Decomposition

For modulus q and base b, with k = 1 + ⌊log_b(q)⌋:

```rust
fn decompose(f: &[i64], b: i64, k: usize) -> Vec<i64> {
    // For each f_i, produce g_i ∈ Z^k with ‖g_i‖_∞ ≤ b/2
    // such that f_i = <g_i, (1, b, b^2, ..., b^{k-1})>
}
```

Paper uses b = 16, k_cs = 16 to convert arbitrary Zq witnesses to low-norm witnesses.

---

## 3. Commitment Scheme (Module-Ajtai)

This is what replaces Merkle trees.

### 3.1 Setup

```
pp_cm := A ←$ Rq^{κ × n}     (random matrix, κ = 12, n = 2^20)
```

### 3.2 Commit

```
Commit(A, m) = A · m ∈ Rq^κ     (commitment is κ ring elements)
```

The commitment is a matrix-vector product over Rq. The opening is the message itself (with a norm bound).

### 3.3 Verification

**Strict opening:** `VfyOpen(A, c, f) = 1` iff `A·f = c` and `‖f‖_2 < B_bnd`

**Relaxed opening:** `RVfyOpen(A, c, m, (f, s)) = 1` iff `A·f = s·c` and `s·m = f` and `‖f‖_2 ≤ B_rbnd` and `s ∈ S − S`

**Fine-grained opening:** `VfyOpen_{ℓ_h, B}(A, c, f) = 1` iff `A·f = c` and for all sub-blocks of the coefficient matrix, `‖F_{i,j}‖_2 ≤ B`

### 3.4 Security

Security relies on **Module-SIS** (MSIS): Given random A ∈ Rq^{κ×n}, it is hard to find x ∈ Rq^n with `A·x = 0` and `0 < ‖x‖_2 ≤ β_SIS`.

### 3.5 Rust Interface Sketch

```rust
pub struct AjtaiParams {
    pub a: Vec<Vec<RingElement>>,  // κ × n matrix over Rq
    pub kappa: usize,               // κ = 12
    pub n: usize,                   // witness length
    pub q: u64,                     // 64-bit prime modulus
    pub d: usize,                   // ring dimension = 64
}

pub struct Commitment {
    pub value: Vec<RingElement>,  // κ ring elements
}

impl AjtaiParams {
    pub fn setup(kappa: usize, n: usize, q: u64, d: usize) -> Self;
    pub fn commit(&self, witness: &[RingElement]) -> (Commitment, Opening);
    pub fn verify_open(&self, c: &Commitment, f: &[RingElement], bound: f64) -> bool;
}
```

---

## 4. Generalized Committed R1CS

The paper works with a generalized R1CS over ring vectors, which batches d standard R1CS statements over Zq into one ring R1CS.

### 4.1 Relation Definition

Parameters: `(n_in, n_w, n := n_in + n_w, ℓ_h, B, (M_i ∈ Z^{m×n})_{i=1}^3)`

A statement `(x, w)` is in the relation if:

```
F^T := [X_in^T, W^T] ∈ Z^{d × n}
(M_1 × F) ∘ (M_2 × F) = M_3 × F        (Hadamard / entry-wise check)
VfyOpen_{ℓ_h, B}(A, c, cf^{-1}(F)) = 1  (commitment opening)
```

### 4.2 Standard R1CS Conversion

Given original R1CS matrices M̄_i ∈ Z^{m × n̄}, convert:

```
M_i := M̄_i ⊗ [1, b, ..., b^{k_cs - 1}]     (Kronecker product)
n  := n̄ · k_cs
```

Each witness w ∈ Zq^{n̄} is decomposed via `decomp_{b, k_cs}(w)` to get a low-norm witness.

---

## 5. Building Blocks (Reductions of Knowledge)

### 5.1 Hadamard Relation → Linear Relation (Πhad, Figure 1)

**Input:** Commitment c, witness matrix F satisfying `(M₁F) ∘ (M₂F) = M₃F`

**Output:** Commitment c, sumcheck evaluation point r, evaluation values v ∈ E³

**Protocol:**

1. Verifier sends challenges s ∈ K^{log m}, α ∈ K
2. Run degree-3 sumcheck over K of size m for the claim:
   ```
   Σ_{b ∈ {0,1}^{log m}} [ Σ_{j=1}^d α^{j-1} · f_j(b) ] = 0
   ```
   where `f_j(X) = eq(s, X) · (g_{1,j}(X) · g_{2,j}(X) − g_{3,j}(X))`
3. Prover sends evaluation matrix U ∈ K^{3×d}
4. Verifier checks consistency and outputs linear evaluation instance

**Complexity:** Prover does 3d inner products between Z^m and K^m, plus sparse matrix-vector products.

### 5.2 Monomial Relation Check (Πmon, Lemma 3.1 from LatticeFold+)

Checks that each entry of committed vectors lies in the monomial set M.

**Input:** Commitments (c^(i))_{i=1}^{k_g}, monomial vectors (g^(i) ∈ M^n)_{i=1}^{k_g}

**Output:** Evaluation point r, commitments with evaluation values

**Protocol:** Single degree-3 sumcheck over K of size n. Prover cost: O(n·k_g) K-additions.

### 5.3 Approximate Range Proof (Πrg, Figure 2)

Reduces norm-checking of a ring vector to linear relations using random projection + monomial embedding.

**Input:** Commitment c, witness f with `VfyOpen_{ℓ_h, B}(A, c, f) = 1`

**Output:** Linear relation instance + batched linear instance

**Protocol steps:**

1. Verifier sends random projection matrix `J ←$ χ^{λ_pj × ℓ_h}` where χ is over {0, ±1}
2. Prover computes projected matrix `H := (I_{n/ℓ_h} ⊗ J) × cf(f)`
3. Prover decomposes H into k_g layers `H = H^(1) + d'·H^(2) + ... + d'^{k_g-1}·H^(k_g)` with `‖H^(i)‖_∞ ≤ d'/2`
4. Prover commits to monomial vectors `g^(i) := Exp(flatten(H^(i)))`
5. Run Πmon on the monomial commitments
6. Verifier checks consistency via the table polynomial

**Key parameters:**

```
λ_pj = 256                  (projection output length)
d' = d − 2 = 62             (range for decomposition)
k_g = min k such that (d'/2)·(1 + d' + ... + d'^{k-1}) ≥ 9.5·B
```

**Relaxation:** Extracted witness may have norm up to `B' = 16·B_{d,k_g}/√30` instead of B. This is acceptable because folding depth is a small constant (1 or 2).

---

## 6. The High-Arity Folding Scheme (Πfold, Figure 4) — Core Algorithm

This is the central construction. It folds ℓ_np R1CS statements into one in a single shot.

### 6.1 Single-Instance Reduction (Πgr1cs, Figure 3)

Interleaves Πrg (range proof) with Πhad (Hadamard check), sharing sumcheck challenges.

**Input:** `(c, X_in)` and witness W

**Output:** Linear relation instance + batched linear instance

**Protocol:**

1. Verifier sends: projection matrix J, sumcheck seed s', random combiner α
2. Prover sends monomial commitments (c^(i))_{i=1}^{k_g}
3. Run two parallel sumchecks (one for Hadamard, one for monomial check), sharing challenges `(r̄, s̄, s)`
4. Execute remaining steps of Πhad and Πrg

### 6.2 Multi-Instance Folding (Full Πfold)

**Input:** ℓ_np statements `{(c_ℓ, X^ℓ_in, W_ℓ)}_{ℓ=1}^{ℓ_np}`

**Steps 1–3 (Parallel reduction):**

- Run ℓ_np parallel Πgr1cs instances with **shared randomness** (J, s', α)
- Merge 2·ℓ_np sumcheck claims into 2 claims via random linear combination with powers of α
- The two merged sumchecks have sizes m and n respectively

**Steps 4–6 (Folding via low-norm challenge):**

1. Verifier samples `β ←$ S^{ℓ_np}` (low-norm challenge vector from the folding challenge set)
2. Fold commitments: `c* := Σ β_ℓ · c_ℓ`
3. Fold public inputs: `x*_in := Σ β_ℓ · cf^{-1}(X^ℓ_in)`
4. Fold evaluations: `v* := Σ β_ℓ · v_ℓ`
5. Fold witnesses: `f* := Σ β_ℓ · f_ℓ`
6. Fold monomial vectors: `g^(i) := Σ β_ℓ · g_{i,ℓ}`

**Output:** One folded statement in `R^{aux_cs}_lin × R^{batch}_lin`

### 6.3 Folding Challenge Set S

From LaBRADOR: elements of S have coefficients in {0, ±1, ±2}, operator norm ≤ 15, and differences S − S are invertible over Rq.

### 6.4 Memory-Efficient Prover (Remark 4.1)

The prover can operate with memory ≈ witness size n of a single statement:

1. **Pass 1:** Stream input witnesses, compute ℓ_np commitments, derive first-round challenges
2. **Passes 2 to 1+log log(n):** Execute sumcheck using the streaming algorithm from [Baw+25], linearly combining evaluation tables per pass
3. **Final pass:** Stream inputs again, combine witnesses using folding challenge β

---

## 7. From Folding to SNARKs (Construction 6.1)

### 7.1 The Commit-and-Prove Compiler

The key innovation: the SNARK statement **never embeds the Fiat-Shamir hash**.

**Setup:**

1. Choose a commitment scheme Π_cm (Merkle or KZG)
2. Setup CP-SNARK for R_cp
3. Setup standard SNARK for the output relation R_o

**Prover:**

1. Run non-interactive folding (Fiat-Shamir applied): at each round, instead of sending message m_i, send commitment `c_{fs,i} := Π_cm.Commit(m_i)`
2. Derive challenges from transcript `(x, {c_{fs,i}})` via hash H
3. Obtain folded instance x_o and witness w_o
4. Generate SNARK proof π for `(x_o, w_o) ∈ R_o`
5. Generate CP-SNARK proof π_cp that the committed messages form a valid folding proof
6. Output `π* := (π_cp, π, {c_{fs,i}}, x_o)`

**Verifier:**

1. Recompute challenges from `(x, {c_{fs,i}})` and H
2. Check `Π_cp.Verify(π_cp)` — this proves folding correctness WITHOUT embedding hash circuits
3. Check `Π_snark.Verify(π)` — this proves the folded statement

**Why no hash-in-circuit:** The CP-SNARK proves knowledge of openings to the Fiat-Shamir commitments. It does NOT encode the commitment-opening relation or the hash function. The verifier independently derives challenges from the commitments and checks the CP-SNARK against those challenges.

### 7.2 Proof Components

| Component | Content | Size Estimate |
|---|---|---|
| π_cp | CP-SNARK proof for folding verification | ~50-100KB (PQ) |
| π | SNARK proof for folded statement | ~50-100KB (PQ) |
| {c_{fs,i}} | log(n) + O(1) Fiat-Shamir commitments | < 1KB with Merkle |
| x_o | Folded instance (κ Rq-elts + evaluations) | Small |
| **Total** | | **< 200KB (PQ), < 50KB (pairing-based)** |

---

## 8. Two-Layer Folding Extension (Section 8)

For extremely large statement counts, use depth-2 folding:

1. **Layer 1:** Fold ℓ_np packed statements using Πfold → one folded statement (x_o, w_o)
2. **Split:** Decompose (x_o, w_o) into ℓ smaller linear statements using the structured MSIS matrix `A = [r₁·A', ..., r_ℓ·A']`
3. **Decompose:** Apply gadget decomposition to reduce norms of the ℓ statements → ℓ·k_b statements
4. **Layer 2:** Fold the ℓ·k_b statements using Πfold again (simpler: no Hadamard needed since inputs are already linear)
5. **Compile:** Two CP-SNARK proofs + one SNARK proof, still no Fiat-Shamir in circuits

**Structural requirement:** The MSIS matrix A must have the form `A = [r₁·A', ..., r_ℓ·A']` for random r_i and shared A'.

---

## 9. Concrete Parameters (Table 1)

| Parameter | Symbol | Value |
|---|---|---|
| Prime modulus | q | 64-bit prime |
| Ring dimension | d | 64 |
| MSIS rank | κ | 12 |
| MSIS norm bound | β_SIS | 2^37 |
| Extension field | K | Fq^2 |
| Folding arity | ℓ_np | 2^10 = 1024 |
| Projection input length | ℓ_h | 2^14 |
| Projection output length | λ_pj | 2^8 = 256 |
| R1CS witness length (original) | n̄ | 2^16 |
| R1CS constraints per instance | m | 2^16 |
| Decomposition factor | k_cs | 16 |
| Decomposition base | b | 2^4 = 16 |
| Generalized witness length | n = n̄·k_cs | 2^20 |
| Folding challenge set | S | LaBRADOR set, coeffs in {0,±1,±2}, ‖·‖_op ≤ 15 |
| Relaxed opening norm bound | B_rbnd | β_SIS/(4·‖S‖_op) ≈ 2^31 |
| Strict opening norm bound | B_bnd | B_rbnd/2 = 2^30 |
| Number of monomial vectors | k_g | 3 |
| Range proof ‖·‖_∞ bound | B_{d,k_g} | 121117 |
| Input witness norm bound | B | 2^10 |
| Relaxed input norm bound | B' | 353806 |

**Total capacity:** ℓ_np · d = 2^16 R1CS statements over Zq, each with 2^16 constraints → 2^32 total constraints.

**Prover cost:** Dominated by κ·n·ℓ_np = 3 · 2^32 multiplications between arbitrary Rq-elements and bounded elements (‖·‖_∞ ≤ 8). Extra 8× speedup if original witnesses are 8-bit integers.

---

## 10. Crate Architecture

### 10.1 Module Hierarchy

```
symphony/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── ring/
│   │   ├── mod.rs            // Rq arithmetic (NTT-accelerated)
│   │   ├── ntt.rs            // Number-theoretic transform for ring mul
│   │   ├── extension.rs      // K = Fq^2 extension field
│   │   └── tensor.rs         // E = K ⊗ Rq tensor ring
│   ├── commitment/
│   │   ├── mod.rs            // Ajtai commitment trait + impl
│   │   ├── params.rs         // Parameter generation, MSIS matrix sampling
│   │   └── opening.rs        // Strict, relaxed, fine-grained verification
│   ├── decomposition/
│   │   ├── mod.rs            // Gadget decomposition
│   │   └── monomial.rs       // Monomial embedding, Exp(), table polynomial
│   ├── sumcheck/
│   │   ├── mod.rs            // Sumcheck protocol over K
│   │   ├── prover.rs         // Streaming sumcheck prover
│   │   └── verifier.rs       // Sumcheck verifier
│   ├── rok/                  // Reductions of Knowledge
│   │   ├── mod.rs
│   │   ├── hadamard.rs       // Πhad (Figure 1)
│   │   ├── monomial.rs       // Πmon (Lemma 3.1)
│   │   ├── range_proof.rs    // Πrg (Figure 2)
│   │   └── gr1cs.rs          // Πgr1cs (Figure 3)
│   ├── folding/
│   │   ├── mod.rs            // High-arity folding (Figure 4)
│   │   ├── challenge.rs      // Folding challenge set S
│   │   ├── streaming.rs      // Memory-efficient prover
│   │   └── two_layer.rs      // Section 8 extension
│   ├── fiat_shamir/
│   │   ├── mod.rs            // Commit-and-open + FS transform (Section 5)
│   │   └── transcript.rs     // Transcript management
│   ├── snark/
│   │   ├── mod.rs            // Construction 6.1 compiler + BackendSnark trait
│   │   ├── cp_snark.rs       // Commit-and-prove SNARK interface
│   │   ├── prover.rs         // Full SNARK prover
│   │   ├── sumcheck_snark.rs // Demo backend (transcript binding checks)
│   │   ├── spartan/          // Spartan backend (Pedersen + IPA over Ristretto)
│   │   │   ├── mod.rs, commitment.rs, ipa.rs, r1cs_sumcheck.rs,
│   │   │   │   scalar_field.rs, serialize.rs, sumcheck.rs
│   │   └── whir/             // WHIR backend (feature-gated, PQ Merkle PCS)
│   │       ├── mod.rs, field.rs, serialize.rs
│   ├── r1cs/
│   │   ├── mod.rs            // R1CS relation definition
│   │   ├── generalized.rs    // Generalized committed R1CS (Eq. 38)
│   │   └── conversion.rs     // Standard → generalized R1CS conversion
│   └── params.rs             // Global parameter struct (Table 1)
└── benches/
    └── folding.rs            // Benchmarks for commitment + folding
```

### 10.2 Public API Sketch

```rust
/// Top-level parameters matching Table 1
pub struct SymphonyParams {
    pub q: u64,
    pub d: usize,          // 64
    pub kappa: usize,      // 12
    pub ell_np: usize,     // 1024 (folding arity)
    pub ell_h: usize,      // 2^14
    pub lambda_pj: usize,  // 256
    pub n_bar: usize,      // 2^16 (original witness length)
    pub m: usize,          // 2^16 (constraints per statement)
    pub b: usize,          // 16 (decomposition base)
    pub k_cs: usize,       // 16 (decomposition factor)
    // derived: n = n_bar * k_cs
}

/// The main entry point: batch-prove many R1CS statements
pub struct SymphonyProver {
    params: SymphonyParams,
    ajtai: AjtaiParams,
}

impl SymphonyProver {
    /// Setup: generate MSIS matrix and SNARK parameters
    pub fn setup(params: SymphonyParams) -> (Self, SymphonyVerifier);

    /// Commit to a single R1CS witness (streaming-friendly)
    pub fn commit_witness(&self, witness: &[i64]) -> (Commitment, Opening);

    /// Fold ℓ_np committed statements into one
    pub fn fold(
        &self,
        statements: &[(Commitment, PublicInput, Witness)],
    ) -> FoldingProof;

    /// Generate the full SNARK proof (calls CP-SNARK + SNARK internally)
    pub fn prove(
        &self,
        statements: &[(Commitment, PublicInput, Witness)],
        r1cs: &R1CSMatrices,
    ) -> SymphonyProof;
}

pub struct SymphonyVerifier { /* vk_cp, vk_snark, params */ }

impl SymphonyVerifier {
    /// Verify a Symphony proof against public inputs
    pub fn verify(
        &self,
        public_inputs: &[PublicInput],
        proof: &SymphonyProof,
        r1cs: &R1CSMatrices,
    ) -> bool;
}

/// R1CS matrices (sparse representation)
pub struct R1CSMatrices {
    pub a: SparseMatrix,  // M_1
    pub b: SparseMatrix,  // M_2
    pub c: SparseMatrix,  // M_3
    pub num_constraints: usize,
    pub num_variables: usize,
}

/// A complete Symphony proof
pub struct SymphonyProof {
    pub cp_proof: Vec<u8>,           // π_cp
    pub snark_proof: Vec<u8>,        // π
    pub fs_commitments: Vec<Vec<u8>>, // {c_{fs,i}}
    pub folded_instance: FoldedInstance,
}
```

### 10.3 Trait for Backend SNARK

Symphony is generic over the backend SNARK used for the final proof. Define a trait:

```rust
/// Backend SNARK that proves the folded statement and CP relation
pub trait BackendSnark {
    type ProvingKey;
    type VerifyingKey;
    type Proof;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey);
    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof;
    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool;
}
```

Implemented backends:

- **`WhirSnark`** *(feature = `whir`)*: Post-quantum, Merkle-based WHIR PCS from whir-p3 over BabyBear. Succinct proofs.
- **`SpartanSnark`**: R1CS-to-sumcheck + Pedersen + IPA over Ristretto. Not post-quantum.
- **`SumcheckSnark`**: Demo backend with transcript binding checks.
- **`DummySnark`**: Trivial backend for API testing.

Possible external backends:

- **Post-quantum:** LaBRADOR (proof size 50–100KB)
- **Pairing-based:** HyperPlonk + KZG (proof size < 50KB, not PQ)

### 10.4 Trait for Fiat-Shamir Commitment Π_cm

```rust
/// Commitment used in the Fiat-Shamir transform (NOT the Ajtai commitment)
/// Must be straightline-extractable. Merkle trees or KZG both work.
pub trait FSCommitment {
    type Commitment;
    type Opening;

    fn commit(&self, message: &[u8]) -> (Self::Commitment, Self::Opening);
    fn verify(&self, commitment: &Self::Commitment, message: &[u8], opening: &Self::Opening) -> bool;
}
```

---

## 11. Critical Implementation Notes

### 11.1 NTT for Ring Multiplication

Ring multiplication over Rq = Zq[X]/<X^d+1> should use NTT (Number-Theoretic Transform) for O(d log d) complexity. Since d = 64, this is a small fixed-size NTT. The prime q must satisfy `q ≡ 1 (mod 2d)` for NTT compatibility.

### 11.2 Low-Norm Multiplication Optimization

The dominant prover cost is `κ·n·ℓ_np` multiplications between arbitrary Rq-elements and elements with ‖·‖_∞ ≤ b/2 = 8. These are **not** full ring multiplications — one operand is small. Exploit this:

- Use schoolbook multiplication when one operand has small coefficients (faster than NTT for small d)
- Or use SIMD/AVX instructions for parallel small-coefficient multiply-accumulate

### 11.3 Streaming Prover

The prover must support streaming to be memory-efficient:

- **Commitment phase:** Process witnesses one at a time, accumulate A·f_ℓ
- **Sumcheck phase:** Use the multi-pass streaming algorithm (2 + log log(n) passes)
- **Folding phase:** Stream witnesses again, accumulate β_ℓ · f_ℓ

### 11.4 Random Projection Matrix

The projection matrix `J ∈ {0, ±1}^{λ_pj × ℓ_h}` uses distribution χ where `Pr[0] = 1/2, Pr[±1] = 1/4`. This is generated from the Fiat-Shamir transcript (verifier randomness). The structured projection `I_{n/ℓ_h} ⊗ J` means J is reused across blocks — store only J, not the full matrix.

### 11.5 Sumcheck Batching

The 2·ℓ_np parallel sumcheck instances are merged into 2 via random linear combination with powers of α. This is essential — without batching, verification cost scales linearly with ℓ_np.

### 11.6 Norm Bound Constraint (Eq. 50)

The norm bounds must satisfy:

```
B_rbnd/2 = B_bnd ≥ ℓ_np · ‖S‖_op · max(B · √(nd/ℓ_h), √n)
```

This is a worst-case bound. In practice, due to the symmetric distribution of β, the folded witness norm is much smaller.

### 11.7 Security Level

MSIS parameters are set for 117-bit security using the lattice estimator. Both |K| and |S| must exceed 2^128. Scale by Q (number of random oracle queries) for non-interactive security.

---

## 12. Integration Guide: Replacing Merkle Trees in ZK Repos

### 12.1 What Changes

| Existing Merkle-based System | Symphony Replacement |
|---|---|
| Hash-based witness commitment | Ajtai commitment `c = A·f` |
| Merkle opening proof in R1CS circuit | **Removed entirely** — CP-SNARK handles this out-of-circuit |
| Fiat-Shamir hash embedded in circuit | **Removed entirely** — verifier derives challenges from commitments |
| 2-to-1 recursive folding with hash verification | Single-shot high-arity folding (1024 statements at once) |
| Deep folding tree (log(n) depth) | Depth 1 or 2 |
| Hash gadget constraints (thousands per hash) | Zero hash-in-circuit constraints |

### 12.2 Migration Steps

1. **Replace commitment scheme:** Swap Merkle/Poseidon commitment with `AjtaiParams::commit()`
2. **Remove hash circuits:** Delete all R1CS constraints that verify Merkle openings or Fiat-Shamir hashes
3. **Replace recursive folding loop:** Replace the fold-2-at-a-time loop with a single call to `SymphonyProver::fold()` on all statements
4. **Add CP-SNARK compilation:** The folding proof is compiled to a SNARK via `SymphonyProver::prove()`, which internally generates both the CP-SNARK and standard SNARK proofs
5. **Update verifier:** Replace recursive verification with `SymphonyVerifier::verify()`

### 12.3 What Stays the Same

- R1CS constraint definition (the application logic)
- Public input format
- Witness generation
- The external SNARK backend — Symphony is a compiler on top (WHIR and Spartan are included; LaBRADOR, HyperPlonk, etc. can be added)

---

## 13. Open Problems and Caveats

1. **Production hardening remains open.** The crate includes end-to-end implementations with two concrete backends (Spartan, WHIR); deploying in production still requires security audits and backend-specific benchmarks.
2. **Approximate range proofs** mean extracted witnesses have slightly larger norms (B' vs B). This is fine for depth ≤ 2 but requires care if extending to deeper folding.
3. **Concrete probability analysis for folded witness norms** is left to future work (Remark 4.2). The worst-case bound (Eq. 50) is conservative.
4. **Two-layer folding** requires the structured MSIS matrix assumption (Eq. 56), which is slightly stronger than standard MSIS.
5. **One-pass streaming** for the non-recursive setting remains an open problem. Current algorithm requires 2 + log log(n) passes.
6. **WHIR output binding is implemented for the R1CS backend path.** The output verifier now checks that the claimed `Az(r*)`, `Bz(r*)`, and `Cz(r*)` values are derived from the same WHIR-committed assignment polynomial `z` using three sparse linear-binding sumchecks plus a constant number of WHIR openings. This keeps the verifier on the intended verifier-centric path from the WHIR/Symphony cost model, while pushing witness-sized work to the prover.
7. **Public proof v2 is the canonical verifier boundary.** `PublicProofBundle` / `PublicSymphonyProof` contain only public inputs supplied out-of-band, public FS commitments/digests, the typed folded output instance, and backend CP/output proofs. The product APIs are `prove_public` / `verify_public`; `prove_v2` / `verify_v2` remain compatibility aliases. The public-boundary digest scheme is backend-selected: SHA-256 remains the compatibility default, and WHIR public proofs use Poseidon2/BabyBear. See `docs/public_proof_v2.md`.
8. **WHIR typed CP is authoritative for public verification.** WHIR public verification succeeds through `verify_public` without witness-side data. The typed CP proof enforces commitment-opening consistency, fold replay, challenge digest and beta binding, folded-output consistency, original Ajtai openings, and original R1CS witness algebra. Legacy/full `verify` remains available as a compatibility/debug path.
9. **CP-R1CS q-wrap status.** Phase-A folded commitment/public-input q-wraps are range-constrained in the WHIR CP-R1CS encoding so they cannot be used as free BabyBear slack for forged folded outputs. Phase-B embedded Hadamard rows remain part of the legacy CP-R1CS core, while authoritative public CP verification is provided by the full typed CP R1CS.
10. **WHIR security level** defaults to 100 bits. Tests that need faster parameters should opt into explicit test-only settings rather than weakening the default backend configuration.

---

## 14. Key References for Implementation

| Reference | What It Provides |
|---|---|
| LaBRADOR [BS23] | Folding challenge set S, random projection technique, lattice-based SNARK backend |
| LatticeFold+ [BC25] | Monomial embedding technique, decomposition RoK |
| Protostar [BC23] | Commit-and-prove compiler inspiration |
| [KLNO25] | Structured random projection `I ⊗ J` with sublinear verifier |
| [Baw+25] | Memory-efficient streaming sumcheck algorithm |
| [LFKN92] | Original sumcheck protocol |
| [GHL22] | Random projection lemma for norm preservation |
| [FMN24] | Coordinate-wise special soundness (Lemma 2.3), lattice polynomial commitments |
