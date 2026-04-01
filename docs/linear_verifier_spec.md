# Making Symphony Verification Sublinear: Implementation Plan

This document explains how to evolve a current **linear-in-$k$** verification path into a **sublinear / near-constant public verifier path** in a Symphony-style system.

The target audience is an implementer who already has:

- a working **folding primitive**,
- a **Fiat–Shamir commitment transcript**,
- a **CP-SNARK** that proves transcript correctness,
- and optionally a **PCS / low-degree backend** such as WHIR.

The core idea is:

> Do **not** let the public verifier re-process per-instance transcript structure or per-instance folded objects.
> Move that work into the **CP proof**, and expose only a compressed public interface:
>
> - the FS commitments,
> - the folded output instance,
> - a tiny set of derived challenges / digests,
> - and one or two succinct proofs.

This is exactly the direction motivated by Symphony: avoid embedding Fiat–Shamir inside the circuit, use a CP-SNARK to prove transcript correctness, and compress large folding proofs into a succinct object.

---

## 1. What "linear verification" usually means in your current prototype

If your verification still grows roughly linearly with the number of folded statements $k$, it usually means one or more of the following is still happening on the public verifier side:

1. The verifier iterates over all folded instances to recompute the folded output.
2. The verifier replays a large portion of the folding transcript explicitly.
3. The verifier checks many per-instance algebraic consistency conditions itself.
4. The verifier reads too many public objects derived from the transcript.
5. The CP proof is not sufficiently **compressing the statement boundary**.

In other words, the current verifier is still acting a bit like a folding verifier, instead of acting like a **succinct verifier of a proof that folding was done correctly**.

That is the key architectural mistake to remove.

---

## 2. The correct target boundary

The verifier should eventually do only this:

1. Read a **small public statement**:
   - folded output instance $x_o$,
   - FS commitments $\{c_{fs,i}\}$ or a digest thereof,
   - optional small metadata,
   - final backend proof(s).

2. Recompute the Fiat–Shamir challenges from the public transcript commitments:

$$r_i = \mathsf{FS}(x,\, c_{fs,1},\, \dots,\, c_{fs,i})$$

outside the circuit. This is one of Symphony's central ideas.

3. Verify a **CP-SNARK** whose public input is only:
   - the transcript commitment interface,
   - the derived challenges,
   - the folded output instance.

4. Verify the backend SNARK / PCS proof for the folded statement.

The verifier should **not**:
- re-open all transcript messages,
- re-check all per-instance folding equations,
- re-scan all folded commitments,
- or linearly combine all original instances itself.

Those must be inside the proof relation.

---

## 3. The exact design goal

You want to transform:

$$\text{Verifier cost} \approx O(k)$$

into something closer to:

$$O(\log k) \quad \text{or} \quad O(1)$$

up to:
- proof verification cost,
- transcript hash derivation,
- a few PCS openings,
- and small metadata checks.

In practice, "sublinear" here usually means:

- **constant-sized public interface**,
- **constant number of backend verifier calls**,
- **constant number of PCS openings**,
- **constant-size folded instance**,
- and at most **logarithmic transcript commitment overhead**.

---

## 4. The high-level strategy

There are **four implementation moves** needed.

### Move A — Shrink the CP public instance

The public input to the CP-SNARK must stop exposing per-instance structure.

Instead of making the public instance contain:
- all per-instance commitments,
- all per-instance values,
- all per-instance folded contributions,

you should expose only:
- a transcript commitment digest,
- the folded output instance $x_o$,
- and the derived challenges.

### Move B — Internalize the folding replay

All per-instance replay logic should move into the CP witness relation.

That means the CP witness contains:
- transcript bytes,
- encoded per-instance GR1CS proof objects,
- linear-combination witnesses,
- openings to FS commitments,

and the CP circuit checks:
- they parse correctly,
- they satisfy transcript structure,
- they induce the exact folded output.

### Move C — Compress the transcript commitment interface

Instead of giving the verifier a linear number of public FS commitments, replace them with:
- a Merkle root,
- a vector commitment root,
- or a tree-structured digest of all FS commitments.

Then only a **small digest** becomes public.

### Move D — Separate transcript correctness from PCS correctness

The CP proof should prove transcript semantics.
The PCS/WHIR proof should prove low-degree/evaluation semantics.
The public verifier should see only the succinct outputs of both.

---

## 5. Concrete implementation architecture

### 5.1 Public statement format

#### Current bad shape

A current linear verifier often has a public input roughly like:

```text
(
  c_fs_1, ..., c_fs_t,
  per_instance_commitments,
  per_instance_inputs,
  beta,
  per_round_values,
  x_o
)
```

This is too large.

#### Desired shape

Replace it with:

```rust
CPPublicInstance {
  fs_root: Digest,
  fold_root: Digest,
  x_folded: FoldedInstance,
  transcript_seed_digest: Digest,
  challenge_digest: Digest,
}
```

Where:
- `fs_root` commits to all FS transcript commitments or messages.
- `fold_root` commits to the per-instance fold inputs.
- `x_folded` is the final folded instance.
- `transcript_seed_digest` commits to all static public metadata needed for FS derivation.
- `challenge_digest` optionally binds the derived challenge sequence.

The verifier then uses `fs_root`, `transcript_seed_digest`, and deterministic reconstruction rules to derive all FS challenges outside the circuit.

#### Why this helps

Now the verifier's public input size stops growing with $k$. That is the first and most important step toward sublinear verification.

---

### 5.2 Transcript commitment compression

Your current system likely exposes each $c_{fs,i}$ separately. That is fine for a prototype, but if the verifier reads all of them, verification stays linear.

#### Replace linear FS commitment exposure with a tree

Build an `FSCommitTree` where each leaf is either:
- a raw FS commitment $c_{fs,i}$, or
- a digest of a round message + its commitment.

Publish only `fs_root`. Then the CP witness contains:
- all leaves,
- all transcript bytes,
- all openings,
- and optionally Merkle paths if the CP relation needs them.

The public verifier sees only the root.

#### Implementation sketch

```rust
pub struct FsLeaf {
    pub round_index: u32,
    pub commitment: [u8; 32],
}

pub struct FsCommitTree {
    pub root: [u8; 32],
}
```

At prove time:
1. Build leaves from all $c_{fs,i}$.
2. Merkleize them.
3. Expose only `root`.

Inside the CP relation:
- Parse transcript bytes.
- Reconstruct the expected per-round messages.
- Verify that the implied commitment sequence hashes into the published root.

> **Important note:** This does not mean "verify Merkle inside the public verifier repeatedly." The public verifier only sees one root. The CP backend proves consistency.

---

### 5.3 Fold input compression

If the verifier currently reads all per-instance folded inputs, that is another source of linearity.

#### Replace explicit per-instance public exposure with a fold input digest

```rust
pub struct FoldInputDigest {
    pub root: [u8; 32],
}
```

This digest binds:
- original per-instance commitments,
- public inputs,
- evaluation values,
- metadata required by the folding rule.

The CP relation then proves:

> The witness transcript internally references a set of fold inputs whose digest is `fold_root`, and the published folded instance `x_folded` is exactly their challenge-weighted linear combination.

Now the verifier does not read all folded inputs.

---

### 5.4 Move all linear combinations inside the CP relation

This is the biggest practical change.

#### Current linear verifier pattern

```rust
for instance in instances {
    c_star += beta_i * instance.commitment;
    x_star += beta_i * instance.public_input;
    v_star += beta_i * instance.eval_value;
}
check(x_o == (c_star, x_star, v_star));
```

This makes verification linear.

#### Desired pattern

Move that computation into the CP proof relation.

The public verifier only checks:

```rust
verify_cp_snark(public_instance, cp_proof)
```

where the CP statement says:

> There exists a transcript and folded input set consistent with `fold_root` such that the folded output `x_o` equals the $\beta$-weighted combination of the folded inputs.

#### Result

The verifier no longer iterates over the folded inputs. That is the main mechanism by which linear verification disappears.

---

## 6. The CP relation you actually want

You previously described a CP relation of the form:
- **witness:** openings $\{o_i\}$, full folding transcript bytes
- **public:** $\{c_{fs,i}\}$, folded instance $x_o$, derived challenges
- **relation:**
  1. openings match commitments,
  2. transcript bytes decode into valid GR1CS proofs,
  3. challenges are the ones derived from public transcript data,
  4. $x_o$ is the correctly folded output.

To get sublinear verification, refine this relation as follows.

### 6.1 New public instance for CP

Instead of:

```
({c_fs_i}, x_o, challenges)
```

use:

```
(fs_root, fold_root, x_o, challenge_digest)
```

Optionally include `transcript_seed_digest`.

### 6.2 New witness for CP

```rust
(
  full_transcript_bytes,
  all round messages,
  all openings o_i,
  all fold inputs,
  all parsing witnesses,
  all per-instance proof objects
)
```

### 6.3 New CP relation

The CP-SNARK proves that:

1. The witness transcript bytes parse into the deterministic folding transcript format.
2. The implied round messages open the FS commitments whose compressed digest is `fs_root`.
3. The Fiat–Shamir challenge sequence derived from the compressed transcript interface matches `challenge_digest`.
4. The transcript contains a set of fold inputs whose digest is `fold_root`.
5. The published folded output `x_o` is exactly the $\beta$-weighted linear combination of those folded inputs.
6. All per-instance GR1CS subproof objects inside the transcript are validly encoded and satisfy the expected internal consistency constraints.

#### Why this helps

Every linear-in-$k$ operation now lives inside the proof, not inside the public verifier.

---

## 7. How to derive challenges without linear verification

A common confusion is:

> "If I compress the commitments, how can the verifier still derive the FS challenges?"

There are two options.

### Option 1 — Keep all $c_{fs,i}$ public, but make everything else compressed

This still reduces verification significantly if your main linearity came from replaying the full fold logic rather than from reading the commitments. This is the simplest transition step.

### Option 2 — Replace $\{c_{fs,i}\}$ with a root and derive a transcript digest

The verifier derives challenges from a small digest interface rather than raw commitments directly. This requires changing the FS definition so that challenges are derived from:

$$\mathsf{FS}(\text{public\_metadata},\, \text{fs\_root},\, \text{round\_index},\, \text{previous\_digest})$$

instead of raw per-round commitments. This is a larger design change, but it gives much better verifier compression.

### Recommendation

Implement **Option 1** first, then move to **Option 2** if needed. This gives you a smooth path:
- First remove per-instance fold replay from the verifier.
- Then compress the FS public interface.

---

## 8. The backend choice that best supports this

For this compressed CP relation, the backend should be good at proving:
- transcript parsing,
- linear combinations,
- structured algebraic consistency,
- digest consistency.

This is why, given your IOR construction, **Spartan-like generic algebraic proving** is often the better engine for the CP relation.

Keep **WHIR** for:
- PCS,
- low-degree extraction,
- evaluation consistency,
- outer committed wrapper.

That is the cleanest decomposition:
- **CP backend** handles transcript correctness.
- **WHIR backend** handles low-degree correctness.

---

## 9. Making the outer verifier sublinear too

Your current public verifier may also still be linear because of PCS checks.

### 9.1 Use a constant-number opening interface

Do not expose per-instance evaluation openings. Instead expose only:
- folded oracle commitments,
- a constant number of evaluation points,
- a constant number of opening proofs.

### 9.2 Verify only folded evaluations

The verifier should check something like:

$$v_{\text{next}} = (1 - \gamma)\,v_{\text{acc}} + \gamma\,v_{\text{sq}}$$

at one or a few points — not all per-instance evaluations.

This is exactly the idea in your IOR_C writeup: use out-of-domain evaluation plus low-degree extraction to enforce global linearity.

So if you already have WHIR in the outer wrapper, the verifier should only perform:
- a constant number of WHIR openings/checks,
- a constant number of affine checks on extracted values.

That side should then also become sublinear / near-constant.

---

## 10. Step-by-step implementation roadmap

### Phase 1 — Remove public linear fold replay

**Goal:** Stop public verification from iterating over all folded instances.

**Tasks:**
- Introduce `fold_root`.
- Put all per-instance fold inputs into the CP witness.
- Change the CP relation so it proves:
  - fold inputs hash to `fold_root`,
  - `x_o` is the correct $\beta$-weighted combination.

**Result:** Verification no longer does explicit folding replay.

---

### Phase 2 — Shrink CP public input

**Goal:** Public CP input size should stop growing with $k$.

**Tasks:**
- Replace public arrays with digests: `fs_root`, `fold_root`, `challenge_digest`.
- Keep only `x_o` plus a tiny metadata bundle public.

**Result:** Verifier sees constant-size CP statement metadata.

---

### Phase 3 — Keep FS derivation outside the proof, but compressed

**Goal:** Retain Symphony's central advantage.

**Tasks:**
- Define a deterministic public transcript seed interface.
- Make verifier derive challenges from compressed transcript commitments/digests.
- Have CP prove only consistency with those challenges.

**Result:** No FS hash gadget in-circuit, and no linear transcript replay outside.

---

### Phase 4 — Constant-number PCS verification

**Goal:** Outer verifier no longer scales with number of witness objects.

**Tasks:**
- Ensure WHIR verification uses a constant number of folded commitments/openings.
- Bind only folded/effective evaluations, not per-instance evaluations.
- Keep cross-oracle linearity checks at a constant number of points.

**Result:** The PCS side also becomes near-constant.

---

## 11. Suggested data structures

```rust
pub struct FoldedInstance {
    pub commitment_star: Commitment,
    pub public_input_star: Vec<FieldElement>,
    pub eval_star: FieldElement,
}

pub struct CpPublicInstance {
    pub fs_root: Digest,
    pub fold_root: Digest,
    pub x_folded: FoldedInstance,
    pub challenge_digest: Digest,
    pub transcript_seed_digest: Digest,
}

pub struct CpWitness {
    pub transcript_bytes: Vec<u8>,
    pub fs_openings: Vec<Opening>,
    pub fold_inputs: Vec<FoldInput>,
    pub parsed_rounds: Vec<ParsedRound>,
}
```

And for the verifier:

```rust
pub fn verify_compiled_folding(
    public: &CpPublicInstance,
    cp_proof: &CpProof,
    backend_proof: &BackendProof,
) -> bool {
    let challenges = derive_challenges(
        &public.transcript_seed_digest,
        &public.fs_root,
        &public.challenge_digest,
    );

    verify_cp(public, &challenges, cp_proof)
        && verify_backend(&public.x_folded, backend_proof)
}
```

Notice what is missing:
- no loop over all folded inputs,
- no loop over all transcript objects,
- no loop over all GR1CS subproofs,
- no per-instance replay.

That is the whole point.

---

## 12. How to test whether you succeeded

You will know verification became sublinear when:

**Benchmark symptom 1:** `verify(k)` grows much slower than linearly — ideally almost flat.

**Benchmark symptom 2:** Public input size stops scaling with $k$.

**Benchmark symptom 3:** Verifier allocations stop scaling significantly with $k$.

**Benchmark symptom 4:** The CP witness grows, but the CP public instance stays nearly constant.

That last point is a success, not a problem. You are intentionally moving cost from public verification into proof generation.

---

## 13. Common mistakes

**Mistake 1:** Keeping `x_o` compressed but still exposing all folded inputs publicly. This still leaves verification linear.

**Mistake 2:** Compressing commitments but still replaying transcript structure outside the CP proof. This keeps verifier work linear in practice.

**Mistake 3:** Letting WHIR re-prove transcript semantics. WHIR should prove low-degree/evaluation semantics, not transcript parsing semantics.

**Mistake 4:** Changing the FS definition in a way that reintroduces hash checks into the circuit. That would defeat the main Symphony advantage.

---

## 14. Recommended final architecture

| Layer | Component | Role |
|---|---|---|
| **Folding layer** | Symphony folding | High-arity algebraic reduction |
| **Transcript correctness layer** | CP-SNARK | Proves transcript semantics; public input: `fs_root`, `fold_root`, `x_folded`, compressed challenge metadata; witness: full transcript, openings, fold inputs, parsing witnesses |
| **Low-degree / PCS layer** | WHIR | Proves low-degree/evaluation consistency for folded witness objects only |
| **Public verifier** | — | Derives challenges from compressed transcript interface; verifies one CP proof; verifies one backend/PCS proof; performs a constant number of affine consistency checks |

That is how you move from linear verification toward sublinear verification.

---

## 15. Final recommendation

Implement this in two passes:

**First pass:** Make verification stop replaying all fold inputs. This alone will likely give you the biggest improvement.

**Second pass:** Compress FS commitments and fold inputs into digests/roots. This gives you the stronger sublinear public interface.

If you try to do both at once, debugging becomes much harder.

---

## 16. Short summary

To make Symphony verification sublinear:

1. Do not expose per-instance fold inputs publicly.
2. Commit to them with a digest/root.
3. Move all linear-combination replay into the CP witness relation.
4. Expose only compressed transcript commitments plus the folded output instance.
5. Keep Fiat–Shamir derivation outside the circuit, but from compressed public transcript data.
6. Use the PCS only for folded witness objects, with a constant number of opening checks.

That is the clean path from a linear prototype verifier to a succinct verifier.
