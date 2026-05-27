# DESIGN.md

## Symphony Verifier Compression Plan

Concrete Rust-oriented design for moving verification from linear to sublinear.

> **Current status (2026-05-20): historical design note.** This file now lives
> under `docs/past_roadmaps/` and should be read as the pre-authority
> compressed-verifier design sketch. The current product ground truth is the
> WHIR+WHIR public route over `ProofBundleV2` / `PublicProofBundle`, with
> `Poseidon2BabyBear` public digests, `WhirSnark::has_authoritative_typed_cp()`
> true, and `verify_public` / `verify_v2` expected to pass using public data
> only. That route is authoritative but still a monolithic typed-CP baseline,
> not the final sublinear performance route. The current performance direction
> is the explicit SYMBT3/K6a/N8 line documented in
> `docs/whir_public_performance_north_star_plan.md`,
> `docs/path_to_native_multi.md`, `docs/protocols/whir.md`, and
> `docs/protocols/n8_accumulation_relation.md`.
>
> The module names below are illustrative. The implemented reusable pipeline
> lives mostly under `src/modular/{folding_core,transcript_core,digest_core,
> cp_relation_core,cp_backend_api,output_backend_api,proof_orchestrator,
> adapter_symphony}` plus WHIR-specific code under `src/snark/whir/`. WHIR
> public digest semantics are Poseidon2/BabyBear; SHA remains a compatibility
> path and this repository does not prove SHA-256 inside WHIR.

---

## Goal

The current implementation verifies in roughly linear time in the number of folded statements `k` because the verifier still sees or replays too much of the folding transcript and/or fold inputs.

The goal of this design is to make the **public verifier** check only:

1. a **compressed transcript commitment interface**,
2. a **compressed fold-input digest**,
3. the **folded output instance**,
4. one **CP proof**,
5. one **backend/PCS proof**,

while moving all linear replay work into the proof relation itself.

This matches the intended Symphony boundary:
- Fiat–Shamir is derived **outside** the proved relation,
- the CP-SNARK proves transcript correctness,
- the backend proof proves the folded statement,
- the verifier no longer linearly replays the fold.

---

## Design Principles

### 1. Keep the folding primitive unchanged

Do not rewrite the algebraic fold semantics. Keep your current folding code as the semantic source of truth.

### 2. Compress what the verifier sees

The verifier should not see:
- all per-instance inputs,
- all per-round transcript messages,
- all per-round commitments,
- all per-instance linear-combination terms.

It should see only digests/roots and the folded output.

### 3. Move all replay into the CP witness

Anything linear in `k` should be reconstructed inside the CP witness relation:
- transcript decoding,
- per-instance proof-object recovery,
- linear combination checks,
- fold-input reconstruction,
- consistency of the folded output.

### 4. Keep FS derivation outside the backend circuit

The verifier derives challenges from public transcript digests and metadata. The CP proof only proves consistency with those derived challenges.

---

## High-Level Architecture

```text
                        ┌──────────────────────────┐
                        │   Original input batch   │
                        └────────────┬─────────────┘
                                     │
                                     ▼
                        ┌──────────────────────────┐
                        │   Symphony fold engine   │
                        │  (semantic transcript)   │
                        └────────────┬─────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
         ┌──────────────────────┐         ┌──────────────────────┐
         │ FS transcript digest │         │  Fold input digest   │
         │      fs_root         │         │      fold_root       │
         └──────────┬───────────┘         └──────────┬───────────┘
                    │                                 │
                    └──────────────┬──────────────────┘
                                   ▼
                      ┌──────────────────────────────┐
                      │     CP public instance       │
                      │ (roots + x_folded + digests) │
                      └──────────────┬───────────────┘
                                     │
                     witness: transcript bytes, openings,
                     parsed rounds, fold inputs, etc.
                                     │
                                     ▼
                      ┌──────────────────────────────┐
                      │       CP-SNARK backend       │
                      │   (recommended: Spartan)     │
                      └──────────────┬───────────────┘
                                     │
                                     ▼
                      ┌──────────────────────────────┐
                      │ backend folded statement /   │
                      │ PCS / low-degree proof       │
                      │ (recommended: WHIR layer)    │
                      └──────────────┬───────────────┘
                                     │
                                     ▼
                      ┌──────────────────────────────┐
                      │      Public verifier         │
                      │ derive FS challenges         │
                      │ verify CP proof              │
                      │ verify backend proof         │
                      └──────────────────────────────┘
```

---

## Recommended Module Layout

```
src/
  folding/
    mod.rs
    transcript.rs
    semantics.rs
    digest.rs
    fold_inputs.rs

  cp/
    mod.rs
    relation.rs
    public_instance.rs
    witness.rs
    parser.rs
    prover.rs
    verifier.rs

  backend/
    mod.rs
    folded_statement.rs
    spartan_backend.rs        # if Spartan is the CP backend
    whir_wrapper.rs           # if WHIR is the PCS / outer wrapper

  verify/
    mod.rs
    public_verifier.rs
    challenge_derivation.rs

  types/
    mod.rs
    digest.rs
    commitments.rs
    instance.rs
    transcript.rs
```

---

## New Core Types

### `types/digest.rs`

```rust
pub type Digest32 = [u8; 32];
```

---

### `types/instance.rs`

```rust
use crate::types::commitments::Commitment;

#[derive(Clone, Debug)]
pub struct FoldedInstance<F> {
    pub commitment_star: Commitment,
    pub public_input_star: Vec<F>,
    pub eval_star: F,
}
```

This is the compressed folded output instance the verifier should ultimately care about.

---

### `cp/public_instance.rs`

```rust
use crate::types::digest::Digest32;
use crate::types::instance::FoldedInstance;

#[derive(Clone, Debug)]
pub struct CpPublicInstance<F> {
    /// Root/digest binding all FS commitments or transcript leaves.
    pub fs_root: Digest32,

    /// Root/digest binding all fold inputs used to derive x_folded.
    pub fold_root: Digest32,

    /// Folded output instance.
    pub x_folded: FoldedInstance<F>,

    /// Digest binding the derived challenge sequence.
    pub challenge_digest: Digest32,

    /// Digest of static public metadata used for challenge derivation.
    pub transcript_seed_digest: Digest32,
}
```

**Why this is the right public boundary**

Instead of exposing all `c_fs_i`, all per-instance commitments, and all per-instance values, we expose only compressed roots and the folded result. That is the key move that makes verification sublinear.

---

### `cp/witness.rs`

```rust
use crate::folding::transcript::TranscriptBytes;
use crate::folding::fold_inputs::FoldInput;
use crate::types::commitments::Opening;

#[derive(Clone, Debug)]
pub struct CpWitness<F> {
    /// Full serialized transcript bytes.
    pub transcript_bytes: TranscriptBytes,

    /// Openings to the FS commitments.
    pub fs_openings: Vec<Opening>,

    /// All fold inputs used internally to compute x_folded.
    pub fold_inputs: Vec<FoldInput<F>>,

    /// Parsed round-level transcript objects.
    pub parsed_rounds: Vec<ParsedRound<F>>,
}

#[derive(Clone, Debug)]
pub struct ParsedRound<F> {
    pub round_index: u32,
    pub round_message_bytes: Vec<u8>,
    pub challenge_values: Vec<F>,
    pub encoded_objects: Vec<EncodedProofObject<F>>,
}

#[derive(Clone, Debug)]
pub enum EncodedProofObject<F> {
    HadamardSumcheck { bytes: Vec<u8> },
    MonomialSumcheck { bytes: Vec<u8> },
    ProjectedValues { values: Vec<F> },
    EvaluationMatrix { bytes: Vec<u8> },
    MonomialCommitments { bytes: Vec<u8> },
}
```

> The witness is intentionally large — that is okay. The witness can stay linear. The verifier should not.

---

### `folding/fold_inputs.rs`

```rust
use crate::types::commitments::Commitment;

#[derive(Clone, Debug)]
pub struct FoldInput<F> {
    pub commitment: Commitment,
    pub public_input: Vec<F>,
    pub eval_value: F,
}
```

These are the per-instance objects that are currently likely forcing linear verification. They must become witness-only data, bound by `fold_root`.

---

### `folding/transcript.rs`

```rust
#[derive(Clone, Debug)]
pub struct TranscriptBytes(pub Vec<u8>);

pub trait DeterministicTranscriptCodec<T> {
    fn encode(value: &T) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Result<T, TranscriptDecodeError>;
}

#[derive(Debug)]
pub enum TranscriptDecodeError {
    InvalidFormat,
    InvalidLength,
    InvalidObjectTag,
    SemanticMismatch,
}
```

The CP relation will rely on deterministic parsing: transcript bytes must decode uniquely, and decoded objects must satisfy round semantics.

---

### `folding/digest.rs`

```rust
use crate::folding::fold_inputs::FoldInput;
use crate::types::digest::Digest32;

pub trait Digestible {
    fn digest(&self) -> Digest32;
}

pub fn digest_fold_inputs<F: CanonicalDigest>(inputs: &[FoldInput<F>]) -> Digest32 {
    let mut hasher = blake3::Hasher::new();
    for input in inputs {
        hasher.update(&input.commitment.to_bytes());
        for x in &input.public_input {
            hasher.update(&x.canonical_bytes());
        }
        hasher.update(&input.eval_value.canonical_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub trait CanonicalDigest {
    fn canonical_bytes(&self) -> &[u8];
}
```

The exact hash is replaceable. The important requirements are: deterministic, canonical, and shared by prover and verifier.

---

## Challenge Derivation

### `verify/challenge_derivation.rs`

```rust
use crate::types::digest::Digest32;

#[derive(Clone, Debug)]
pub struct ChallengeDigest(pub Digest32);

pub trait ChallengeDeriver<F> {
    fn derive_all(
        transcript_seed_digest: &Digest32,
        fs_root: &Digest32,
    ) -> DerivedChallenges<F>;
}

#[derive(Clone, Debug)]
pub struct DerivedChallenges<F> {
    pub beta: Vec<F>,
    pub per_round: Vec<Vec<F>>,
    pub digest: Digest32,
}
```

**Important design rule**

The verifier should derive challenges from compressed public metadata and the compressed transcript commitment interface — not from witness data and not from linearly replayed transcript messages. This preserves the Symphony philosophy: FS outside the proof, consistency proved inside the CP relation.

---

## CP Relation Structure

### `cp/relation.rs`

```rust
use crate::cp::public_instance::CpPublicInstance;
use crate::cp::witness::CpWitness;
use crate::verify::challenge_derivation::DerivedChallenges;

pub trait CpRelation<F> {
    fn check(
        public: &CpPublicInstance<F>,
        challenges: &DerivedChallenges<F>,
        witness: &CpWitness<F>,
    ) -> Result<(), CpRelationError>;
}

#[derive(Debug)]
pub enum CpRelationError {
    TranscriptParseFailure,
    FsCommitmentMismatch,
    ChallengeMismatch,
    FoldDigestMismatch,
    FoldedInstanceMismatch,
    EncodedProofObjectMismatch,
    SemanticRelationFailure,
}
```

**What `CpRelation::check` must enforce**

1. `transcript_bytes` parses into the expected round structure.
2. The implied FS commitment sequence is consistent with `public.fs_root`.
3. The derived challenge sequence matches `public.challenge_digest`.
4. The internal `fold_inputs` hash to `public.fold_root`.
5. The folded output computed from the witness fold inputs and derived beta equals `public.x_folded`.
6. The parsed proof objects are well-formed and semantically valid for the fold relation.

---

## Folding Reconstruction Helper

### `folding/semantics.rs`

```rust
use crate::folding::fold_inputs::FoldInput;
use crate::types::instance::FoldedInstance;

pub fn fold_inputs_with_beta<F>(
    inputs: &[FoldInput<F>],
    beta: &[F],
) -> Result<FoldedInstance<F>, FoldSemanticsError>
where
    F: Clone
        + core::ops::Add<Output = F>
        + core::ops::Mul<Output = F>
        + Zero,
{
    if inputs.len() != beta.len() {
        return Err(FoldSemanticsError::MismatchedArity);
    }

    let mut commitment_star = Commitment::zero();
    let mut public_input_star = vec![F::zero(); inputs[0].public_input.len()];
    let mut eval_star = F::zero();

    for (input, coeff) in inputs.iter().zip(beta.iter()) {
        commitment_star = commitment_star.add_scaled(&input.commitment, coeff);
        for (dst, src) in public_input_star.iter_mut().zip(input.public_input.iter()) {
            *dst = dst.clone() + coeff.clone() * src.clone();
        }
        eval_star = eval_star + coeff.clone() * input.eval_value.clone();
    }

    Ok(FoldedInstance {
        commitment_star,
        public_input_star,
        eval_star,
    })
}

#[derive(Debug)]
pub enum FoldSemanticsError {
    MismatchedArity,
    EmptyInputs,
}
```

> This is the logic the verifier should stop doing publicly. It should become part of the CP witness check.

---

## FS Commitment Compression

You currently likely expose all `c_fs_i` directly. To make the verifier sublinear, replace this with a tree root.

### `folding/digest_fs.rs`

```rust
use crate::types::digest::Digest32;

#[derive(Clone, Debug)]
pub struct FsCommitmentLeaf {
    pub round_index: u32,
    pub commitment_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct FsCommitmentRoot {
    pub root: Digest32,
}

pub fn digest_fs_commitments(leaves: &[FsCommitmentLeaf]) -> FsCommitmentRoot {
    let mut hasher = blake3::Hasher::new();
    for leaf in leaves {
        hasher.update(&leaf.round_index.to_le_bytes());
        hasher.update(&(leaf.commitment_bytes.len() as u64).to_le_bytes());
        hasher.update(&leaf.commitment_bytes);
    }
    FsCommitmentRoot {
        root: *hasher.finalize().as_bytes(),
    }
}
```

**Transition plan**

If changing FS derivation immediately is too invasive:
- keep raw `c_fs_i` public for one intermediate step,
- first remove fold replay from the verifier,
- then compress the transcript commitment interface.

This gives a practical staged migration path.

---

## Public Verifier API

### `verify/public_verifier.rs`

```rust
use crate::backend::folded_statement::BackendProof;
use crate::cp::public_instance::CpPublicInstance;
use crate::verify::challenge_derivation::{ChallengeDeriver, DerivedChallenges};

pub struct PublicVerifier<CPV, BPV, CD> {
    pub cp_verifier: CPV,
    pub backend_verifier: BPV,
    pub challenge_deriver: CD,
}

impl<F, CPV, BPV, CD> PublicVerifier<CPV, BPV, CD>
where
    CPV: CpProofVerifier<F>,
    BPV: BackendProofVerifier<F>,
    CD: ChallengeDeriver<F>,
{
    pub fn verify(
        &self,
        public: &CpPublicInstance<F>,
        cp_proof: &CPProof,
        backend_proof: &BackendProof,
    ) -> Result<(), PublicVerifyError> {
        let challenges = self
            .challenge_deriver
            .derive_all(&public.transcript_seed_digest, &public.fs_root);

        if challenges.digest != public.challenge_digest {
            return Err(PublicVerifyError::ChallengeDigestMismatch);
        }

        self.cp_verifier.verify(public, &challenges, cp_proof)?;
        self.backend_verifier.verify(&public.x_folded, backend_proof)?;

        Ok(())
    }
}

pub trait CpProofVerifier<F> {
    fn verify(
        &self,
        public: &CpPublicInstance<F>,
        challenges: &DerivedChallenges<F>,
        proof: &CPProof,
    ) -> Result<(), PublicVerifyError>;
}

pub trait BackendProofVerifier<F> {
    fn verify(
        &self,
        folded: &crate::types::instance::FoldedInstance<F>,
        proof: &BackendProof,
    ) -> Result<(), PublicVerifyError>;
}

#[derive(Debug)]
pub enum PublicVerifyError {
    ChallengeDigestMismatch,
    CpVerifyFailed,
    BackendVerifyFailed,
}
```

**Note what is gone**

There is no per-instance replay, no loop over fold inputs, no loop over per-instance proof objects, and no loop over transcript messages. That is the target design.

---

## CP Prover API

### `cp/prover.rs`

```rust
use crate::cp::public_instance::CpPublicInstance;
use crate::cp::witness::CpWitness;

pub trait CpBackendProver<F> {
    fn prove(
        &self,
        public: &CpPublicInstance<F>,
        witness: &CpWitness<F>,
    ) -> Result<CPProof, CpBackendError>;
}

#[derive(Debug)]
pub enum CpBackendError {
    RelationUnsatisfied,
    BackendFailure,
}
```

The CP backend should be able to prove a generic NP relation over transcript decoding, fold input consistency, and folded output derivation. This is why Spartan is a good backend candidate here.

---

## Backend Folded Statement API

### `backend/folded_statement.rs`

```rust
use crate::types::instance::FoldedInstance;

#[derive(Clone, Debug)]
pub struct BackendStatement<F> {
    pub folded_instance: FoldedInstance<F>,
}

#[derive(Clone, Debug)]
pub struct BackendWitness {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BackendProof {
    pub bytes: Vec<u8>,
}
```

This module is deliberately small. The verifier should only see the final folded statement and one backend proof.

---

## Historical Engine Split Recommendation

Given the earlier IOR construction and CP relation, this note recommended
**Spartan** as the CP-SNARK backend and **WHIR** as the PCS / low-degree /
outer wrapper engine.

That is not the current product route. The implemented authoritative public
path uses WHIR typed CP and WHIR typed output directly; `SpartanSnark` remains
available as a backend, but product `verify_public` does not depend on Spartan
for CP authority. The live performance work is SYMBT3: CP-aware WHIR oracle
relations, explicit K6a NonZK integrity accumulation, and the N8 integrated
one-WHIR NonZK accumulation route. Keep this section as historical rationale
for a split-backend architecture, not as current routing guidance.

**Reason:** The CP relation is transcript-semantic and generic; WHIR is more naturally suited to low-degree and evaluation consistency in IOR_C, which your formal IOR_C writeup already places there naturally.

```
Symphony fold semantics
    ↓
CP relation over transcript + fold inputs
    ↓ (Spartan)
CP proof
    ↓
Folded witness / PCS statement
    ↓ (WHIR)
Low-degree backend proof
```

---

## Migration Plan

### Phase 1 — Introduce compressed public types

Add `CpPublicInstance`, `FoldInput`, `FoldedInstance`, and `Digest32`. No behavior change yet.

### Phase 2 — Move fold replay behind `fold_root`

Current verifier still likely loops over all fold inputs. Replace that with `fold_root` as public, `fold_inputs` as witness, and fold replay moved into `CpRelation::check`. This is the single biggest win.

### Phase 3 — Compress FS interface

Current verifier likely still sees all `c_fs_i`. Replace with `fs_root`, `challenge_digest`, and deterministic challenge derivation from compressed public data.

### Phase 4 — Constant-size verifier path

Refactor the public verifier so it only derives challenges, verifies the CP proof, and verifies the backend proof. No direct transcript replay remains.

---

## Benchmarks to Add

After each phase, benchmark the following:

**1. Public verifier time vs `k`**
Expected: current roughly linear → target much flatter.

**2. Public input size vs `k`**
Expected: current growing → target near-constant.

**3. Public verifier allocations vs `k`**
Expected: current growing → target mostly flat.

**4. CP witness size vs `k`**
Expected: likely still linear — which is okay.

The success criterion is: witness grows, public interface stops growing. That is how you buy succinct verification.

---

## Common Pitfalls

**Pitfall 1** — Expose `fold_root` but still pass all fold inputs publicly for debugging. This defeats the point.

**Pitfall 2** — Expose `fs_root` but keep replaying full transcript semantics publicly. This also defeats the point.

**Pitfall 3** — Let the backend verifier see per-instance openings instead of only folded ones. That leaks linearity back into the verifier.

**Pitfall 4** — Use WHIR to prove transcript structure. That is usually the wrong abstraction layer. Keep WHIR focused on low-degree/evaluation checks.

---

## Historical Immediate TODO List

```
[x] Add the modular CP public/witness model (`CpPublicStatement`,
    `CpPublicInstance`, `CpWitnessBundle`) under `src/modular/cp_relation_core`.
[x] Add digest helpers under `src/modular/digest_core`; WHIR public proofs use
    `Poseidon2BabyBear` public digests.
[x] Make WHIR typed CP authoritative for the product public route.
[x] Keep challenge derivation outside the WHIR typed CP relation.
[x] Add `public_verify_v2_vs_k` for public-only verification.
[ ] Continue performance compression through SYMBT3/K6a/N8 rather than treating
    this generic sketch as the active implementation plan.
```

---

## Minimal First Implementation Target

If you do not want to rewrite everything at once, do this first:

1. Keep raw `c_fs_i` public for now.
2. Introduce `fold_root`.
3. Move all folded-input replay into the CP witness.
4. Keep only `c_fs_i`, `x_folded`, and challenge metadata public.

This already removes the biggest linear verifier bottleneck. Then later, replace raw `c_fs_i` with `fs_root`. That gives you a practical staged rollout.

---

## Final Summary

To make Symphony verification sublinear in your crate:

1. Keep the folding primitive as-is.
2. Compress fold inputs behind `fold_root`.
3. Compress FS commitments behind `fs_root`.
4. Move all transcript replay and linear combination checks into the CP witness relation.
5. Keep Fiat–Shamir derivation outside the backend circuit.
6. Let the public verifier only check: compressed public instance, CP proof, and folded backend proof.

This is the cleanest path from a linear verifier prototype to a succinct verifier architecture.
