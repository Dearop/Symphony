# Updated Plan for Writing `report/main.tex`

> **Current audit status (2026-05-20):** `report/main.tex` now exists and its
> introduction already distinguishes the default product `verify_public` route,
> K6a, N8, and the SYMBT3/native roadmap. The body is still largely a section
> scaffold: the route taxonomy table, route-specific construction/evaluation
> sections, and most implementation/soundness prose still need to be filled in.
> The file still ends with `\bibliography{references}`, and this checkout still
> does not contain `report/references.bib`.
>
> README status has been refreshed in this documentation pass and now matches
> the authoritative WHIR public-verifier state. Prefer the authoritative docs
> and code paths listed below for detailed maturity claims; use README only for
> broad orientation.

## 0. Executive recommendation

Write `report/main.tex` as a **route-aware implementation report**, not as a single undifferentiated “the system does accumulation” narrative.

After re-reading the repository docs, the cleanest and most accurate framing is:

1. **Current default product public verifier:** the authoritative WHIR+WHIR `verify_public` / `verify_v2` route over `ProofBundleV2` / `PublicProofBundle`.
2. **Current implemented full accumulator route:** the explicit opt-in **K6a** SYMBT3 accumulator integrity route.
3. **Current integrated alternative route:** N8 is already implemented as an explicit opt-in NonZK authoritative alternative route for same-shape, nonempty accumulation transitions, but it is **not** the default `verify_public` route and it is **not** yet production-reviewed.
4. **Current performance direction:** the broader SYMBT3/native multi-oracle roadmap aims to compress verifier cost beyond the current monolithic typed-CP baseline.

Because `report/main.tex` is titled **“WHIR Accumulation Through Lattice-Based Folding”**, the report should center the **verify\_public $\rightarrow$ K6a $\rightarrow$ N8** evolution rather than a full chronology of every intermediate native route. In particular:

- treat **K6a** as the main currently implemented full accumulator workload path;
- treat **N8** as the implemented integrated alternative accumulation route;
- and treat the monolithic WHIR public verifier as the **authoritative stepping stone / baseline** that established the public-only boundary and made later route comparisons meaningful.

That distinction is the most important thing to preserve.

---

## 1. Source-of-truth documents and precedence

Use the precedence from `AGENTS.md`, adjusted for the current file layout in this checkout.

### Primary sources for status and claims

1. `docs/past_roadmaps/whir_typed_cp_authority_plan.md`
2. `docs/whir_public_performance_north_star_plan.md`
3. `docs/whir_public_security_review.md`
4. `docs/past_roadmaps/public_proof_v2.md`
5. `docs/protocols/whir.md`
6. `docs/symphony_crate_spec.md`

### Additional route- and roadmap-specific sources

7. `docs/path_to_native_multi.md`
8. `docs/symbt3_multi_oracle_whir_accumulator_roadmap.md`
9. `README.md` for broad orientation only

### Important path drift to keep in mind

Historical docs and comments may refer to older root-level public-proof, WHIR,
or typed-CP authority-plan paths. In this checkout, the relevant files live at:

- `docs/past_roadmaps/public_proof_v2.md`
- `docs/protocols/whir.md`
- `docs/past_roadmaps/whir_typed_cp_authority_plan.md`

Use the **actual current paths** in the report notes and any internal planning citations.

### README status

`README.md` has been updated to reflect the current public-verifier state:
WHIR typed CP is authoritative, WHIR public proofs use `Poseidon2BabyBear`, and
`verify_public` succeeds for WHIR+WHIR using public data only. Use the
authoritative docs above for detailed maturity/status claims and README for
architecture and module overview.

---

## 2. Current repository reality the report must reflect

The report must distinguish several different “routes,” and it should treat the monolithic WHIR public verifier as a **stepping stone baseline** rather than as the conceptual center of the report.

## 2.1 Route taxonomy

| Route | Main APIs / benchmark names | What it is | Default `verify_public` route? | ZK status | Current status |
|---|---|---|---|---|---|
| **Authoritative product public verifier** | `prove_public`, `verify_public`, `prove_v2`, `verify_v2`, `public_verify_v2_vs_k` | WHIR typed-CP + typed-output public-only verification over `ProofBundleV2` / `PublicProofBundle` | **Yes** | Public-only verifier boundary; no witness-side fallback | **Implemented and authoritative; best presented as the stepping-stone baseline that established the public-only boundary** |
| **K6a explicit accumulator route** | `prove_public_symbt3_accumulator_non_zk_integrity`, `verify_public_symbt3_accumulator_non_zk_integrity`, `symbt3_accumulator_authority_vs_k`, `product_route_comparison_vs_k` | Explicit opt-in SYMBT3 ProductAuthority accumulator route | **No** | **NonZK integrity-only** | **Implemented; current full accumulator workload path** |
| **N8 integrated one-WHIR path** | `prove_symbt3_integrated_whir_from_claim_plan`, `verify_symbt3_integrated_whir_backend_from_verifier_input`, `symbt3_n8_integrated_authority_vs_k`, `accumulate_symbt3_n8_non_zk`, `verify_symbt3_n8_accumulation_non_zk`, `decide_symbt3_n8_accumulator_non_zk` | One-WHIR integrated explicit accumulation-authority path | **No** | **NonZK explicit route** | **Implemented as an explicit opt-in authoritative alternative for same-shape, nonempty transitions; not default `verify_public`, not ZK, not production-reviewed** |

### What this means for the report

- Do **not** present SYMBT3/N8 as “the current default product route.”
- Do **not** merge K6a, N8, and the monolithic product route into one claim.
- Do **not** imply the alternative accumulation route inherits the same review status as the default WHIR public verifier.
- Do describe N8 as **implemented**, **explicit opt-in**, **NonZK**, and **authoritative for its own explicit ACC.D accumulation boundary**, while also saying that it is **not** the default `verify_public` route and **not** yet production-reviewed.

---

## 2.2 The current authoritative product boundary

This is the clearest “what is true today” story, but for the report it should be treated mainly as the **authoritative stepping-stone baseline** rather than as the main conceptual destination.

From `docs/past_roadmaps/whir_typed_cp_authority_plan.md`, `docs/past_roadmaps/public_proof_v2.md`, `docs/whir_public_security_review.md`, and `docs/protocols/whir.md`:

- WHIR typed CP is authoritative for the public verifier boundary.
- WHIR public proofs use `Poseidon2BabyBear` public digests.
- `WhirSnark::has_authoritative_typed_cp()` is true.
- `verify_public` / `verify_v2` succeeds for WHIR+WHIR using public data only.
- The public proof boundary is `ProofBundleV2` / `PublicProofBundle` and `SymphonyProofV2` / `PublicSymphonyProof`.
- Public verification uses:
  - caller-supplied public inputs;
  - relation metadata / R1CS metadata;
  - public FS commitments;
  - `fs_root`, `fold_root`, `challenge_digest`, `transcript_seed_digest`;
  - public folded output;
  - WHIR CP proof;
  - WHIR output proof.
- Public verification must **not** read:
  - FS openings;
  - FS messages;
  - fold inputs;
  - folding proofs;
  - original witnesses;
  - folded witnesses;
  - CP witness bundles;
  - witness-side debug data.

This path is the **default product route** that `verify_public` exposes.

---

## 2.3 The current implemented full accumulator route

This is the route that best matches the current title and accumulation theme of `main.tex`.

From `docs/protocols/whir.md` and `docs/path_to_native_multi.md`:

- K6a is the current **full accumulator workload path**.
- It is:
  - explicit opt-in;
  - ProductAuthority;
  - NonZK integrity-only;
  - not privacy-preserving;
  - not the default `verify_public` route.
- K6b adds the side-by-side route comparison benchmark.

This is the best route to treat as the report’s **main accumulation construction**.

---

## 2.4 The current native / multi-oracle direction

From `docs/whir_public_performance_north_star_plan.md`, `docs/path_to_native_multi.md`, `docs/protocols/whir.md`, and `docs/symbt3_multi_oracle_whir_accumulator_roadmap.md`:

- The next performance target is **SYMBT3**.
- For the report-facing narrative, the native/multi-oracle line should mainly be used to explain how the system moves from the authoritative monolithic baseline toward more compressed accumulated verification.
- In that evolution, the two explicit accumulation routes worth centering are:
  - K6a as the current full accumulator workload path;
  - N8 as the implemented integrated one-WHIR alternative with its own ACC.P / ACC.V / ACC.D boundary.
- The multi-oracle roadmap document is explicit that:
  - it is about improving the **SYMBT3 K6a** accumulator after the current single-oracle baseline;
  - **Milestone 0 is implemented**;
  - later milestones remain roadmap work.

So the native / multi-oracle line is important to the report mainly as:

- performance roadmap,
- future work,
- and architectural motivation for the K6a $\rightarrow$ N8 evolution.

It is **not** the main current product verifier story.

---

## 3. Recommended scope for `main.tex`

## 3.1 Best overall framing

The strongest framing for the report is:

> Symphony provides a lattice-based folding framework with a WHIR backend. The repository now has an authoritative public-only WHIR verifier boundary, a separate explicit K6a accumulator route for NonZK integrity, and an active SYMBT3/native-oracle roadmap aimed at compressing verifier cost.

This lets the report do three things honestly:

1. explain the **implemented system**,
2. explain the **implemented accumulation route**,
3. explain the **performance roadmap** without overstating route maturity.

---

## 3.2 Recommended report center of gravity

Because the report title is about **accumulation through lattice-based folding**, the report should most likely:

- make **K6a** the central current accumulation construction;
- give **N8** a dedicated subsection as the implemented integrated alternative accumulation route;
- explain the **default product public verifier** as the authoritative stepping-stone baseline that established the public-only boundary and provides the comparison point;
- and treat the broader multi-oracle/native line as future/performance direction rather than as co-equal report protagonists.

### In other words

- **Main construction section:** K6a, with an N8 integrated-alternative subsection
- **Main product-boundary / soundness section:** default WHIR public verifier as authoritative baseline/stepping stone
- **Main future-work section:** SYMBT3 native/multi-oracle trajectory beyond the current implemented routes

---

## 3.3 Optional title refinement

The current title is usable, but a slightly more route-aware title would be safer, e.g.:

- **WHIR-Backed Accumulation Through Lattice-Based Folding in Symphony**
- **Accumulating WHIR Verification Claims via Lattice-Based Folding: Implementation and Roadmap**

If the current title is kept, the introduction should clarify early that the repo contains:

- an authoritative public verifier route,
- an explicit accumulator route,
- and a separate native/SYMBT3 roadmap.

---

## 4. Recommended narrative arc

A clean narrative arc is:

1. **Why accumulation is subtle for WHIR-like systems.** You are accumulating proof-validity claims / relations, not just proof bytes.
2. **Why Symphony is relevant.** Ajtai commitments, high-arity folding, and no hash-in-circuit overhead make this composition attractive.
3. **What had to be solved first.** The repository first established an authoritative WHIR public-only verifier boundary.
4. **How accumulation is currently instantiated.** The implemented full accumulator workload is the explicit K6a route, and N8 provides an implemented integrated alternative route.
5. **Why the monolithic public route is not the end state.** It is correct and authoritative, but still dominated by a large typed-CP relation, so it should be presented as a stepping-stone baseline.
6. **Where the system is heading.** SYMBT3, native multi-oracle compression, compressed public-boundary work, and the implemented-but-nondefault N8 route together target a much stronger verifier-cost profile.

That arc is consistent with the docs and with the current code/benchmark structure.

---

## 5. Section-by-section plan for `report/main.tex`

## 5.1 Abstract

### What the abstract should do

The abstract should mention all four layers:

- Symphony as the lattice-based folding framework;
- the authoritative WHIR public verifier boundary as the enabling baseline/stepping stone;
- the explicit K6a accumulation route as the current full accumulator workload path;
- N8 as an implemented integrated alternative accumulation route;
- the SYMBT3/native performance roadmap.

### Recommended content points

- The repo implements WHIR-backed public verification over a public-only proof boundary.
- That monolithic public verifier is best presented as the authoritative stepping-stone baseline that enabled later accumulation routes.
- The repo also implements an explicit opt-in K6a accumulation route for NonZK integrity.
- The repo now also implements an explicit N8 integrated accumulation route for same-shape, nonempty NonZK transitions.
- Current product public verification is authoritative but expensive because typed CP is large.
- The next performance direction is SYMBT3/native multi-oracle compression.

### Avoid in the abstract

- Do not imply N8 is the default product verifier; describe it as an implemented explicit alternative route with its own ACC.P / ACC.V / ACC.D boundary, not as the default route.
- Do not imply the accumulator route is privacy-preserving.
- Do not imply the whole system has already reached the performance north star.

---

## 5.2 Introduction

### Motivation

Explain:

- why proof aggregation/accumulation matters;
- why WHIR is attractive as a post-quantum-ish / hash-based backend;
- why simply “accumulating proof bytes” is the wrong abstraction;
- why Symphony’s no-hash-in-circuit approach matters.

### Problem statement

State the problem in route-aware terms:

- how to verify many WHIR-backed claims efficiently,
- while preserving public-only verification,
- and while keeping transcript, digest, beta, and folded-output semantics sound.

### Contributions

State contributions in implementation terms, not speculative ones:

1. implemented Symphony folding stack in Rust;
2. implemented WHIR backend with an authoritative public-only verifier boundary that serves as the stepping-stone baseline for later routes;
3. implemented K6a explicit accumulator route for NonZK integrity;
4. implemented N8 explicit integrated accumulation route for same-shape, nonempty NonZK transitions;
5. benchmarked the authoritative monolithic public route against the K6a route;
6. documented the SYMBT3/native multi-oracle roadmap.

### Add a “route distinction” paragraph early

The introduction should explicitly say something like:

> The repository currently exposes an authoritative default product route through `verify_public`, which should be understood as the stepping-stone baseline that established the public-only boundary. On top of that baseline, it exposes a separate explicit K6a accumulator route and an explicit N8 integrated accumulation route, alongside a further SYMBT3/native multi-oracle performance line. These are related, but they are not the same interface or maturity level.

---

## 5.3 Technical Overview

This section should contain a **route taxonomy table** very early.

### Recommended route table columns

- Route
- API / benchmark name
- What it proves / checks
- Default route?
- ZK status
- Current maturity

You can derive this directly from the route taxonomy in this plan.

### Subsections

#### High-Level Architecture

Describe the common stack:

- source R1CS / GR1CS claims,
- Ajtai commitments,
- folding,
- CP relation,
- folded output,
- WHIR backend.

#### Product public-verifier boundary

Explain the `ProofBundleV2` / `PublicProofBundle` public-only boundary.

#### Explicit accumulation routes

Explain that K6a is the current full accumulator workload route, and that N8 is an implemented integrated alternative accumulation route with its own explicit ACC.P / ACC.V / ACC.D boundary.

#### Native / multi-oracle roadmap

Briefly explain that the broader native/multi-oracle line is the performance/compression direction supporting the `verify_public` $\rightarrow$ K6a $\rightarrow$ N8 evolution, not the default route.

### Important note

This section should explicitly separate:

- **default product route**,
- **explicit accumulator route**,
- **native / roadmap routes**.

That separation is more important than any single algorithm block.

---

## 5.4 Preliminaries

Keep preliminaries focused on what the implementation actually uses.

### Recommended subsections

- Interactive oracle proofs and SNARKs
- WHIR
- Lattice commitments / Ajtai commitments
- High-arity folding
- Commit-and-prove SNARKs
- Public proof boundary and typed CP statements

### Best sources

- `docs/symphony_crate_spec.md`
- `docs/protocols/whir.md`
- `docs/past_roadmaps/public_proof_v2.md`

### What to emphasize

- Ajtai commitments replace Merkle-style in-circuit hash checking in the folding logic.
- Typed CP is a semantic relation, not just raw transcript-byte replay.
- The public verifier boundary is a concrete API boundary, not only a conceptual one.

---

## 5.5 WHIR Accumulation Through Lattice-Based Folding

This should be the report’s core section, and it should be **anchored to K6a**, with a smaller but explicit N8 subsection that presents the integrated alternative route. It should not spend comparable space on intermediate native wrapper routes.

### Strong recommendation

Do **not** leave this section as a fully generic accumulation sketch. Instead, explicitly say something like:

> In the current repository, the implemented full accumulator workload corresponds to the explicit K6a NonZK integrity route. The repository also implements an explicit N8 integrated accumulation route for same-shape, nonempty NonZK transitions. The default product `verify_public` route remains the monolithic authoritative WHIR typed-CP verifier, which is best understood here as the stepping-stone baseline rather than the main accumulation destination.

### Use K6a as the primary construction

The current `AccumulateWHIR` algorithm in `main.tex` is fine as a very high-level sketch, but it should either:

- be relabeled as the K6a accumulation flow; or
- be followed immediately by a paragraph saying the current concrete implementation is K6a.

### Subsections to write

#### Interface

Define:

- old accumulator,
- batch inputs / statements,
- new accumulator,
- accumulator proof,
- explicit route status and intended trust model.

#### K6a route

Explain the current full accumulator workload path and why it is the most natural main construction for a report titled around WHIR accumulation.

#### N8 integrated alternative route

Explain that the repo also implements an explicit integrated one-WHIR accumulation API (`ACC.P` / `ACC.V` / `ACC.D`) for same-shape, nonempty NonZK transitions. Present it as an implemented alternative route, not as the default product verifier.

#### From WHIR proofs to verification claims

Explain how source claims are turned into foldable typed claims. Tie this to the CP public statement and folded output boundary.

#### Lattice-Based Folding of Claims

Describe accumulator transition consistency and boundary compression at a high level.

#### CP-SNARK for the folding transition

Explain the typed CP role:

- public input binding,
- FS commitment binding,
- fold-root binding,
- challenge-to-beta binding,
- folded output derivation,
- original Ajtai validity,
- original R1CS validity.

#### WHIR backend for the CP relation

Explain how WHIR proves the typed CP relation and typed output relation.

#### Verification algorithm

Separate clearly:

- default `verify_public` verification,
- K6a explicit accumulator verification,
- native roadmap routes as separate APIs.

### Important warning for this section

The report must not blur:

- “the current public-only product verifier is authoritative” with
- “the current full accumulator route is K6a” with
- “the native integrated route is the end-state roadmap.”

Those are different claims.

---

## 5.6 Completeness

Keep this section modest and route-aware.

### Recommended structure

- local completeness of the typed CP relation;
- completeness of folding / accumulator transition for the explicit route;
- completeness of WHIR typed output binding;
- end-to-end informal completeness theorem.

### Recommended wording

Use language like:

- “informal,”
- “for the implemented route,”
- “assuming honest prover execution,”
- “conditional on the backend relation setup.”

### Sources

- `docs/protocols/whir.md`
- `docs/past_roadmaps/whir_typed_cp_authority_plan.md`
- tests in `tests/snark.rs`, `tests/batched_cp.rs`, and WHIR/native tests

---

## 5.7 Soundness of the Composition

This section should be built from the docs, not from ad hoc prose.

### Strongest source

Use `docs/whir_public_security_review.md` as the backbone for the product-route soundness story.

### Key soundness chain for the default product route

State how the product verifier binds:

- public inputs and R1CS metadata,
- `fs_commitments` to `fs_root`,
- GR1CS message bytes to typed CP structure,
- fold inputs to `fold_root`,
- challenge bodies to `challenge_digest`,
- challenge bytes to `beta`,
- folded output to beta-bound folding semantics,
- original Ajtai openings,
- original R1CS validity,
- typed output bytes to the WHIR output proof.

### Important distinction

Make clear that:

- `docs/whir_public_security_review.md` reviews the **WHIR+WHIR product public verifier boundary**;
- K6a and N8 route discussions are related, but they are **not identical** to the reviewed WHIR+WHIR product public-verifier boundary. N8 has its own explicit accumulation boundary and should be described separately as an implemented alternative route, not folded into either K6a or the default product verifier.

### Recommendation on section ordering

`main.tex` currently places `Formal Relation Definitions` after `Soundness of the Composition`. That is awkward.

Better options:

- move “Formal Relation Definitions” before the soundness section; or
- fold it into the construction section as a group of subsections.

---

## 5.8 Implementation

This section should map directly to the repo.

### Recommended module tour

- `src/ring/` — ring arithmetic and tensor/extension structures
- `src/commitment/` — Ajtai commitment layer
- `src/rok/` — reductions of knowledge / range / monomial components
- `src/folding/` — high-arity folding machinery
- `src/modular/` — modular proof pipeline, public proof boundary, orchestration
- `src/snark/mod.rs` — top-level public verifier and backend routing
- `src/snark/whir/` — WHIR typed CP/output routing, SYMBT3 route helpers, native route helpers
- `tests/` — route soundness, public-boundary tampering, route-separation tests

### Core data structures to highlight

- `ProofBundleV2` / `PublicProofBundle`
- `SymphonyProofV2` / `PublicSymphonyProof`
- `PublicProofEnvelope`
- `CpPublicStatement`
- folded output instance
- route-specific accumulator instances / proofs where relevant

### Important implementation distinction to state

The implementation section should explain that **public product routing** and **explicit accumulator routing** are not the same function call path.

---

## 5.9 Evaluation

The evaluation section should be split into **three separate measurement stories**.

## 5.9.1 Story A — authoritative product public verification baseline

Use:

- benchmark: `public_verify_v2_vs_k`
- docs: `docs/protocols/whir.md`
- docs: `docs/whir_public_performance_north_star_plan.md`

### What this measures

- public verification only;
- WHIR+WHIR product route;
- no witness-side replay;
- current monolithic typed-CP cost.

### Key message

This route is **correct and authoritative**, but still expensive because typed CP is large and scales roughly linearly with folded statement count.

### Good quantitative points already documented

- `k = 1`: about `2.02 s`
- `k = 2`: about `4.12 s`
- typed-CP rows roughly double from `1,116,203` to `2,221,456`

Do not overfocus on exact machine-specific numbers unless you are freezing a local environment in the report.

---

## 5.9.2 Story B — explicit K6a accumulation route

Use:

- benchmark: `symbt3_accumulator_authority_vs_k`
- docs: `docs/protocols/whir.md`
- `benchmarks/symbt3_scaling.csv`

### What this measures

- explicit opt-in SYMBT3 K6a NonZK integrity route;
- current full accumulator workload path;
- one top-level WHIR proof / zero family subproofs / one backend table in the benchmarked K6a shape.

### Key message

This is the report’s best “current accumulation route in practice” evaluation story.

---

## 5.9.3 Story C — explicit N8 integrated alternative route

Use when the report wants to show that the repository has already moved beyond purely split or wrapper-style accumulation routes.

Good sources:

- benchmark: `symbt3_n8_integrated_authority_vs_k`
- `docs/protocols/whir.md`
- `docs/protocols/n8_accumulation_relation.md`
- `docs/path_to_native_multi.md`

### What this measures

- explicit opt-in integrated one-WHIR accumulation route;
- same-shape, nonempty NonZK accumulation transitions;
- actual serialized N8 output bytes;
- explicit N8 authority-gate acceptance/rejection behavior.

### Key message

Use this story to show that the monolithic public verifier was not the final conceptual destination: it served as the public-boundary stepping stone, while K6a and now N8 instantiate actual accumulation routes with increasingly integrated structure.

---

## 5.9.4 Story D — side-by-side route comparison

Use:

- benchmark: `product_route_comparison_vs_k`
- docs: `docs/protocols/whir.md`
- `benchmarks/product_route_comparison.csv`
- `docs/symbt3_multi_oracle_whir_accumulator_roadmap.md` for the baseline table interpretation

### Key message

This is probably the report’s single most important evaluation table, because it compares:

- the **authoritative monolithic public route** as stepping-stone baseline, and
- the **explicit K6a accumulator route** as the main current accumulation path.

That gives the report a strong empirical backbone.

### Current interpretation from the docs

The K6a single-oracle benchmark already shows very strong verification savings relative to monolithic verification. Use the docs’ wording carefully and keep the route distinction explicit.

---

## 5.9.5 Story E — native / integrated alternative routes and roadmap evidence

Split this material into two sub-stories.

### D1 — N8 as an implemented explicit alternative route

Use when the report wants to mention that the repository already has an integrated one-WHIR accumulation API beyond K6a.

Good sources:

- `docs/protocols/whir.md`
- `docs/protocols/n8_accumulation_relation.md`
- `docs/path_to_native_multi.md`
- N8 tests in `src/snark/whir/native_oracles/tests.rs`
- benchmark: `symbt3_n8_integrated_authority_vs_k`

Recommended treatment:

- describe N8 as **implemented**;
- describe it as **explicit opt-in** and **NonZK**;
- describe it as **authoritative for its own ACC.D boundary**;
- do **not** describe it as the default `verify_public` route;
- do **not** describe it as production-reviewed.

### D2 — broader native / multi-oracle roadmap evidence

Use as:

- future work,
- roadmap evidence,
- or an appendix-style evaluation subsection.

Good sources:

- `docs/symbt3_multi_oracle_whir_accumulator_roadmap.md`
- `benchmarks/symbt3_instrumented_multi_oracle.jsonl`
- `plots/symbt3/summary.md`
- `plots/symbt3/*.svg`

### Important caveat

Most `plots/symbt3/*.svg` assets are about the **SYMBT3 / K6a / native-oracle line**, not the default product `verify_public` route.

If included, label them accordingly.

---

## 5.10 Challenges and Limitations

This section should be candid.

### Must-include limitations

- The authoritative default public verifier remains expensive because typed CP is large.
- K6a is NonZK integrity-only, not privacy-preserving.
- K6a and N8 do not replace default product routing.
- N8 is implemented as an explicit alternative route, but it still has fail-closed gating, is NonZK, and is not the default product verifier or a production-reviewed route.
- The broader native/multi-oracle performance line still includes technical constraints such as repeated RLC batching rather than true vector-valued tuple leaves.
- External cryptographic review is still required before production-grade claims.

### Best sources

- `docs/whir_public_security_review.md`
- `docs/whir_public_performance_north_star_plan.md`
- `docs/path_to_native_multi.md`
- `docs/protocols/whir.md`

---

## 5.11 Related Work

This section should situate the implementation relative to:

- Symphony
- WHIR / whir-p3
- Spartan
- Protostar
- LatticeFold+
- LaBRADOR
- LFKN sumcheck
- Plonky3 / Poseidon2 context as needed

Best starting point:

- `docs/symphony_crate_spec.md` references section

---

## 5.12 Future Work

Split future work into **two clearly different tracks**.

### Track A — hardening the current authoritative public route

Use Production Milestones A–H from:

- `docs/past_roadmaps/whir_typed_cp_authority_plan.md`

This includes:

- spec freezing,
- negative matrix,
- audit harness,
- performance baselines,
- optimization passes,
- release gate.

### Track B — reaching the SYMBT3/native north star

Use:

- `docs/whir_public_performance_north_star_plan.md`
- `docs/path_to_native_multi.md`
- `docs/symbt3_multi_oracle_whir_accumulator_roadmap.md`

This track should include:

- structured batched CP,
- multi-oracle WHIR behavior,
- native round-message oracles,
- the broader native/multi-oracle compression trajectory behind K6a and N8,
- and the remaining review/productionization caveats around the implemented N8 integrated route.

### Important sentence to include

The report should explicitly say that the **next performance target is SYMBT3**, and that the current monolithic typed-CP public route is authoritative but not the performance north star.

---

## 5.13 Conclusion

The conclusion should summarize four truths:

1. authoritative WHIR public-only verification now exists in the repository and is best understood as the stepping-stone baseline;
2. the repository already implements an explicit K6a accumulation route with strong comparative benchmark behavior;
3. the repository also implements an explicit N8 integrated accumulation route for same-shape, nonempty NonZK transitions;
4. SYMBT3/native multi-oracle work is the path toward a more compressed verifier and broader route evolution, but it is not yet the default product route.

That conclusion will be much more accurate than either:

- “everything is already one polished production accumulator,” or
- “this is only a prototype with no real public verifier.”

---

## 6. Benchmarks and artifacts to cite

## 6.1 Product public-verifier baseline

- benchmark name: `public_verify_v2_vs_k`
- docs with current interpreted values:
  - `docs/protocols/whir.md`
  - `docs/whir_public_performance_north_star_plan.md`

## 6.2 K6a explicit route

- benchmark name: `symbt3_accumulator_authority_vs_k`
- artifact: `benchmarks/symbt3_scaling.csv`
- instrumentation artifact: `benchmarks/symbt3_instrumented_benchmark.jsonl`
- docs: `docs/protocols/whir.md`

## 6.3 Route comparison

- benchmark name: `product_route_comparison_vs_k`
- artifact: `benchmarks/product_route_comparison.csv`
- docs: `docs/protocols/whir.md`
- supporting interpretation: `docs/symbt3_multi_oracle_whir_accumulator_roadmap.md`

## 6.4 N8 integrated alternative route and native / multi-oracle artifacts

- benchmark names:
  - `symbt3_native_folding_integrity_public_vs_k`
  - `symbt3_native_accumulator_authority_vs_k`
  - `symbt3_native_accumulator_authority_full_vs_k`
  - `symbt3_n8_integrated_authority_vs_k`
  - `symbt3_instrumented_multi_oracle`
- artifacts:
  - `benchmarks/symbt3_instrumented_multi_oracle.jsonl`
  - `plots/symbt3/*.svg`
  - `plots/symbt3/summary.md`
  - `docs/protocols/n8_accumulation_relation.md`

### Report-use recommendation

- Use the N8 benchmark/doc material when the report wants to mention an already-implemented integrated alternative accumulation route.
- Use the broader native/multi-oracle artifacts in future work / appendix / roadmap subsections unless the report explicitly wants a route-evolution chapter.

---

## 7. Evidence from tests and code to cite

## 7.1 Product public boundary

Use:

- `tests/snark.rs`
- `tests/modular_cp_pipeline.rs`
- `tests/regression_soundness.rs`
- `docs/whir_public_security_review.md`

### Good claims these support

- public-only verification succeeds without witness-side data;
- tampering / replay / splicing fail;
- non-authoritative backends fail closed;
- default routing uses typed authority, not legacy fallback.

## 7.2 K6a explicit accumulator route

Use:

- `tests/batched_cp.rs`
- `docs/protocols/whir.md`
- `benchmarks/product_route_comparison.csv`
- `benchmarks/symbt3_scaling.csv`

## 7.3 Route separation and native-route status

Use:

- `src/snark/whir/native_oracles/tests.rs`
- `docs/path_to_native_multi.md`
- `docs/whir_public_performance_north_star_plan.md`

Particularly useful are the route-separation tests that explicitly assert default `verify_public` routing remains unchanged.

---

## 8. Claims and guardrails to preserve in the write-up

## 8.1 Safe claims

Do say:

- WHIR typed CP is authoritative for public verification.
- `verify_public` succeeds for WHIR+WHIR with public data only.
- `ProofBundleV2` / `PublicProofBundle` is the canonical public proof boundary.
- K6a is implemented, explicit opt-in, and NonZK integrity-only.
- N8 is an implemented explicit alternative route and is not the default product route.
- SYMBT3 is the next performance target.

## 8.2 Claims to avoid

Do not say:

- default product `verify_public` already routes through SYMBT3/K6a/N8;
- K6a or N8 is zero-knowledge;
- WHIR proves SHA-256 inside typed CP;
- public verification depends on witness-side replay/checks;
- the product public verifier has already reached the performance north star;
- the multi-oracle roadmap is already fully implemented.

## 8.3 Recommended vocabulary

Use these labels consistently:

- **authoritative product route**
- **public-only boundary**
- **explicit opt-in accumulator route**
- **NonZK integrity-only**
- **native smoke profile**
- **full-wrapper candidate**
- **integrated explicit alternative route**
- **performance north star / roadmap**

---

## 9. Practical repo issues to resolve before finalizing the report

## 9.1 Missing bibliography

`report/main.tex` ends with:

```tex
\bibliography{references}
```

but the repo currently does **not** contain `report/references.bib`.

You will need to create one.

## 9.2 Figure format mismatch

Most current plot assets are `.svg`.

`main.tex` currently uses `graphicx` but not an SVG package/workflow. So you likely need to either:

- convert selected SVGs to PDF/PNG, or
- adopt an SVG-aware LaTeX workflow.

## 9.3 Section-order cleanup

`Formal Relation Definitions` currently appears after `Soundness of the Composition`.

Move it earlier or merge it into the construction section.

## 9.4 Route-specific labeling

If you include benchmark plots/tables, label them precisely as:

- product public route / stepping-stone baseline,
- K6a explicit accumulator route,
- N8 integrated explicit alternative route,
- native smoke / native wrapper route,
- multi-oracle roadmap artifact,

rather than just “the verifier” or “the accumulator.”

---

## 10. Suggested immediate edits to `main.tex`

Before writing full prose, make these structural adjustments. The introduction
already contains route-aware language; the remaining work is to carry that
discipline through the table, construction, soundness, implementation, and
evaluation sections.

### A. Add a route taxonomy table in the Technical Overview

This will prevent confusion for the rest of the document.

### B. Rewrite the abstract to mention the four-part structure

- authoritative product boundary as stepping-stone baseline,
- K6a explicit accumulation route,
- N8 integrated explicit alternative route,
- SYMBT3/native roadmap.

### C. Make the main construction section explicitly K6a-centered

That matches the title much better than centering the monolithic public route.

### D. Move “Formal Relation Definitions” earlier

Put it before the soundness theorem chain.

### E. Split the evaluation section into baseline / K6a / N8 / route comparison / roadmap

Do not mix these into a single undifferentiated benchmark section.

---

## 11. Best final shape for the report

If written well, `report/main.tex` should read as:

- a report on the implemented Symphony + WHIR system;
- a clear explanation of the current authoritative public verifier boundary as a stepping-stone baseline;
- a concrete account of the K6a explicit accumulation route;
- a concrete account of the N8 integrated explicit alternative route;
- an empirical comparison between monolithic public verification and the explicit accumulator route(s);
- a careful roadmap discussion of SYMBT3/native multi-oracle work.

That shape is faithful to the repository after re-reading the docs, and it avoids the main failure mode: accidentally presenting all these routes as one and the same thing.
