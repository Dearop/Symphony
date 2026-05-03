# WHIR Public Performance North Star Plan

## Current Finding

The WHIR public verifier is functionally authoritative, but it has not reached
the performance north star. The current `public_verify_v2_vs_k` benchmark now
works for `k > 1`, and the result shows near-linear scaling:

| k | `verify_public` mean | Typed CP rows | CP proof bytes | Public envelope bytes |
|---:|---:|---:|---:|---:|
| 1 | 2.0219 s | 1,116,203 | 1,202,354 | 1,218,527 |
| 2 | 4.1157 s | 2,221,456 | 1,254,768 | 1,270,994 |

This means the public product boundary is now correct and multi-statement, but
the cost model is still dominated by a linear-size typed CP proof. The public
verifier no longer performs witness-side replay, yet it verifies a WHIR proof
for a typed CP R1CS whose row count grows approximately linearly with
`params.ell_np`.

The main cost drivers for `k = 2` are:

| Audit block kind | Rows |
|---|---:|
| Poseidon digest gadgets | 1,559,524 |
| Byte constraints | 594,512 |
| GR1CS message reconstruction | 35,562 |
| Range/monomial semantics | 16,434 |
| CP folding core | 11,712 |
| Challenge-to-beta binding | 1,744 |
| Folded-output derivation | 1,408 |
| Ajtai opening checks | 256 |
| Original R1CS validity | 128 |
| Public-input binding | 176 |

The performance north star is not "make the current R1CS faster." It is to make
the public verifier see a compressed CP statement and verify a proof whose
outer cost is near-constant or logarithmic in the number of folded statements.

## North Star Target

The target public verifier should have:

- constant or logarithmic public proof fields with respect to `k`;
- no public vector of per-statement FS commitments;
- no public replay of per-statement transcript or fold inputs;
- constant number of backend verifier calls;
- typed CP verification time that grows much slower than linearly in `k`;
- typed output verification remaining near-constant and small.

The witness/prover side may remain linear in `k`. The public verifier and public
proof boundary should not.

## Architectural Diagnosis

Current `verify_public` still receives `ProofBundleV2.fs_commitments: Vec<Vec<u8>>`.
It recomputes `fs_root` over that vector and passes all FS commitments into
`CpPublicStatement`. That keeps the public boundary and CP public input linear
in `k`.

Current WHIR typed CP proves one monolithic BabyBear R1CS. The builder in
`generate_typed_cp_digest_r1cs_with_audit` appends per-statement digest gadgets,
byte constraints, GR1CS message reconstruction, range semantics, Ajtai checks,
original R1CS checks, challenge-to-beta binding, and folded-output derivation.
This is sound, but it makes the WHIR verifier pay for a proof whose committed
polynomial size doubles when `k` doubles.

The first optimization pass removed repeated setup and duplicate Poseidon input
materialization, but the remaining large blocks are semantically real in the
current design. Further local row reductions will improve constants, not the
asymptotic story.

## Milestone P1 - Freeze the Measured Baseline

Goal: make the current linear cost model impossible to misread.

Implementation requirements:

- Record clean `k = 1, 2` numbers in `docs/whir.md`.
- Add an explicit "linear typed CP baseline" note next to
  `public_verify_v2_vs_k`.
- Add a `public_verify_v2_vs_k` CI/dev command that can be run with
  `SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2`.
- Keep the default benchmark at `k = 1` for developer turnaround.

Acceptance criteria:

- `public_verify_v2_vs_k` verifies and times `k = 1, 2`.
- Docs state that current public verification is authoritative but linear.
- No proof format or security-boundary changes.

Status: implemented. `docs/whir.md` records the `k = 1, 2` public verifier
baseline and explicitly labels the current cost model as an authoritative
linear typed-CP baseline.

## Milestone P2 - Compress the Public Boundary

Goal: remove linear public fields before changing the CP proof architecture.

Implementation requirements:

- Replace public `fs_commitments: Vec<Vec<u8>>` at the product boundary with a
  fixed digest/root plus a versioned compressed transcript commitment object.
- Move the full FS commitment list into the typed CP witness.
- Keep `fs_root`, `fold_root`, `challenge_digest`, `transcript_seed_digest`,
  and `FoldedOutputInstance` public.
- Update `CpPublicStatement` so WHIR public verification does not take all FS
  commitments as public inputs.
- Version the public proof envelope because this changes public wire shape.

Acceptance criteria:

- Public envelope size grows sublinearly in `k`.
- `verify_public` no longer hashes a public vector of all FS commitments.
- Typed CP still proves every FS commitment opening/message against `fs_root`.
- Public tampering/splicing tests cover the new compressed boundary.

Status: in progress. A version-2 compressed public envelope has been added as a
roadmap wire shape. It omits the public `fs_commitments` vector and keeps only
the roots/digests plus backend proof payloads. The typed CP R1CS builder now
also has a compressed-FS development mode where FS commitment digest outputs are
private witness columns and are still constrained into `fs_root`,
`challenge_digest`, and the per-round challenge transcripts. The product
verifier still uses the v1 Rust proof boundary until this compressed typed CP
relation is wired into WHIR proving and verification.

Current envelope-size measurements:

| k | V1 envelope bytes | V2 compressed envelope bytes |
|---:|---:|---:|
| 1 | 1,217,150 | 1,217,102 |
| 2 | 1,271,222 | 1,271,134 |

The small savings are expected at this stage: the proof payload is still
dominated by the monolithic typed CP proof. V2 removes the public linear FS
commitment vector from the wire shape, but P3/P4 are still required to compress
the CP proof itself.

## Milestone P3 - Split CP Into Per-Statement Leaves and an Accumulator

Goal: stop proving the full linear CP relation as one public verifier proof.

Implementation requirements:

- Define a typed CP leaf relation for one original statement:
  FS opening/message consistency, GR1CS message semantics, range/monomial
  semantics, Ajtai opening validity, and original R1CS validity.
- Define a typed CP accumulator relation:
  fold-root binding, challenge-to-beta binding, beta-weighted folded output
  derivation, and transcript/digest binding over a compact root.
- Commit leaf proofs or leaf claims into an accumulator root.
- Make the public verifier check only the accumulator proof and a compact root,
  not one monolithic proof over all leaves.

Acceptance criteria:

- Leaf proving cost remains linear or parallelizable.
- Public verification cost for the accumulator grows much slower than current
  monolithic typed CP verification.
- The audit matrix maps every old `CpFieldRelation` responsibility to either
  leaf or accumulator proof rows.

## Milestone P4 - Batch or Recursively Aggregate Leaf Proofs

Goal: make all per-statement semantic checks available to the public verifier
through a compressed proof object.

Implementation options:

- Recursive WHIR aggregation of leaf typed CP proofs.
- Merkle-rooted leaf proof commitments plus a succinct accumulator proof that
  verifies a batched claim over all leaves.
- A dedicated folding/accumulation scheme for typed CP leaf verification keys
  and leaf outputs.

Required decision:

- Choose the aggregation design before implementing this milestone. The current
  codebase does not yet contain the recursive verifier or proof-carrying-data
  machinery needed to make this step mechanical.

Acceptance criteria:

- Public verifier checks one aggregate CP proof or logarithmic aggregate data.
- `typed_cp_verify_only_vs_k` grows sublinearly over at least `k = 1, 2, 4`.
- Leaf proof tampering, omitted leaf, duplicated leaf, and reordered leaf tests
  reject.

## Milestone P5 - Replace Exact-Byte In-Circuit Hashing Where Versioned

Goal: reduce the largest constant factors only after the compressed architecture
is clear.

Implementation requirements:

- Keep the existing exact-byte Poseidon2/BabyBear path as version 1.
- Define a version 2 field-native transcript body that avoids byte/bit packing
  where values are already BabyBear field elements.
- Keep canonical digest domain separation and serialization documented.
- Rebuild typed CP leaf/accumulator gadgets over field-native bodies.

Acceptance criteria:

- `PoseidonDigestGadgets` and `ByteConstraints` row counts drop materially.
- Public proof versioning makes v1/v2 semantics unambiguous.
- v1 compatibility tests remain green or are explicitly scoped as legacy.

## Milestone P6 - Benchmark Against the North Star

Goal: prove the cost model has changed, not just the implementation.

Required benchmark curves:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4 cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4 cargo bench --bench whir_scaling --features whir -- "typed_cp_verify_only_vs_k"
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4 cargo bench --bench whir_scaling --features whir -- "public_proof_size_vs_k"
```

Acceptance criteria:

- Public verification grows much slower than the current near-linear baseline.
- Public envelope size is constant or logarithmic in `k`.
- Typed output verification remains negligible.
- The docs report both absolute times and scaling ratios.

## Non-Goals

- Do not make `verify_public` call witness-side checks.
- Do not hide the linearity by skipping requested `k` values.
- Do not claim production performance from constant-factor row reductions alone.
- Do not change Poseidon2/BabyBear semantics without proof-envelope versioning.
- Do not remove current authoritative typed CP tests until the new compressed
  architecture has equivalent negative coverage.

## Immediate Next Step

Start with Milestone P1 and P2. P1 locks the new `k = 1, 2` truth into docs.
P2 removes the public boundary linearity and forces the API to match the north
star before deeper proof aggregation work begins. P3/P4 are the real
performance architecture milestones: they replace the current monolithic
linear typed CP proof with an accumulated or recursive CP proof.
