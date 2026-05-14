# WHIR Public Performance North Star Plan

## Contents

1. [Current Finding](#current-finding)
2. [Recalibrated Diagnosis](#recalibrated-diagnosis)
3. [North Star Target](#north-star-target)
4. [Architectural Diagnosis](#architectural-diagnosis)
5. [Milestone P1 — Freeze the Measured Baseline](#milestone-p1-freeze-the-measured-baseline)
6. [Milestone P2 — Compress the Public Boundary](#milestone-p2-compress-the-public-boundary)
7. [Milestone P3 — Structured Batched CP Relation](#milestone-p3-structured-batched-cp-relation)
8. [Milestone P4 — WHIR Structured Relation Integration](#milestone-p4-whir-structured-relation-integration)
9. [Milestone P5 — SYMBT3 CP-Aware WHIR Oracle Relation](#milestone-p5-symbt3-cp-aware-whir-oracle-relation)
10. [Milestone P6 — Versioned Field-Native Transcript Cleanup](#milestone-p6-versioned-field-native-transcript-cleanup)
11. [Milestone P7 — Benchmark Against the North Star](#milestone-p7-benchmark-against-the-north-star)
12. [Non-Goals](#non-goals)
13. [Immediate Next Step](#immediate-next-step)

---


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

---


## Recalibrated Diagnosis

The `SYMBT2F` message-section measurements changed the north star. The problem
is not that the mathematical CP statement is over-constrained. The problem is
that the implementation is over-materializing CP semantics at the byte,
serialization, table, and proof-object layer.

Symphony's CP-SNARK boundary should look like one CP proof over committed
folding-message oracles. The CP proof should establish the folding algebra from
the input accumulator to the folded output accumulator. It should not embed a
large Fiat-Shamir circuit, a hash-transcript circuit, or a forest of
commitment-opening byte-equality proofs. Fiat-Shamir challenge derivation and
message commitment binding belong in the proof-system/transcript layer; the
proven CP relation should consume the committed message oracles and prove the
algebraic folding relation over them.

The current authoritative monolithic typed CP path is sound, but its audit
profile shows the cost inversion clearly: for `k = 2`, exact-byte Poseidon
gadgets and byte constraints dominate the actual folding algebra by orders of
magnitude. The `SYMBT2F` development path then repeats the same mistake at a
different layer: it turns canonical bytes into section tables and proves many
local table predicates with 82-88 independent WHIR subproofs. That is useful as
a diagnostic harness, but it is not the Symphony CP-SNARK architecture.

The new implementation rule is:

> If a check only proves that byte encodings, transcript bodies, or hash inputs
> were formed correctly, do not assume it belongs inside pi_cp.

The next architecture target is therefore `SYMBT3`: a CP-aware WHIR oracle
relation, not more `SYMBT2F` table splitting.

---


## North Star Target

The target public verifier should have:

- constant or logarithmic public proof fields with respect to `k`;
- no public vector of per-statement FS commitments;
- no public replay of per-statement transcript or fold inputs;
- constant number of backend verifier calls;
- one CP proof object per same-shape CP bucket, not dozens of local WHIR
  subproofs;
- CP message oracles `M_i(T, U_i)` committed directly as proof-system oracles;
- Fiat-Shamir challenges derived outside the proven CP relation from shape,
  public boundary, message-oracle roots, and WHIR parameters;
- no in-CP exact-byte proof of transcript formatting, digest-body construction,
  or commitment-opening byte equality unless a versioned design explicitly
  needs it;
- algebraic columns for folding, beta binding, Ajtai linear combinations,
  GR1CS/R1CS residuals, and folded-output derivation;
- typed CP verification time that grows much slower than linearly in `k`;
- typed output verification remaining near-constant and small.

The witness/prover side may remain linear in `k`. The public verifier and public
proof boundary should not.

---


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

---


## Milestone P1 - Freeze the Measured Baseline

**Goal.** make the current linear cost model impossible to misread.

**Implementation requirements**

- Record clean `k = 1, 2` numbers in `docs/whir.md`.
- Add an explicit "linear typed CP baseline" note next to
  `public_verify_v2_vs_k`.
- Add a `public_verify_v2_vs_k` CI/dev command that can be run with
  `SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2`.
- Keep the default benchmark at `k = 1` for developer turnaround.

**Acceptance criteria**

- `public_verify_v2_vs_k` verifies and times `k = 1, 2`.
- Docs state that current public verification is authoritative but linear.
- No proof format or security-boundary changes.

**Status.** implemented. `docs/whir.md` records the `k = 1, 2` public verifier
baseline and explicitly labels the current cost model as an authoritative
linear typed-CP baseline.

---


## Milestone P2 - Compress the Public Boundary

**Goal.** remove linear public fields before changing the CP proof architecture.

**Implementation requirements**

- Replace public `fs_commitments: Vec<Vec<u8>>` at the product boundary with a
  fixed digest/root plus a versioned compressed transcript commitment object.
- Move the full FS commitment list into the typed CP witness.
- Keep `fs_root`, `fold_root`, `challenge_digest`, `transcript_seed_digest`,
  and `FoldedOutputInstance` public.
- Update `CpPublicStatement` so WHIR public verification does not take all FS
  commitments as public inputs.
- Version the public proof envelope because this changes public wire shape.

**Acceptance criteria**

- Public envelope size grows sublinearly in `k`.
- `verify_public` no longer hashes a public vector of all FS commitments.
- Typed CP still proves every FS commitment opening/message against `fs_root`.
- Public tampering/splicing tests cover the new compressed boundary.

**Status.** in progress. A version-2 compressed public envelope has been added as a
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

---


## Milestone P3 - Structured Batched CP Relation

**Goal.** replace the flat monolithic typed CP relation with a same-shape
product-domain relation, not with `k` independent WHIR proofs and not with an
appended R1CS containing `k` copied circuits.

**Implementation requirements**

- Define `CpAccumulatorShape` as the canonical local CP accumulator object
  shape: local public layout, witness layout, CP round/message layout,
  accumulator input/output layout, WHIR parameter digest, and stable
  `shape_id`.
- Define `BatchedCpStatementShape` wrapping a `CpAccumulatorShape` with
  `batch_log_size`, active item count, product-domain layout, manifest layout,
  and per-round batch message oracle layout.
- Bucket CP accumulator objects by exact `shape_id`; reject mixed-shape
  batching, shape coercion, and heterogeneous selectors.
- Commit to a batch manifest over all per-item public CP data, accumulator
  input/output data, item tags, active mask, and shape id.
- Commit to each batch round message oracle `M_i(T,U_i)`.
- Derive batch-level challenges from the shape id, manifest digest, prior batch
  message commitments, WHIR parameter digest, and batch size.
- Add a software evaluator for the product-domain relation that proves the
  invariant: accepting the batch implies every active item satisfies the local
  CP accumulator relation.

**Acceptance criteria**

- Exact same-shape objects batch; shape mismatch rejects.
- Manifest tampering, omitted item, duplicate item, reordered item, wrong
  active mask, and inactive padding tampering reject.
- Any item-level CP violation rejects the batch evaluator.
- The implementation exposes product-domain witness/message oracles `W(T,V)`
  and `M_i(T,U_i)` and does not construct an appended typed CP R1CS.

**Status.** implemented as a non-authoritative foundation. The repo now has
`CpAccumulatorShape`, `BatchedCpStatementShape`, exact-shape bucketing, batch
manifest commitments, per-round batch message commitments, batch challenge
digests, product-domain witness/message oracle objects, canonical public
statement bytes, and a software evaluator.

The software evaluator binds the exposed product-domain oracle rows back to the
same ordered active items used by the manifest and round-message commitments,
including inactive padding rows. Tampering with witness oracle rows, round
message oracle rows, manifest shape/active-count metadata, omitted items,
duplicate item tags, or reordered items rejects before local CP relation checks.

Initial P3 software/profile measurements on the current machine:

| k | Batched public statement bytes | Manifest body bytes | Software evaluator mean |
|---:|---:|---:|---:|
| 1 | 590 | 19,921 | 3.0539 ms |
| 2 | 590 | 39,747 | 6.0897 ms |

These numbers are intentionally not WHIR proof timings. They show the desired
short public batch boundary and the still-linear software evaluator baseline
that P4 must replace with one structured WHIR verification object.

The product verifier still verifies the authoritative monolithic typed CP
proof. No structured batched CP proof is accepted by public routing yet.

---


## Milestone P4 - WHIR Structured Relation Integration

**Goal.** make WHIR consume `BatchedCpStatementShape` directly and produce one
WHIR-backed CP proof per exact same-shape bucket.

**Implementation requirements**

- Add a WHIR-facing structured relation path for product-domain evaluators.
- WHIR setup must receive product-domain dimensions and evaluator metadata, not
  a flattened appended R1CS.
- WHIR prove/verify must produce/check one CP proof per same-shape bucket.
- Independent `k` WHIR-backed CP proofs must not be accepted as a batched proof.
- Product public routing stays on monolithic typed CP until structured proof
  semantics, negative tests, and benchmarks are green.

**Acceptance criteria**

- `k = 1` structured path matches monolithic typed CP semantics.
- `k = 2, 4` verify with one structured proof per same-shape bucket.
- Proof from another shape, manifest, batch size, round commitment, or WHIR
  parameter digest rejects.
- `typed_cp_verify_only_vs_k` and public verifier benchmarks grow materially
  slower than the current monolithic baseline, or the measured blocker is
  documented.

**Status.** in progress. WHIR now exposes a non-authoritative structured batched CP
relation description for `BatchedCpStatementShape`. The context has a dedicated
`SYMBTC1` marker, stable relation id, public statement byte size, product-domain
size, witness-oracle row length, and per-round message-oracle lengths. Its
`RelationDescription` deliberately reports `num_constraints = 0` because this
is not a flattened/appended R1CS relation.

### P4 — `SYMBTC1` product-domain oracle proof

WHIR also now produces and verifies a `SYMBTC1` product-domain oracle proof:
the prover commits with WHIR to one canonical batch oracle built from
`W(T,V)`, `M_i(T,U_i)`, exact round-message digest-body frames, the manifest
digest body, and the batch challenge digest body, then opens that oracle at a
transcript-derived point bound to the structured context and
`BatchedCpPublicStatement`. The verifier also checks every fully public packed
oracle chunk against the concrete public statement: domain tags, shape/context
bytes, item/round indices, active markers, inactive padding lengths,
digest-body framing, public manifest digest bytes, public round-message
commitment bytes, and the final byte-length sentinel. Private
witness/message/public-item chunks are not opened.

This is a real WHIR-backed product-domain proof object, but it is not yet
CP-authoritative: it proves oracle possession/public-framing binding, not the
full structured CP predicate or complete Poseidon hash authority over the
oracle.
It also enforces a sampled structured byte-equality predicate: Fiat-Shamir
selected round-message oracle bytes must match the duplicated round-message
digest-body bytes opened from the same committed oracle, and folded-output
contribution bytes in active witness rows must match the folded-output
accumulator body carried in the same oracle. Product routing therefore remains
on the current authoritative monolithic typed CP path.

### P4 — `SYMBTC1` clarification (oracle vs CP-semantic)

Current P4 status clarification: `SYMBTC1` is a WHIR-backed product-domain
oracle proof, not a CP-semantic proof. It binds the canonical batch oracle,
public framing, manifest/challenge digest bodies, and selected equality checks.
It now also has a non-authoritative
`BatchedCpSemanticRelationDescription` layer. That semantic description carries
the stable same-shape batch layout, typed product-oracle byte ranges, verifier
digests of the indexed Ajtai parameters and original R1CS matrices, the indexed
Ajtai matrix used by the development structured verifier, the input bound, and
the required semantic constraint families:

- Poseidon digest correctness;
- manifest membership;
- round-message binding;
- challenge derivation;
- challenge-to-beta binding;
- folded-output derivation;
- Ajtai opening validity;
- original R1CS validity;
- active-or-dummy padding policy.

WHIR now consumes that semantic context through a structured-constraint
interface that can enable one semantic block at a time. The first supported
blocks are `ManifestMembership`, `ChallengeDerivation`,
`ChallengeToBetaBinding`, `FoldedOutputDerivation`, `AjtaiOpeningValidity`,
`OriginalR1csValidity`, `RoundMessageBinding`, and `ActiveOrDummyPolicy`: for
each selected equality, public packed-value, or sampled algebra constraint,
WHIR opens typed product-oracle columns/chunks and checks that
manifest item tags/public statements agree with their typed witness-row copies,
that the batch challenge body is bound to the public shape, manifest digest,
round-message commitments, WHIR parameter digest, and batch dimensions, that
the public challenge digest maps to its canonical base-5 beta ring element,
that folded-output contribution bytes agree between active witness rows and the
folded-output accumulator body, that the folded-output accumulator body is bound
to the public accumulator-root bytes, that each active item's public `x_folded`
copy equals the folded instance embedded in its `FoldedOutputInstance`, that
each active item's fold-input commitment/public-input/eval-message fields agree
between the typed witness row and a dedicated fold-input reconstruction body,
that each fold-input eval message also agrees with the matching `M_i(T,U_i)` row,
that witness-row FS message bytes agree with the matching `M_i(T,U_i)` row,
that round-message oracle bytes equal their duplicated digest-body bytes, and
that every witness/message/digest-body active marker agrees with the manifest
marker for the same batch item. FS openings are now typed product-oracle ranges
and the `PoseidonDigestCorrectness` block now carries a canonical
`fs-commit` body section whose private bytes are bound to
`len(message) || message || opening` from the typed witness-row FS ranges. For
Poseidon2/BabyBear batches, the same block also carries private trace columns
for the Poseidon digest output limbs, canonical input limbs, and x^7 S-box
auxiliary values. WHIR samples rows from the existing Poseidon private-digest
R1CS gadget's full row domain and checks those row equations over opened trace
variables, with the trace digest output limbs byte-bound to the FS commitment
bytes. This removes the earlier bounded first/last-row candidate surface and
gives the Poseidon block a proximity-style full-domain challenge surface, but
it is still sampled development coverage rather than complete authoritative hash
proof composition.
Original witness bytes are also exposed as typed product-oracle ranges. The
`AjtaiOpeningValidity` block now samples original commitment-opening equations
against the indexed Ajtai matrix: sampled product-oracle openings for public
input scalars, original-witness coefficients, and commitment coefficients must
satisfy `A_row * [x || w] = c` over the BabyBear cyclotomic ring.
The `OriginalR1csValidity` block now also samples original source-R1CS
equations from the same product oracle: for each sampled `(item, original
statement, R1CS row, ring coefficient)`, WHIR opens assignment coefficients and
checks `(Az) * (Bz) = Cz` over BabyBear, treating public inputs as constant ring
elements. The product-oracle layout also now exposes Poseidon2/BabyBear folded
public-input, folded commitment, and folded Hadamard-evaluation algebra
offsets. A BabyBear-modulus regression checks that those offsets satisfy the
expected cyclotomic equations against the canonical oracle bytes, and the WHIR
sampled-opening path now samples those folded public-input, commitment,
evaluation, Ajtai-opening, and original-R1CS algebra constraints as part of the
non-authoritative SYMBTC1 proof. This is still sampled development coverage,
not complete proximity-style semantic authority, and product routing must
remain on the authoritative monolithic typed CP proof until the full CP
predicate and negative tests pass.

### P4 — `SYMBTC2` full-selection candidate

`SYMBTC2` now exists as the versioned P4 candidate context. It wraps the
same `BatchedCpSemanticRelationDescription` with an explicit v2 layout carrying
the canonical product-oracle byte length, packed BabyBear field length,
product-row count, semantic-column count, and residual-family count. The
serialized relation context uses the `SYMBTC2` marker and has a distinct
relation id from `SYMBTCS1`; its `RelationDescription` still reports
`num_constraints = 0`, so it cannot be confused with an appended typed CP R1CS.

When WHIR receives a `SYMBTC2` context, it no longer samples bounded subsets of
the advertised semantic blocks. It enumerates all byte equalities, public
packed-value claims, folded-output algebra constraints, Poseidon private-digest
R1CS rows, Ajtai opening equations, and original R1CS equations currently
exposed by the structured relation and verifies them through one WHIR
product-oracle proof object. This is a full-selection development path over the
current canonical product oracle, not yet the final optimized low-degree
columnar proximity interface. Because the resulting proof is intentionally
large and slow, the end-to-end SYMBTC2 WHIR proof test is marked ignored as a
heavy candidate audit; the default tests cover stable context serialization and
non-R1CS routing. Product public routing remains on the authoritative
monolithic typed CP proof.

### P4 — `SYMBT2C` columnar skeleton

The first columnar SYMBTC2 skeleton is available under a separate `SYMBT2C`
context. It commits to a typed semantic table and derives bounded
transcript-bound residual openings. The current columnar residual model supports
all advertised semantic families:
`ActiveOrDummyPolicy`, `ManifestMembership`, `RoundMessageBinding`,
`ChallengeDerivation`, `ChallengeToBetaBinding`, `PoseidonDigestCorrectness`,
`FoldedOutputDerivation`, `AjtaiOpeningValidity`, and
`OriginalR1csValidity`. Equality-style families use two-column residuals, while
Poseidon and original-R1CS rows use product residuals of the form `a * b = c`.
The SHA-shaped development fixture only instantiates the families with
non-empty constraints. The Poseidon/BabyBear-shaped SYMBT2C fixture now
instantiates all nine families, including `PoseidonDigestCorrectness`,
`AjtaiOpeningValidity`, and `OriginalR1csValidity`, with active trace-level
tampering coverage for every family. The bounded WHIR proof-profile test for
`k = 1` passes but is marked ignored because it is a heavy audit path in the
test profile. This path is still development-only and sampled/proximity-style,
not product-authoritative.

### P4 — `SYMBT2F` family-local columnar candidate

`SYMBT2F` is the family-local columnar candidate. It keeps the same residual
equations as `SYMBT2C`, but each instantiated residual family gets its own
compact table, row domain, and internal WHIR PCS subproof instead of sharing one
rectangular table padded to the largest family. The SHA-shaped fixture
proves/verifies through this path by default, while the Poseidon/BabyBear WHIR
proof-profile test is kept as an ignored heavy audit path. The active
Poseidon/BabyBear trace test still covers all nine residual families. This is
also development-only and is not product-authoritative.

Previous `SYMBT2F` family-local measurements after shared verifier-infra caching:

| Fixture | k | Family subproofs | Unique num vars | Cache hits/misses | Proof bytes | Max family num vars | Prove mean | Verify mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SHA-shaped | 1 | 6 | 5 | 1 / 5 | 3,030,072 | 19 | 94.211 ms | 26.654 ms |
| Poseidon/BabyBear-shaped | 1 | 9 | 7 | 2 / 7 | 3,394,583 | 19 | 8.3492 s | 2.1002 s |

After the dominant-domain split, `RoundMessageBinding` is partitioned by CP
round and by digest-body vs witness-message equality, while
`FoldedOutputDerivation` is partitioned into contribution binding,
self-consistency, fold-input reconstruction, folded public-input linear
equations, folded commitment ring-mul equations, and folded evaluation ring-mul
equations. This preserves the same residual corpus but avoids padding every
row into the former `num_vars = 19` domains.

Current `SYMBT2F` split-table measurements:

| Fixture | k | Family tables / subproofs | Unique num vars | Cache hits/misses | Proof bytes | Max table num vars | Prove mean | Verify mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SHA-shaped | 1 | 18 / 18 | 7 | 11 / 7 | 9,058,137 | 17 | 180.24 ms | 79.476 ms |
| Poseidon/BabyBear-shaped | 1 | 24 / 24 | 11 | 13 / 11 | 9,586,570 | 17 | 6.0962 s | 2.0653 s |

The split succeeds at the intended local-domain objective: the two former
`num_vars = 19` domains shrink, and the largest remaining tables are
`num_vars = 17`. The dominant remaining tables are still round-message byte
binding and fold-input round-message reconstruction tables, each with `34,568`
rows padded to `65,536` rows.

The tradeoff is now explicit. SHA-shaped proving and verification regress
because one development proof object now contains 18 independent WHIR PCS
subproofs instead of 6. Poseidon/BabyBear proving improves substantially
because the largest local domains shrink, while verification only improves
slightly because it still verifies 24 independent subproofs. The next
meaningful P4 performance target is not more table splitting by itself; it is
either reducing the remaining `34,568`-row message/reconstruction tables or
adding real cryptographic multi-proof verification across the split family
subproofs.

The message-section domain shrink partitions the remaining round-message and
fold-input round-message reconstruction tables by canonical GR1CS message
sections: `header`, `hadamard-evals`, `range-payload`, `monomial-payload`,
`square-evals`, `projected-values`, and `trailing-frame`. Sections larger than
`8192` rows are split into stable chunk tables. This preserves exact-byte
semantics while capping the targeted two-column message equality tables at
`num_vars <= 14`.

Current `SYMBT2F` message-section measurements:

| Fixture | k | Family tables / subproofs | Unique num vars | Cache hits/misses | Proof bytes | Max table num vars | Prove mean | Verify mean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SHA-shaped | 1 | 82 / 82 | 8 | 74 / 8 | 22,732,708 | 16 | 163.20 ms | 207.66 ms |
| Poseidon/BabyBear-shaped | 1 | 88 / 88 | 11 | 77 / 11 | 23,177,442 | 16 | 6.1499 s | 2.3468 s |

The section split succeeds at the intended local-domain objective. The largest
round-message and fold-input round-message section tables now have `8192` rows
and `num_vars = 14`. The remaining max table is `num_vars = 16`, currently
from `ManifestMembership` and folded-output contribution binding. The tradeoff
is worse verifier cost and much larger development proof payloads because the
proof object now contains 82-88 independent WHIR PCS subproofs. This confirms
that the next useful P4 optimization is not further message-section splitting;
it is either reducing the `num_vars = 16` manifest/contribution tables or
adding real multi-proof aggregation/shared verification across the family
subproofs.

The benchmark now prints a `family_attribution` diagnostic with per-family
subproof count, proof-byte estimate, private eval count, sampled query count,
Merkle-path query proxy, rows, padded rows, max `num_vars`, transcript-label
bytes, and simple prove/verify work proxies. The current attribution points at
fixed per-subproof/proof-object overhead rather than the remaining
`num_vars = 16` tables:

| Fixture | Family | Subproofs | Proof bytes approx. | Queries | Max num vars |
|---|---|---:|---:|---:|---:|
| SHA-shaped | `RoundMessageBinding` | 36 | 9,993,395 | 144 | 14 |
| SHA-shaped | `FoldedOutputDerivation` | 42 | 11,916,347 | 168 | 16 |
| SHA-shaped | `ManifestMembership` | 1 | 753,181 | 4 | 16 |
| Poseidon/BabyBear-shaped | `RoundMessageBinding` | 36 | 9,969,689 | 144 | 14 |
| Poseidon/BabyBear-shaped | `FoldedOutputDerivation` | 45 | 12,029,254 | 180 | 16 |
| Poseidon/BabyBear-shaped | `ManifestMembership` | 1 | 749,064 | 4 | 16 |

So the immediate diagnostic supports the aggregation direction. The remaining
`num_vars = 16` tables are visible, but they account for only two subproofs.
The verifier regression is primarily caused by dozens of section/chunk
subproofs, their independent transcript/PCS payloads, and their Merkle-opening
work. This does not make `SYMBT2F` a security issue, because it remains
development-only and non-authoritative. It does make `SYMBT2F` the wrong final
architecture.

`SYMBT2F` is now calibrated as:

- development-only diagnostic path
- oracle layout sanity checker
- negative-test harness
- byte/table over-materialization warning system

It should not be treated as the route to the production CP proof. Further
splitting of `ManifestMembership`, folded-output contribution binding, or
message sections is useful only when it improves diagnostics. The next
production-oriented P4/P5 work should pivot to a CP-aware WHIR relation where
message oracles are committed objects queried directly by the proof system and
the proven constraints are the folding algebra itself.

### P4 — `SYMBTC1` product-oracle measurements

Initial `SYMBTC1` product-oracle measurements:

| k | Product oracle bytes | Public oracle claims | WHIR num vars | Proof bytes | Prove mean | Verify mean |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 68,949 | 306 | 15 | 705,806 | 73.316 ms | 6.7663 ms |
| 2 | 137,042 | 326 | 16 | 753,202 | 134.42 ms | 7.3514 ms |

These numbers are much smaller than the monolithic typed CP proof, but they are
not a replacement for it until the structured CP constraints are enforced by
the WHIR proof. The prover slowdown relative to the previous oracle-only
prototype is expected: the proof now opens all verifier-known packed framing
chunks, not just one random transcript point, and the oracle now includes
round-message, manifest, and challenge digest-body frames. The public-known
opening strategy is deliberately simple and will need compression before this
becomes the production fast path.

---


## Milestone P5 - SYMBT3 CP-Aware WHIR Oracle Relation

**Goal.** replace byte/table emulation of CP with one CP-aware WHIR proof object per
same-shape bucket.

**Implementation requirements**

- Treat each CP round message `M_i(T, U_i)` as a committed WHIR/BCS oracle, not
  as bytes that must be re-proved through separate equality tables.
- Bind the message-oracle roots directly as the CP public commitments
  `c_fs,i`.
- Derive Fiat-Shamir challenges outside the proven relation from the shape id,
  public boundary, message-oracle roots, WHIR parameter digest, and batch
  dimensions.
- Expose algebraic semantic columns/traces for beta values, folded commitments,
  folded public inputs, folded evaluations, Ajtai linear combinations,
  GR1CS/R1CS residuals, and active-row policy.
- Enforce the necessary CP semantics:
  - folded output derivation;
  - challenge-to-beta binding at the algebraic level;
  - Ajtai linear-combination/opening algebra;
  - GR1CS/R1CS validity of the folded/source relation;
  - shape and public-boundary binding.
- Do not embed exact-byte transcript reconstruction, Poseidon digest-body
  correctness, public chunk equality tables, round-message digest byte equality,
  or fold-input byte reconstruction inside the CP relation unless a separate
  versioned argument justifies it.
- Produce one WHIR-backed CP proof object per same-shape bucket.
- Keep product public routing on the authoritative monolithic typed CP proof
  until `SYMBT3` has equivalent negative coverage and benchmark data.

**Current submilestone**

- `SYMBT3-J` extends the non-authoritative cumulative profile with a
  production-shaped Ajtai norm/range layer. The cumulative development profile
  uses
  `RqNegacyclicConvolutionV1` for folded GR1CS product residuals,
  `RingCoefficientActionV1` for ring/module beta action, and
  `DirectDevMatrixVectorV1` for the folded Ajtai map check. It uses
  `StructuredBlockProjectionV1` and `MonomialEmbeddingRangeV1` for folded
  Ajtai norm/range evidence, `Symbt3BatchManifestLayoutV1` for typed
  manifest/source membership, and `Symbt3MessageSemanticLayoutV1` with native
  message-oracle views for typed CP message semantics.
- `relation_id` is stable relation metadata only; message roots and folded
  public output values are instance data.
- `relation_id` binds `Symbt3RingModuleLayout` and `AjtaiCommitLayoutV1`,
  including ring degree, modulus, basis/sign convention, action side, module
  dimensions, beta encoding, Ajtai indexed evaluator id, and commit layout
  version. It also binds `Symbt3R1csEvaluatorLayoutV1` and
  `Symbt3Gr1csResidualLayoutV1`, `Symbt3AlgebraLawV1`,
  `Symbt3AjtaiLinearAlgebraLayoutV1`,
  `Symbt3AjtaiNormRangeLayoutV1`, `Symbt3BatchManifestLayoutV1`, and
  `Symbt3MessageSemanticLayoutV1`,
  `Symbt3FoldedGr1csProductResidualLayoutV1`, including matrix/evaluator
  digest, public/witness wire layout, sparse term encoding, Ajtai matrix-vector
  evaluator id, projection/range evaluator ids, manifest/source component
  layout, coordinate grouping, product law, beta action, selector layout,
  padding policy, and version.
- `folding_transcript_digest` binds `relation_id`, the input/public-boundary
  digest, batch manifest root, source assignment roots, source Ajtai opening
  roots, source commitment boundary, message-oracle roots, WHIR parameter
  digest, batch size, and active count.
- `proof_public_statement_digest` additionally binds folded public-input,
  commitment, evaluation, declared algebraic accumulator, folded Ajtai
  opening/commitment boundary, folded-GR1CS boundary digest, and output-bound
  public data.
- Beta is derived from `H("SYMBT3-A-BETA", folding_transcript_digest)` and
  therefore does not depend on folded output or folded Ajtai output data.
- The development proof enforces ring/module beta action for ring-shaped
  commitment/opening coordinates and checks the folded Ajtai residual
  `A * o_fold - c_fold = 0`, with q-wrap terms for centered modulo-q
  arithmetic inside BabyBear evaluation claims.
- `SYMBT3-F` makes this Ajtai block explicit: folded openings and folded
  commitments are beta-linear combinations of source opening/commitment
  columns, and folded Ajtai map consistency is checked as
  `A * f_fold = c_fold` under the declared algebra law. Source item map
  consistency `A * f_T = c_T` is deferred as an optional heavier source-opening
  authority block.
- `SYMBT3-J` upgrades folded Ajtai norm/range evidence. The default cumulative
  profile projects `flatten(f_fold)` with `StructuredBlockProjectionV1`, using
  relation-bound `{0, +/-1}` entry distribution metadata, and checks projected
  values with `MonomialEmbeddingRangeV1` plus representative-policy metadata.
  This is production-shaped check-field range evidence, not full integer/mod-q
  lattice range authority.
- `SYMBT3-H` adds typed source/manifest membership. The first development
  profile binds a typed batch manifest root, manifest layout digest, and
  source-column layout digest, and checks
  `Source(T,K,C) = Manifest(T,K,C)` for active public/input-side source
  coordinates and digest/root boundary coordinates inside the same single
  SYMBT3 table. This is not byte transcript reconstruction.
- `SYMBT3-I2` adds native typed CP message-oracle views. The development
  profile binds a message-semantic layout digest, treats round-message roots as
  the CP message commitment boundary, derives prefix round challenges outside
  the relation, and maps message-derived trace values directly to
  `M_r(T,U)` coordinates through relation-bound view metadata. Pure
  `Message = Trace` copy columns and per-coordinate copy residuals are not
  allocated. The checked values are algebraic message-view coordinates, not
  canonical message bytes, FS openings, or digest-body tables.
- The development proof also commits to source-R1CS residual columns computed
  from setup-bound sparse evaluator metadata and source assignment roots, and
  folded-GR1CS boundary residual columns.
- `FoldedGr1csProductResidualZeroCheck` exposes folded GR1CS product columns
  under the declared `Symbt3AlgebraLawV1` and checks the Boolean-domain
  residual
  `sum_g eq(g, rho) * sel(g) * (ProductLaw(L,R)(g) - O(g)) = 0` with a
  degree-3 sumcheck plus final WHIR/PCS openings. This is deliberately not the
  invalid shortcut `L_hat(z) * R_hat(z) - O_hat(z) = 0`.
- The E folded evaluation boundary is product-closed for the output slice under
  `RqNegacyclicConvolutionV1` in the WHIR check field. Authority over
  integer/lattice `R_q` semantics still requires explicit modulus, range,
  reduction, and soundness treatment.
- Cryptographic roots/digests are public-boundary data and are not folded as
  linear algebraic coordinates.
- `SYMBT3-J` remains non-authoritative and non-ZK; final integer/lattice `R_q`
  representative authority, production sumcheck transcript authority,
  zero-knowledge masking, and final WHIR/Σ-IOP soundness analysis are future
  SYMBT3 blocks.

### P5 — Architecture benchmark (`symbt3_c_vs_k`, 2026-05-06)

Architecture benchmark baseline, recorded on 2026-05-06 with:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_c_vs_k"
```

These numbers are an architecture benchmark for the development path, not a
final performance claim or product verifier benchmark. The primary regression
guard is the proof shape: one top-level WHIR proof object and zero
family-columnar subproofs for every tested `k`.

| k | top-level WHIR proofs | family-columnar subproofs | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | transcript squeezes | max oracle `num_vars` | Ajtai linear-form claims |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 340,749 | 3.6701 ms | 4.4679 ms | 12 | 12 | 12 | 12 | 128 |
| 2 | 1 | 0 | 419,997 | 5.5698 ms | 6.1235 ms | 18 | 18 | 18 | 13 | 128 |

Criterion history should still be interpreted carefully; reset
`target/criterion/whir_scaling` when comparing fresh before/after numbers.

### P5 — SYMBT3-D baseline (2026-05-07)

SYMBT3-D architecture benchmark baseline, recorded on 2026-05-07 with:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_d_vs_k"
```

| k | top-level WHIR proofs | family-columnar subproofs | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | transcript squeezes | max oracle `num_vars` | source R1CS residual claims | folded GR1CS residual claims |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 330,836 | 4.7096 ms | 5.3228 ms | 14 | 14 | 14 | 12 | 64 | 384 |
| 2 | 1 | 0 | 404,215 | 7.0489 ms | 7.0847 ms | 20 | 20 | 20 | 13 | 128 | 384 |

### P5 — SYMBT3-D2 folded product residual

SYMBT3-D2 added the direct folded product residual benchmark target:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_d2_vs_k"
```

The required structural benchmark guard remains:

```text
top_level_whir_proof_count = 1
family_columnar_subproof_count = 0
backend_table_count = 1
```

SYMBT3-D2 architecture benchmark, recorded on 2026-05-07 with the command
above:

| k | top-level WHIR proofs | family-columnar subproofs | backend tables | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | sumcheck rounds | max oracle `num_vars` | source R1CS residual claims | folded GR1CS boundary claims | folded GR1CS product claims |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 1 | 394,767 | 6.2087 ms | 6.4224 ms | 20 | 20 | 8 | 13 | 64 | 384 | 128 |
| 2 | 1 | 0 | 1 | 401,147 | 7.4955 ms | 7.2242 ms | 26 | 26 | 8 | 13 | 128 | 384 | 128 |

These are architecture/proof-shape numbers for a non-authoritative
development path, not product public-verifier performance claims.

### P5 — SYMBT3-E algebra-law profile

SYMBT3-E replaces the default product law with ring negacyclic convolution and
adds the algebra-law profile benchmark:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_e_vs_k"
```

SYMBT3-E architecture benchmark, recorded on 2026-05-07 with the command
above:

| k | top-level WHIR proofs | family-columnar subproofs | backend tables | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | sumcheck rounds | max oracle `num_vars` | product law | beta action | ring degree |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---:|
| 1 | 1 | 0 | 1 | 395,418 | 6.4393 ms | 7.1004 ms | 22 | 22 | 8 | 13 | `RqNegacyclicConvolutionV1` | `RingCoefficientActionV1` | 64 |
| 2 | 1 | 0 | 1 | 406,431 | 8.2783 ms | 7.4959 ms | 28 | 28 | 8 | 13 | `RqNegacyclicConvolutionV1` | `RingCoefficientActionV1` | 64 |

These numbers remain architecture/proof-shape measurements for a
non-authoritative development path, not product public-verifier performance
claims.

### P5 — SYMBT3-K authority profile gate

SYMBT3-K adds an authority soundness profile gate. `Symbt3AuthorityProfileV1`
is canonical profile metadata binding the enabled A/B/D/D2/E/F/G/H/I2/J2
families, WHIR parameter digest, folding/proof/public-statement schedules,
ring/module algebra, production projection/range/monomial policy, challenge
policy, Fiat-Shamir domain separators, union-bound family count, accepted
shape, ZK status, and authority status. This is not a product routing
promotion. The current development proof verifies on the SYMBT3 dev hook but
fails the K authority gate until the relation has a non-development soundness
profile and ZK/product authority policy.

SYMBT3-K2 splits the authority-style gates:

- `ResearchAuthorityCandidate`: explicitly `SoundnessCandidate`,
  `NonZkDevelopment`, `ResearchOnly`, and `product_eligible=false`. A current
  SYMBT3-J2 proof may pass this gate when all semantic families are enabled and
  the production-shaped projection/range profile is used.
- `ProductAuthority`: product-eligible, non-research, ZK-required, and still
  rejects non-ZK profiles, development range/projection modes, missing J2
  families, and development soundness profiles.

Product `verify_public` still does not route through SYMBT3.

K2a is implemented as structural accumulator scaffolding only. The SYMBT3
public statement binds `old_accumulator_digest` and `new_accumulator_digest`,
and typed accumulator instance/witness wrappers provide stable digesting and
public-statement conversion. The accumulator transition family, `rho_acc`, and
`old_accumulator -> new_accumulator` proof remain K2b work.
K2b adds the constant-size accumulator transition profile and
`AccumulatorTransitionConsistency`: `rho_acc` is derived under
`SYMBT3_ACC_TRANSITION`, remains separate from folding beta, and binds
shape/relation metadata, the transition profile, `old_accumulator_digest`, and
the folded batch boundary. The benchmark CSV reports
`accumulator_transition_claims=1`; this counter must remain constant as `k`
changes.
K3 adds semantic profile versioning and the
`AccumulatorSoundnessAuthorityCandidateV1` gate for the current NonZK research
soundness profile. K4 adds the explicit research public accumulator API:
`prove_public_symbt3_accumulator_research_non_zk(...)` and
`verify_public_symbt3_accumulator_research_non_zk(...)`. The K4 API takes
`Symbt3AccumulatorInstance` public input, rejects ProductAuthority and
`product_eligible` profiles, requires the K3 gate, and delegates to the
existing single-proof SYMBT3 verifier. It is not product routing and not a
zkSNARK; K5 masking/ZK and K6 product promotion remain future work.
K4.5/K3b adds verifier-side evaluator compression for source R1CS residuals.
The verifier now opens the source residual column at a domain-separated
`SYMBT3_SOURCE_R1CS_RESIDUAL_BATCH` batching point instead of treating the
logical `64*k` residual coordinates as individual verifier checks. Benchmarks
report both `source_r1cs_residual_claims` and
`source_r1cs_residual_verifier_evaluations`; the latter is `1` for the current
nonempty SYMBT3 profiles.
K4.6 adds compressed public accumulator boundary canonicalization. The K4
benchmark `public_statement_bytes` now measures
`Symbt3AccumulatorInstance::canonical_bytes()` with expanded batch item,
source-root, source-opening-root, and message-root vectors replaced by digest
commitments. Expanded vectors remain present only for the current
research/dev conversion path and are checked against the digest commitments
before verification. This targets public-boundary size only; it does not
promote SYMBT3 to product routing.

Opt-in comparison command:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_research_vs_product_verify_vs_k"
```

This benchmark reports product `verify_public` and
`verify_symbt3_research_authority_candidate` side by side. It requires the
`ResearchAuthorityCandidate` profile, does not require `ProductAuthority`, and
keeps the research verifier explicitly non-ZK/research-only/product-ineligible.
The K4-specific research accumulator route is benchmarked separately:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4,8 cargo bench --bench whir_scaling --features whir -- "symbt3_accumulator_research_vs_k"
```

That benchmark calls the public accumulator research API, not the lower-level
development hook, and reports proof shape, accumulator transition claims,
manifest/source materialization counters, public accumulator bytes, and verifier
cost attribution, including source residual logical claims versus verifier
evaluations.
K6a adds the opt-in NonZK integrity product benchmark:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4,8 cargo bench --bench whir_scaling --features whir -- "symbt3_accumulator_authority_vs_k"
```

This benchmark calls the explicit SYMBT3 ProductAuthority NonZK integrity API,
not monolithic typed CP and not the K4 research verifier. It reports
`route_kind=symbt3_non_zk_integrity_product`,
`product_route_selected=true`, and `monolithic_fallback_used=false`, alongside
the K4.5/K4.6 proof-shape and public-boundary counters. The default product
`verify_public` benchmark remains the monolithic typed-CP route.

Milestone 0 for the separate SYMBT3 multi-oracle roadmap (the SYMBT3
instrumented benchmark baseline) is complete on this branch as a single-oracle
K6a instrumentation baseline only. It does not add multi-oracle profiles,
tuple-leaf layouts, shared-query routing, or multi-oracle verifier semantics.
The stable JSONL comparison contract is
`benchmarks/symbt3_instrumented_benchmark.jsonl` with schema
`symphony.symbt3.instrumented_benchmark.v1` and top-level fields `schema`,
`k_table`,
`prove_ms`, `verify_ms`, `proof_bytes`, `public_bytes`,
`proof_bytes_by_section`, `public_bytes_by_section`, `counters`,
`verifier_timers`, and `prover_timers`. The JSONL rows are benchmark hygiene
only: `ProofBundleV2`, `PublicProofBundle`, WHIR/public proof payload bytes,
authority flags, product `verify_public`, and K6a NonZK integrity semantics
remain unchanged. Product `verify_public` remains on the authoritative
monolithic WHIR typed-CP route and malformed SYMBT3/K6a profile or proof-kind
inputs still fail closed in the explicit opt-in route.

K6b adds the consolidated side-by-side reporter:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4,8 cargo bench --bench whir_scaling --features whir -- "product_route_comparison_vs_k"
```

The reporter emits `PRODUCT_COMPARISON_CSV` rows joining the existing
monolithic typed-CP product route with the explicit SYMBT3 K6a NonZK integrity
route. Monolithic proof bytes are `cp_proof_bytes + output_proof_bytes`;
monolithic public bytes are the compressed public envelope with proof payloads
omitted. SYMBT3 proof bytes are the single SYMBT3 WHIR proof bytes; SYMBT3
public bytes are the compressed accumulator instance canonical bytes.

K6b stabilizes reporting only. The `PRODUCT_COMPARISON_CSV` schema is:

```text
k,monolithic_verify_ms,symbt3_verify_ms,verify_speedup,monolithic_prove_ms,symbt3_prove_ms,prove_speedup,monolithic_proof_bytes,symbt3_proof_bytes,proof_size_ratio,monolithic_public_statement_bytes,symbt3_public_statement_bytes,public_size_ratio,symbt3_whir_num_vars,symbt3_oracle_len,symbt3_opened_field_elements,symbt3_top_level_whir_proof_count,symbt3_family_columnar_subproof_count,symbt3_backend_table_count,symbt3_accumulator_transition_claims,symbt3_source_r1cs_residual_verifier_evaluations,symbt3_product_route_selected,symbt3_monolithic_fallback_used
```

The reported SYMBT3 K6a shape remains one top-level WHIR proof, zero family
subproofs, and one backend table.

### K6b: Product Route Comparison

| k | monolithic verify_ms | SYMBT3 K6a verify_ms | verify speedup | monolithic prove_ms | SYMBT3 prove_ms | prove speedup | monolithic proof bytes | SYMBT3 proof bytes | proof size ratio | monolithic public bytes | SYMBT3 public bytes | public size ratio | SYMBT3 shape | notes |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 1 | 2,109.052 | 17.656 | 119.45x | 3,664.787 | 17.491 | 209.52x | 1,206,465 | 311,568 | 0.258 | 15,171 | 18,715 | 1.234 | 1 WHIR / 0 family / 1 table | K6a selected, no fallback |
| 2 | 6,232.810 | 24.180 | 257.77x | 7,519.404 | 49.591 | 151.63x | 1,256,159 | 335,935 | 0.267 | 15,187 | 18,715 | 1.232 | 1 WHIR / 0 family / 1 table | K6a selected, no fallback |
| 4 | 13,326.962 | 24.348 | 547.36x | 23,325.334 | 25.078 | 930.11x | 1,556,795 | 329,707 | 0.212 | 15,219 | 18,715 | 1.230 | 1 WHIR / 0 family / 1 table | K6a selected, no fallback |
| 8 | 51,182.449 | 30.702 | 1,667.09x | 43,438.693 | 67.128 | 647.10x | 1,613,175 | 387,417 | 0.240 | 15,283 | 18,715 | 1.225 | 1 WHIR / 0 family / 1 table | K6a selected, no fallback |

These rows are one-shot route measurements emitted by the comparison reporter;
the individual `public_verify_v2_vs_k` and
`symbt3_accumulator_authority_vs_k` suites remain the repeated Criterion
timing sources. SYMBT3 K6a is NonZK integrity only, explicit opt-in, not default
product routing, does not implement K5 masking, and does not support private
manifest membership. Product `verify_public` remains unchanged, and
K5/private manifest/native multi-oracle work remains deferred.

### P5 — SYMBT3-F Ajtai linear-algebra layout

SYMBT3-F adds the explicit Ajtai commitment/opening linear-algebra layout and
profile benchmark:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_f_vs_k"
```

SYMBT3-F architecture benchmark, recorded on 2026-05-07 with the command
above:

| k | top-level WHIR proofs | family-columnar subproofs | backend tables | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | sumcheck rounds | max oracle `num_vars` | Ajtai evaluator | product law | beta action | ring degree |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|---:|
| 1 | 1 | 0 | 1 | 407,284 | 7.1685 ms | 6.7837 ms | 22 | 22 | 8 | 13 | `DirectDevMatrixVectorV1` | `RqNegacyclicConvolutionV1` | `RingCoefficientActionV1` | 64 |
| 2 | 1 | 0 | 1 | 422,389 | 8.0666 ms | 7.7776 ms | 28 | 28 | 8 | 13 | `DirectDevMatrixVectorV1` | `RqNegacyclicConvolutionV1` | `RingCoefficientActionV1` | 64 |

These numbers remain architecture/proof-shape measurements for a
non-authoritative development path, not product public-verifier performance
claims.

### P5 — SYMBT3-G folded Ajtai projection/range

SYMBT3-G adds the folded Ajtai projection/range development layout and profile
benchmark:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_g_vs_k"
```

SYMBT3-G architecture benchmark, recorded on 2026-05-07 with the command
above:

| k | top-level WHIR proofs | family-columnar subproofs | backend tables | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | sumcheck rounds | max oracle `num_vars` | projection mode | range mode | bound B | projection output length | monomial embedding |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---:|---:|---|
| 1 | 1 | 0 | 1 | 412,101 | 7.3181 ms | 7.1763 ms | 25 | 25 | 8 | 13 | `DirectDevDenseProjectionV1` | `DirectSignedRangeDevV1` | 131,072 | 192 | disabled |
| 2 | 1 | 0 | 1 | 416,389 | 8.6389 ms | 8.0182 ms | 31 | 31 | 8 | 13 | `DirectDevDenseProjectionV1` | `DirectSignedRangeDevV1` | 262,144 | 192 | disabled |

These numbers remain architecture/proof-shape measurements for a
non-authoritative development path, not product public-verifier performance
claims.

### P5 — SYMBT3-H manifest/source membership

SYMBT3-H adds the typed manifest/source membership development layout and
profile benchmark:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_h_vs_k"
```

The benchmark reports manifest component count, manifest coordinate count,
membership challenge count, and the same one-proof architecture metrics. The
required structural guard remains:

```text
top_level_whir_proof_count = 1
family_columnar_subproof_count = 0
backend_table_count = 1
```

SYMBT3-H architecture benchmark, recorded on 2026-05-07 with the command
above:

| k | top-level WHIR proofs | family-columnar subproofs | backend tables | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | sumcheck rounds | max oracle `num_vars` | manifest components | manifest coordinates | membership challenges |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 1 | 735,652 | 25.906 ms | 13.482 ms | 28 | 28 | 11 | 16 | 7 | 1,218 | 1 |
| 2 | 1 | 0 | 1 | 801,784 | 44.825 ms | 19.817 ms | 34 | 34 | 12 | 17 | 7 | 2,436 | 1 |

These numbers remain architecture/proof-shape measurements for a
non-authoritative development path, not product public-verifier performance
claims. The manifest membership table is intentionally typed algebraic/oracle
boundary data; it does not reintroduce byte transcript reconstruction.

### P5 — SYMBT3-I2 native message-oracle views

SYMBT3-I2 adds native CP message-oracle views and a profile benchmark:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_i2_vs_k"
```

The benchmark reports message round count, native message-view coordinate
count, message-to-trace binding count, semantic sumcheck transition count, and
the same one-proof architecture metrics. The required structural guard remains:

```text
top_level_whir_proof_count = 1
family_columnar_subproof_count = 0
backend_table_count = 1
```

SYMBT3-I baseline architecture benchmark, recorded on 2026-05-07:

| k | top-level WHIR proofs | family-columnar subproofs | backend tables | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | sumcheck rounds | max oracle `num_vars` | message rounds | message coordinates | message-to-trace bindings | sumcheck transitions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 1 | 798,232 | 45.866 ms | 19.563 ms | 34 | 34 | 12 | 17 | 1 | 3,928 | 3,928 | 3,928 |
| 2 | 1 | 0 | 1 | 1,100,993 | 169.30 ms | 51.712 ms | 40 | 40 | 13 | 19 | 1 | 7,856 | 7,856 | 7,856 |

SYMBT3-I2 native-view architecture benchmark, recorded on 2026-05-10 with the
command above:

| k | top-level WHIR proofs | family-columnar subproofs | backend tables | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | sumcheck rounds | max oracle `num_vars` | message rounds | message view coordinates | message-to-trace bindings | semantic transitions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 1 | 747,339 | 26.364 ms | 14.600 ms | 29 | 29 | 11 | 16 | 1 | 6 | 0 | 2 |
| 2 | 1 | 0 | 1 | 807,042 | 48.393 ms | 20.824 ms | 35 | 35 | 12 | 17 | 1 | 12 | 0 | 2 |

SYMBT3-I2 is a semantic coverage benchmark for the non-authoritative
development path. It is not a product public-verifier benchmark, and it does
not reintroduce byte transcript/hash/opening reconstruction.

### P5 — SYMBT3-J structured projection / monomial range

SYMBT3-J adds the production-shaped structured projection and monomial
embedding norm/range profile:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_j_vs_k"
```

The benchmark reports projection mode, projection block length, range mode,
bound, projection output length, monomial-embedding status, message view
coordinates, message-to-trace binding count, and the same one-proof
architecture metrics. The required structural guard remains:

```text
top_level_whir_proof_count = 1
family_columnar_subproof_count = 0
backend_table_count = 1
```

SYMBT3-J structured-range architecture benchmark, recorded on 2026-05-10 with
the command above:

| k | top-level WHIR proofs | family-columnar subproofs | backend tables | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | sumcheck rounds | max oracle `num_vars` | projection mode | block len | range mode | bound B | projection output length | monomial embedding | message view coordinates | message-to-trace bindings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|---:|---:|---|---:|---:|
| 1 | 1 | 0 | 1 | 735,444 | 27.255 ms | 14.270 ms | 30 | 30 | 11 | 16 | `StructuredBlockProjectionV1` | 64 | `MonomialEmbeddingRangeV1` | 8,388,608 | 3 | enabled | 6 | 0 |
| 2 | 1 | 0 | 1 | 801,392 | 49.314 ms | 20.919 ms | 36 | 36 | 12 | 17 | `StructuredBlockProjectionV1` | 64 | `MonomialEmbeddingRangeV1` | 16,777,216 | 3 | enabled | 12 | 0 |

SYMBT3-J is a semantic coverage benchmark for the non-authoritative
development path. It replaces the default direct development projection/range
scaffold, but it is not a final integer/mod-q lattice soundness claim and is
not a product public-verifier benchmark.

### P5 — SYMBT3-J2 verifier-cost attribution

SYMBT3-J2 adds verifier-cost attribution and range-evaluator compression while
keeping the same default J semantics. The deterministic monomial-witness and
representative-residual columns are no longer committed table columns; they are
virtual consequences of the projected opening and relation-bound range layout.
This reduces the default `k=2` profile from `num_vars=18` to `num_vars=17` and
from 38 to 36 opened field elements while preserving:

```text
top_level_whir_proof_count = 1
family_columnar_subproof_count = 0
backend_table_count = 1
message_to_trace_binding_count = 0
```

Differential J2 profiles, recorded on 2026-05-10 with:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_j"
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_i2"
```

| profile | k | projection mode | range mode | projection output len | monomial coords | proof bytes | verify mean | num_vars | opened fields |
|---|---:|---|---|---:|---:|---:|---:|---:|---:|
| `symbt3_i2` | 2 | `DirectDevDenseProjectionV1` | `DirectSignedRangeDevV1` | 192 | 0 | 804,220 | 21.320 ms | 17 | 36 |
| `symbt3_j_projection_only` | 2 | `StructuredBlockProjectionV1` | `DirectSignedRangeDevV1` | 3 | 0 | 800,217 | 20.927 ms | 17 | 36 |
| `symbt3_j_monomial_only` | 2 | `DirectDevDenseProjectionV1` | `MonomialEmbeddingRangeV1` | 192 | 192 | 804,892 | 21.322 ms | 17 | 36 |
| `symbt3_j_full` | 2 | `StructuredBlockProjectionV1` | `MonomialEmbeddingRangeV1` | 3 | 3 | 802,471 | 21.227 ms | 17 | 36 |

The first attribution run shows the previous J overhead was primarily the
extra oracle variable caused by committed range/debug columns, not local
projection arithmetic. For `symbt3_j_full` at `k=2`, the single-shot verifier
profile reported approximately 22.1 ms total, 7.5 ms in WHIR/PCS opening
verification, 2.0 ms in transcript/public-statement work, and 12.6 ms in the
combined sumcheck/final-constraint evaluator.

### P5 — SYMBT3-K0/J3 virtual/succinct evaluator refactor

SYMBT3-K0/J3 begins the virtual/succinct evaluator refactor before any further
authority promotion. Manifest/source membership is no longer materialized as
three backend table columns (`manifest_source`, `manifest_value`, and
`manifest_residual`), and `manifest_coordinate_count` is no longer part of the
backend row-domain maximum. The manifest root, source-column layout, and typed
manifest rows remain input-side beta-bound data; active manifest/source
tampering still rejects before proof construction or at public-statement
verification. The verifier profile now attributes the generic final evaluator
to manifest, source R1CS, folded-boundary, product-residual, Ajtai, range, and
message-view buckets. The benchmark harness enforces the K0/J3 structural gate
that backend `oracle_len` grows by at most 2x when `k` doubles. Source R1CS
residual bundling is the next succinct-evaluator target if the new attribution
shows it dominates the remaining final evaluator cost.

### P5 — SYMBT3-K1 compressed research public manifest

SYMBT3-K1 compresses the research public manifest boundary. The canonical
SYMBT3 development public statement now contains short boundary objects:
`batch_manifest_root`, manifest/source layout digests, input public-boundary
digest, source assignment boundary digest, source Ajtai commitment boundary
digest, message oracle roots, folded-output boundary data, and semantic layout
digests. It no longer serializes every active public/source coordinate matrix,
every source assignment root, or every source Ajtai opening root. The verifier
therefore binds the manifest root/layout as input-side data and does not
reconstruct/hash the full logical manifest. This is a research-only compressed
public statement; product `verify_public` remains on the monolithic
authoritative typed CP path.

K1b adds the research `ManifestEvaluationClaim` on top of this compressed
boundary. The public statement now carries a canonical BabyBear
`manifest_eval_claim`, and the single top-level SYMBT3 WHIR proof opens the
source and manifest membership columns at a verifier-derived
`manifest_membership_challenge`. This keeps `family_columnar_subproofs = 0` and
`top_level_whir_proof_count = 1`, but increases the current opened-field count
by two relative to the K0/J3/K1a measurements below.
K1c changes the verifier-side evaluator to stream the source-side membership
claim directly from the compressed public statement instead of reconstructing
the full manifest row matrix. Prover-side row reconstruction remains only a
sanity check.
The K1 verifier additionally recomputes the canonical manifest oracle root
from that same streamed public source boundary and requires it to equal
`manifest_oracle_root`; a root-linked but non-canonical manifest root therefore
fails before claim verification while preserving one top-level WHIR proof and
zero family subproofs.
K1e.2 removes both the dense manifest-oracle evaluation column and the
materialized source-view column from the backend table. The public statement
keeps the legacy `manifest_eval_claim` field as non-semantic data, but
verification derives both `ManifestView(zeta)` and virtual `SourceView(zeta)`
from compressed public boundary data. The benchmark reports
`source_view_backend_column_count = 0`,
`source_view_materialized_coordinate_count = 0`,
`manifest_backend_column_count = 0`, and
`manifest_materialized_coordinate_count = 0`.

The K0/J3/K1 `symbt3_j_vs_k` scaling run, recorded on 2026-05-10 with
`SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4,8,16,32,64`, reported:

| k | proof bytes | prove mean | verify mean | opened fields | num_vars | oracle_len | manifest coordinates | message_to_trace_binding_count |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 398,442 | 8.060 ms | 7.042 ms | 21 | 13 | 8,192 | 1,218 | 0 |
| 2 | 397,646 | 8.878 ms | 7.109 ms | 21 | 13 | 8,192 | 2,436 | 0 |
| 4 | 404,432 | 11.687 ms | 6.955 ms | 21 | 13 | 8,192 | 4,872 | 0 |
| 8 | 428,092 | 17.461 ms | 7.838 ms | 21 | 14 | 16,384 | 9,744 | 0 |
| 16 | 649,445 | 30.010 ms | 10.536 ms | 21 | 15 | 32,768 | 19,488 | 0 |
| 32 | 681,418 | 52.673 ms | 12.871 ms | 21 | 16 | 65,536 | 38,976 | 0 |
| 64 | 700,328 | 97.545 ms | 16.197 ms | 21 | 17 | 131,072 | 77,952 | 0 |

The proof remains one top-level WHIR object with zero family-columnar subproofs
and one backend table. The backend oracle length no longer jumps by 4x at
`k=16`: the sequence is 8,192, 8,192, 8,192, 16,384, 32,768, 65,536, 131,072,
so the hard K0/J3 gate of at most 2x growth per k doubling passes for this run.
`public_statement_bytes` is flat at 10,256 for all measured `k`, while
`manifest_coordinate_count` remains a logical coverage counter. The generated
scaling summary reports log-log slopes of about 0.223 for verify time, 0.621
for prove time, 0.167 for proof bytes, 0.000 for public statement bytes, and
0.714 for oracle length. These are still non-authoritative, non-ZK development
numbers and not product public-verifier claims.

### P5 — Asymptotic scaling CSV and plot dashboard

The asymptotic-scaling benchmark suite writes a machine-readable CSV and plot
dashboard:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4,8,16,32,64 \
  cargo bench --bench whir_scaling --features whir -- "symbt3_j_vs_k"
python3 scripts/plot_symbt3_scaling.py benchmarks/symbt3_scaling.csv plots/symbt3
```

The benchmark writes `benchmarks/symbt3_scaling.csv` directly and also prints
`SYMBT3_CSV,...` rows for shell collection. The plotting script uses
pandas/matplotlib when available and otherwise emits dependency-free SVG plots,
`doubling_ratios.csv`, and `summary.md`. The summary reports empirical log-log
slopes for verify/prove time, proof bytes, public statement bytes, oracle
length, opened fields, transcript squeezes, source R1CS claims, manifest
coordinates, and message coordinates. The guardrail plot tracks one top-level
WHIR proof, zero family subproofs, one backend table, and zero
message-to-trace bindings.

**Acceptance criteria**

- `SYMBT3` verifies honest `k = 1, 2, 4` same-shape batches with one CP proof
  object per bucket.
- The verifier does not call witness-side `CpFieldRelation::check`.
- The verifier does not receive or open full private messages, openings,
  original witnesses, or folded witnesses.
- Independent `SYMBT2F`, `SYMBT2C`, monolithic typed CP, or per-table WHIR
  proofs are not accepted as a `SYMBT3` proof.
- Negative tests cover shape mismatch, public-boundary mismatch, message-oracle
  root tampering, challenge tampering, beta tampering, folded-output tampering,
  Ajtai algebra tampering, R1CS/GR1CS residual tampering, batch-manifest-root
  tampering, active source/manifest coordinate tampering, message semantic
  layout tampering, message oracle coordinate tampering, message view layout
  tampering, structured projection/range/monomial layout tampering, and
  projected opening/range witness tampering.
- Benchmark output shows a small constant number of WHIR proof objects and a
  proof size/verifier time trajectory consistent with the CP-SNARK north star.

---


## Milestone P6 - Versioned Field-Native Transcript Cleanup

**Goal.** reduce constant factors only after the CP-aware architecture is in place.

**Implementation requirements**

- Keep the existing exact-byte Poseidon2/BabyBear path as compatibility and
  diagnostic version 1.
- Define a versioned field-native public transcript body for `SYMBT3` where
  values that are already BabyBear field elements are absorbed as field
  elements, not re-encoded as byte tables.
- Keep domain separation, root serialization, and proof-envelope versioning
  documented.
- Do not prove SHA-256 or legacy exact-byte transcript machinery inside WHIR.

**Acceptance criteria**

- `SYMBT3` keeps the same security boundary while reducing byte/packing
  overhead.
- Public proof versioning makes v1/v2 semantics unambiguous.
- Compatibility tests remain green or are explicitly scoped as legacy.

---


## Milestone P7 - Benchmark Against the North Star

**Goal.** prove the cost model has changed, not just the implementation.

**Required benchmark curves**

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4 cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4 cargo bench --bench whir_scaling --features whir -- "typed_cp_verify_only_vs_k"
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2,4 cargo bench --bench whir_scaling --features whir -- "public_proof_size_vs_k"
cargo bench --bench whir_scaling --features whir -- "batched_cp_shape_profile_vs_k"
cargo bench --bench whir_scaling --features whir -- "batched_cp_verify_only_vs_k"
cargo bench --bench whir_scaling --features whir -- "batched_cp_product_oracle_whir_vs_k"
cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_whir_v2_vs_k"
cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_columnar_v2_vs_k"
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1 cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_columnar_poseidon_v2_vs_k"
cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_family_columnar_v2_vs_k"
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1 cargo bench --bench whir_scaling --features whir -- "batched_cp_semantic_family_columnar_poseidon_v2_vs_k"
cargo bench --bench whir_scaling --features whir -- "public_proof_batched_cp_size_vs_k"
```

The `batched_cp_shape_profile_vs_k` and `batched_cp_verify_only_vs_k` groups
measure P3 software/profile costs. The `batched_cp_product_oracle_whir_vs_k`
group measures the current non-authoritative P4 WHIR product-oracle proof. P4
is still incomplete until the WHIR proof enforces the structured CP predicate
over that oracle with acceptable negative coverage and performance. The
`batched_cp_semantic_whir_v2_vs_k` group measures the heavy SYMBTC2
full-selection semantic candidate and is expected to be much slower than
SYMBTC1 until the next columnar/proximity implementation replaces explicit
enumeration. The `batched_cp_semantic_columnar_v2_vs_k` group measures the
current bounded columnar residual candidate. It supports all semantic families
that have non-empty constraints for the selected shape, but remains
development-only until broader negative coverage and benchmark comparisons are
complete. The default columnar benchmark uses a fast SHA-shaped same-shape CP
fixture so it exercises the active columnar/proximity plumbing cheaply. The
separate `batched_cp_semantic_columnar_poseidon_v2_vs_k` group uses a
Poseidon/BabyBear-shaped fixture and defaults to `k = 1`; use it to profile the
full nine-family columnar surface before attempting broader curves. The columnar
path now exposes a development-only private-opening profile that maps each proof
opening span back to its residual family. Tests use that profile to tamper one
sampled opening per instantiated family, and the benchmarks print residual
counts, sampled checks, and private eval counts by family. This profiling data
is intentionally not part of the public proof format.

The `batched_cp_semantic_family_columnar_*` groups measure the `SYMBT2F`
family-local diagnostic path. They print per-family row counts, local table
sizes, subproof indices, local domain sizes, total internal subproof count,
proof bytes, and `family_attribution` data. These groups are retained to catch
over-materialization and to support negative tests; they are not the production
performance target. The production comparison point for the next architecture
is the future `SYMBT3` CP-aware WHIR oracle relation.

**Acceptance criteria**

- Public verification grows much slower than the current near-linear baseline.
- Public envelope size is constant or logarithmic in `k`.
- Typed output verification remains negligible.
- The docs report both absolute times and scaling ratios.

---


## Non-Goals

- Do not make `verify_public` call witness-side checks.
- Do not hide the linearity by skipping requested `k` values.
- Do not claim production performance from constant-factor row reductions alone.
- Do not change Poseidon2/BabyBear semantics without proof-envelope versioning.
- Do not remove current authoritative typed CP tests until the new compressed
  architecture has equivalent negative coverage.

---


## Immediate Next Step

Stop treating `SYMBT2F` table splitting as the production route. Keep it as a
diagnostic and negative-test harness, but pivot implementation planning to
`SYMBT3`: a CP-aware WHIR oracle relation.

The next concrete step is a design/implementation plan for `SYMBT3` with:

- CP round messages `M_i(T, U_i)` as first-class committed WHIR/BCS oracles;
- public `c_fs,i` roots bound directly to those message oracles;
- Fiat-Shamir challenges derived outside the proven relation;
- algebraic folding/Ajtai/GR1CS constraints over committed field/ring columns;
- one WHIR-backed CP proof object per same-shape bucket;
- no exact-byte transcript/hash/opening proof machinery inside `pi_cp`;
- no product-route promotion until negative coverage and benchmarks are green.

The implementation must still avoid appended typed CP R1CS lowering and must
not open private oracle bytes to run `CpFieldRelation::check` in the verifier.
