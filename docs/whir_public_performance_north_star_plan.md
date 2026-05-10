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

```text
If a check only proves that byte encodings, transcript bodies, or hash inputs
were formed correctly, do not assume it belongs inside pi_cp.
```

The next architecture target is therefore `SYMBT3`: a CP-aware WHIR oracle
relation, not more `SYMBT2F` table splitting.

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

## Milestone P3 - Structured Batched CP Relation

Goal: replace the flat monolithic typed CP relation with a same-shape
product-domain relation, not with `k` independent WHIR proofs and not with an
appended R1CS containing `k` copied circuits.

Implementation requirements:

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

Acceptance criteria:

- Exact same-shape objects batch; shape mismatch rejects.
- Manifest tampering, omitted item, duplicate item, reordered item, wrong
  active mask, and inactive padding tampering reject.
- Any item-level CP violation rejects the batch evaluator.
- The implementation exposes product-domain witness/message oracles `W(T,V)`
  and `M_i(T,U_i)` and does not construct an appended typed CP R1CS.

Status: implemented as a non-authoritative foundation. The repo now has
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

## Milestone P4 - WHIR Structured Relation Integration

Goal: make WHIR consume `BatchedCpStatementShape` directly and produce one
WHIR-backed CP proof per exact same-shape bucket.

Implementation requirements:

- Add a WHIR-facing structured relation path for product-domain evaluators.
- WHIR setup must receive product-domain dimensions and evaluator metadata, not
  a flattened appended R1CS.
- WHIR prove/verify must produce/check one CP proof per same-shape bucket.
- Independent `k` WHIR-backed CP proofs must not be accepted as a batched proof.
- Product public routing stays on monolithic typed CP until structured proof
  semantics, negative tests, and benchmarks are green.

Acceptance criteria:

- `k = 1` structured path matches monolithic typed CP semantics.
- `k = 2, 4` verify with one structured proof per same-shape bucket.
- Proof from another shape, manifest, batch size, round commitment, or WHIR
  parameter digest rejects.
- `typed_cp_verify_only_vs_k` and public verifier benchmarks grow materially
  slower than the current monolithic baseline, or the measured blocker is
  documented.

Status: in progress. WHIR now exposes a non-authoritative structured batched CP
relation description for `BatchedCpStatementShape`. The context has a dedicated
`SYMBTC1` marker, stable relation id, public statement byte size, product-domain
size, witness-oracle row length, and per-round message-oracle lengths. Its
`RelationDescription` deliberately reports `num_constraints = 0` because this
is not a flattened/appended R1CS relation.

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

```text
development-only diagnostic path
oracle layout sanity checker
negative-test harness
byte/table over-materialization warning system
```

It should not be treated as the route to the production CP proof. Further
splitting of `ManifestMembership`, folded-output contribution binding, or
message sections is useful only when it improves diagnostics. The next
production-oriented P4/P5 work should pivot to a CP-aware WHIR relation where
message oracles are committed objects queried directly by the proof system and
the proven constraints are the folding algebra itself.

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

## Milestone P5 - SYMBT3 CP-Aware WHIR Oracle Relation

Goal: replace byte/table emulation of CP with one CP-aware WHIR proof object per
same-shape bucket.

Implementation requirements:

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

Current submilestone:

- `SYMBT3-I` extends the non-authoritative algebraic blocks with a versioned
  CP message-semantic layout. The cumulative development profile
  still includes the `SYMBT3-G` Ajtai norm/range layout, using
  `RqNegacyclicConvolutionV1` for folded GR1CS product residuals,
  `RingCoefficientActionV1` for ring/module beta action, and
  `DirectDevMatrixVectorV1` for the folded Ajtai map check. It adds
  `DirectDevDenseProjectionV1` and `DirectSignedRangeDevV1` as development
  projection/range evidence for the folded Ajtai opening, and now adds
  `Symbt3BatchManifestLayoutV1` for typed manifest/source membership, and now
  adds `Symbt3MessageSemanticLayoutV1` for typed message-to-trace binding.
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
- `SYMBT3-G` adds folded Ajtai norm/range evidence. The first development
  profile projects `flatten(f_fold)` with `DirectDevDenseProjectionV1` and
  checks the projected coefficients with `DirectSignedRangeDevV1` under a
  relation-bound bound. This is development check-field range evidence, not
  full integer/mod-q lattice range authority.
- `SYMBT3-H` adds typed source/manifest membership. The first development
  profile binds a typed batch manifest root, manifest layout digest, and
  source-column layout digest, and checks
  `Source(T,K,C) = Manifest(T,K,C)` for active public/input-side source
  coordinates and digest/root boundary coordinates inside the same single
  SYMBT3 table. This is not byte transcript reconstruction.
- `SYMBT3-I` adds typed CP message semantic validity. The first development
  profile binds a message-semantic layout digest, treats round-message roots as
  the CP message commitment boundary, derives prefix round challenges outside
  the relation, and checks typed message-to-trace equality inside the same
  single SYMBT3 table. The checked values are algebraic packed message
  coordinates, not canonical message bytes, FS openings, or digest-body tables.
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
- `SYMBT3-I` remains non-authoritative and non-ZK; full monomial embedding
  range authority, production sumcheck transcript authority,
  production integer/lattice `R_q` reduction semantics, and final WHIR/Σ-IOP
  soundness analysis are future SYMBT3 blocks.

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

SYMBT3-D architecture benchmark baseline, recorded on 2026-05-07 with:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_d_vs_k"
```

| k | top-level WHIR proofs | family-columnar subproofs | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | transcript squeezes | max oracle `num_vars` | source R1CS residual claims | folded GR1CS residual claims |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 330,836 | 4.7096 ms | 5.3228 ms | 14 | 14 | 14 | 12 | 64 | 384 |
| 2 | 1 | 0 | 404,215 | 7.0489 ms | 7.0847 ms | 20 | 20 | 20 | 13 | 128 | 384 |

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

SYMBT3-I adds the CP message semantic development layout and profile
benchmark:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "symbt3_i_vs_k"
```

The benchmark reports message round count, message coordinate count,
message-to-trace binding count, sumcheck transition count, and the same
one-proof architecture metrics. The required structural guard remains:

```text
top_level_whir_proof_count = 1
family_columnar_subproof_count = 0
backend_table_count = 1
```

SYMBT3-I architecture benchmark, recorded on 2026-05-07 with the command
above:

| k | top-level WHIR proofs | family-columnar subproofs | backend tables | proof bytes | prove mean | verify mean | opened field elements | PCS/Merkle opening proxy | sumcheck rounds | max oracle `num_vars` | message rounds | message coordinates | message-to-trace bindings | sumcheck transitions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 1 | 798,232 | 45.866 ms | 19.563 ms | 34 | 34 | 12 | 17 | 1 | 3,928 | 3,928 | 3,928 |
| 2 | 1 | 0 | 1 | 1,100,993 | 169.30 ms | 51.712 ms | 40 | 40 | 13 | 19 | 1 | 7,856 | 7,856 | 7,856 |

SYMBT3-I is a semantic coverage benchmark for the non-authoritative
development path. It is not a product public-verifier benchmark, and it does
not reintroduce byte transcript/hash/opening reconstruction.

Acceptance criteria:

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
  layout tampering, message oracle coordinate tampering, and message-to-trace
  binding tampering.
- Benchmark output shows a small constant number of WHIR proof objects and a
  proof size/verifier time trajectory consistent with the CP-SNARK north star.

## Milestone P6 - Versioned Field-Native Transcript Cleanup

Goal: reduce constant factors only after the CP-aware architecture is in place.

Implementation requirements:

- Keep the existing exact-byte Poseidon2/BabyBear path as compatibility and
  diagnostic version 1.
- Define a versioned field-native public transcript body for `SYMBT3` where
  values that are already BabyBear field elements are absorbed as field
  elements, not re-encoded as byte tables.
- Keep domain separation, root serialization, and proof-envelope versioning
  documented.
- Do not prove SHA-256 or legacy exact-byte transcript machinery inside WHIR.

Acceptance criteria:

- `SYMBT3` keeps the same security boundary while reducing byte/packing
  overhead.
- Public proof versioning makes v1/v2 semantics unambiguous.
- Compatibility tests remain green or are explicitly scoped as legacy.

## Milestone P7 - Benchmark Against the North Star

Goal: prove the cost model has changed, not just the implementation.

Required benchmark curves:

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
