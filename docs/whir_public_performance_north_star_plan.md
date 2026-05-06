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
work. The next P4 milestone should therefore design shared family-level WHIR
verification or multi-proof aggregation before doing more local table splits.

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
family-local variant and print per-family row counts, local table sizes,
subproof indices, local domain sizes, total internal subproof count, and proof
bytes so they can be compared directly against the rectangular `SYMBT2C`
baseline.

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

Continue P4. The next step is replacing the heavy SYMBTC2 full-selection
enumeration with a genuine typed-column/product-domain proximity relation:
Poseidon traces, manifest rows, challenge/beta columns, folded-output columns,
Ajtai columns, and original-R1CS columns should be committed as semantic
oracles with low-degree residual checks rather than opened exhaustively. The
implementation must continue to use the structured relation/evaluator
interface, avoid lowering the batch into an appended typed CP R1CS, and must
not open private oracle bytes to run `CpFieldRelation::check` in the verifier.
