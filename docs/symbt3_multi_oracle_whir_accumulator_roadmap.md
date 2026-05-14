# SYMBT3 Multi-Oracle WHIR Accumulator Roadmap

**Project:** Symphony / WHIR accumulator work  
**Scope:** Improve the SYMBT3 K6a WHIR accumulator after the current single-oracle WHIR baseline.  
**Status:** Milestone 0 implemented; later milestones remain roadmap work.
**Primary goal:** Make the multi-oracle WHIR accumulator verify like one shared WHIR proof plus small batching overhead, rather than like many independent WHIR proofs.

---

## 1. Current Benchmark Baseline

Latest SYMBT3 K6a single-oracle WHIR benchmark table:

| k | monolithic verify ms | SYMBT3 K6a verify ms | verify speedup | monolithic prove ms | SYMBT3 prove ms | prove speedup | monolithic proof bytes | SYMBT3 proof bytes | proof ratio | monolithic public bytes | SYMBT3 public bytes | public ratio |
| --: | -------------------: | -------------------: | -------------: | ------------------: | --------------: | ------------: | ---------------------: | -----------------: | ----------: | ----------------------: | ------------------: | -----------: |
| 1 | 2,109.052 | 17.656 | 119.45x | 3,664.787 | 17.491 | 209.52x | 1,206,465 | 311,568 | 0.258 | 15,171 | 18,715 | 1.234 |
| 2 | 6,232.810 | 24.180 | 257.77x | 7,519.404 | 49.591 | 151.63x | 1,256,159 | 335,935 | 0.267 | 15,187 | 18,715 | 1.232 |
| 4 | 13,326.962 | 24.348 | 547.36x | 23,325.334 | 25.078 | 930.11x | 1,556,795 | 329,707 | 0.212 | 15,219 | 18,715 | 1.230 |
| 8 | 51,182.449 | 30.702 | 1,667.09x | 43,438.693 | 67.128 | 647.10x | 1,613,175 | 387,417 | 0.240 | 15,283 | 18,715 | 1.225 |

To avoid ambiguity, this document calls the table parameter `k_table`. WHIR's internal folding parameter should be called `kappa` or `whir_folding_k` in code and docs.

---

## 2. Main Read of the Benchmarks

### 2.1 SYMBT3 verification is already excellent

SYMBT3 K6a verification is almost flat:

```text
k_table = 1: 17.656 ms
k_table = 2: 24.180 ms
k_table = 4: 24.348 ms
k_table = 8: 30.702 ms
```

Meanwhile monolithic verification grows from **2,109.052 ms** to **51,182.449 ms**. This means the accumulator is already doing the main job: it avoids monolithic verifier blowup.

### 2.2 Proof size is also already strong

SYMBT3 proof size is roughly **21% to 27%** of the monolithic proof size.

The best proof-size row is:

```text
k_table = 4
monolithic proof bytes = 1,556,795
SYMBT3 proof bytes     =   329,707
proof ratio            = 0.212
```

### 2.3 `k_table = 4` is the current balanced default

For current development, use:

```text
default benchmark row: k_table = 4
fastest demo row:      k_table = 1
stress/scaling row:    k_table = 8
```

Why `k_table = 4` should be the default:

- Verification is essentially tied with `k_table = 2`.
- Proving is much better than `k_table = 2` and `k_table = 8`.
- Proof ratio is best: `0.212`.
- Monolithic prove speedup is best: `930.11x`.

### 2.4 The current weak spot is prover irregularity

The SYMBT3 prover is not monotone:

```text
k_table = 1: 17.491 ms
k_table = 2: 49.591 ms
k_table = 4: 25.078 ms
k_table = 8: 67.128 ms
```

This suggests either:

1. a real parameter knee,
2. a memory/cache threshold,
3. an implementation artifact,
4. unnecessary allocation/copying,
5. Merkle tree/path materialization overhead,
6. duplicated transcript/constraint batching work,
7. or a proof serialization section that scales unexpectedly.

This needs profiling before further optimization.

---

## 3. Roadmap Thesis

The next improvement should not be “make one WHIR proof slightly faster” first.

The next improvement should be:

> Make multi-oracle WHIR behave like one shared WHIR proof over a structured batched oracle, not like `t` independent WHIR proofs for `t` oracles.

The desired asymptotic/concrete shape is:

```text
multi_oracle_verify(t)
  ≈ one WHIR verifier
  + wider leaves / tuple decoding
  + O(t * num_queries) small field work
```

not:

```text
multi_oracle_verify(t)
  ≈ t * independent_whir_verify
```

This matches WHIR's core strength: fast verification for constrained Reed--Solomon proximity claims with batching of constraints, and it aligns with the Symphony goal of keeping Fiat--Shamir/hash logic out of the proven circuit.

---

## 4. Design Principles

### 4.1 Do not run one WHIR verifier per oracle

Bad shape:

```rust
for oracle in oracles {
    verify_whir(oracle, constraint_for_oracle)?;
}
```

Target shape:

```rust
verify_whir(
    batched_oracle,
    batched_constraints,
    shared_query_schedule,
)?;
```

### 4.2 Same-domain oracles should share leaves and queries

For same-domain oracles `f_0, ..., f_{t-1}`, use tuple leaves:

```text
leaf(x) = (f_0(x), f_1(x), ..., f_{t-1}(x))
```

After committing to the tuple-leaf Merkle root, sample a batching challenge `gamma` and define:

```text
f_star(x) = f_0(x)
          + gamma * f_1(x)
          + gamma^2 * f_2(x)
          + ...
          + gamma^(t-1) * f_(t-1)(x)
```

The verifier opens one Merkle path per queried position, reads the tuple at that position, and locally computes `f_star(x)`.

### 4.3 Group heterogeneous oracles by shape

Only batch oracles together when they share the same relevant WHIR shape:

```text
field
extension field mode
domain size
rate
folding parameter
security mode
constraint interface
oracle layout compatibility
```

If oracles have different WHIR shapes, group them into shape-compatible batches instead of forcing everything into one tree.

### 4.4 Keep the Symphony no-Fiat-Shamir-in-circuit invariant

Do not push WHIR verification, Merkle openings, or Fiat--Shamir replay into the CP-SNARK circuit.

The accumulator interface should stay close to:

```text
public:
  compact accumulator instance
  roots / commitments
  challenge-derived evaluation claims
  shape metadata

private:
  opened local values
  witness material
  local oracle slices

CP-SNARK proves:
  algebraic consistency of the accumulator update

outside circuit:
  Fiat-Shamir transcript
  Merkle opening checks
  WHIR query scheduling
  root binding
```

This preserves Symphony's central advantage: avoiding random-oracle/hash gadgets inside the proven statement.

---

## 5. Milestone 0 — Benchmark Hygiene and Counters

### Goal

Make the benchmark explainable before optimizing further.

### Deliverables

Add counters and timers to the current single-oracle path.

Verifier timers:

```text
transcript absorb/squeeze
Merkle root/path verification
field extension operations
fold-query evaluation
eq/Lagrange evaluation
constraint batching
Symphony accumulator decoding
proof deserialization
public input parsing
```

Prover timers:

```text
oracle construction
WHIR folding layers
Merkle tree build
Merkle path materialization
constraint construction
constraint batching
transcript absorb/squeeze
field extension operations
allocations / copies
proof serialization
Symphony accumulator glue
```

Counters:

```text
num_oracles
num_roots
num_query_positions
num_merkle_paths
num_hashes_estimate
num_field_ops_estimate
num_extension_field_ops_estimate
proof_bytes_total
proof_bytes_by_section
public_bytes_total
public_bytes_by_section
peak_alloc_bytes
```

### Acceptance criteria

For every benchmark row, emit a structured report such as:

```json
{
  "k_table": 4,
  "verify_ms": 24.348,
  "prove_ms": 25.078,
  "proof_bytes": 329707,
  "public_bytes": 18715,
  "num_roots": 1,
  "num_query_positions": 0,
  "num_merkle_paths": 0,
  "timers": {
    "verify_transcript_ms": 0.0,
    "verify_merkle_ms": 0.0,
    "verify_field_ms": 0.0
  }
}
```

The exact schema can differ, but it must be stable and diffable.

### Status

Implemented for the current single-oracle K6a SYMBT3 accumulator benchmark
path. `symbt3_accumulator_authority_vs_k` now emits the existing
`SYMBT3_CSV` row plus a stable JSONL row with prefix
`SYMBT3_MILESTONE0_JSON,` and writes the same JSON object to:

```text
benchmarks/symbt3_milestone0.jsonl
```

The JSON schema is `symphony.symbt3.milestone0.v1`. It includes:

- `k_table`, measured `prove_ms`, measured `verify_ms`;
- total proof/public bytes plus `proof_bytes_by_section` and
  `public_bytes_by_section`;
- counters for roots, query positions, Merkle-path proxy, hash/field-operation
  estimates, peak allocation estimate, proof shape, backend table count, and
  source-R1CS residual verifier evaluations;
- verifier timers for transcript, Merkle/PCS opening, field operations,
  field-extension operations, fold-query evaluation, eq/Lagrange evaluation,
  constraint batching, accumulator decoding, proof parsing, and public-input
  parsing;
- prover timers for oracle construction, WHIR folding, Merkle tree build,
  Merkle-path materialization, constraint construction/batching, transcript
  work, field/extension-field operations, allocation/copy proxy time, proof
  serialization, and Symphony accumulator glue.

This is benchmark hygiene only. It does not change `ProofBundleV2`,
`PublicProofBundle`, WHIR payload bytes, authority flags, product
`verify_public` routing, or the K6a NonZK integrity security boundary. Product
`verify_public` is still expected to pass through the authoritative monolithic
WHIR typed-CP route; malformed SYMBT3/K6a profile or proof-kind inputs still
fail closed in the explicit opt-in route.

---

## 6. Milestone 1 — Single-Oracle Cleanup

### Goal

Ensure the current single-oracle baseline is not hiding easy wins or anomalies.

### Tasks

1. Investigate why `k_table = 2` prover time is worse than `k_table = 4`.
2. Investigate why `k_table = 8` prover time and proof size jump.
3. Check proof section sizes by row.
4. Check whether `k_table = 8` creates more openings, larger messages, or more serialized metadata.
5. Check whether allocation/copy counts spike at `k_table = 2` or `k_table = 8`.
6. Confirm whether WHIR alternate-domain verifier encoding is enabled.

### Specific questions

```text
Is k_table=2 paying overhead without enough batching benefit?
Is k_table=8 crossing a cache/memory threshold?
Is proof serialization duplicating metadata at k_table=8?
Are roots or transcript labels duplicated?
Are field-extension operations dominating specific rows?
Is the same oracle data copied more than once?
```

### Acceptance criteria

- Explain the `k_table = 2` prover anomaly.
- Explain the `k_table = 8` prover/proof-size jump.
- Choose one of:
  - fix the issue,
  - mark it as expected from parameters,
  - or record it as a known limitation with evidence.

### Target

For the current single-oracle path:

```text
k_table=2 prove: reduce from 49.591 ms toward <= 30 ms, or explain why not.
k_table=8 prove: reduce from 67.128 ms toward <= 50 ms, or explain why not.
k_table=8 proof: reduce from 387,417 bytes toward <= 350 KiB, or explain why not.
```

---

## 7. Milestone 2 — Shared-Query Tuple-Leaf Multi-Oracle WHIR

### Goal

Implement the first real multi-oracle accumulator path for same-domain oracles.

### Core idea

Instead of one Merkle tree/proof per oracle, commit to tuple leaves:

```text
leaf(x) = (f_0(x), f_1(x), ..., f_{t-1}(x))
```

Then use one query schedule and one path per queried domain position.

### New concepts/types

Suggested names:

```rust
struct WhirOracleShapeId(...);
struct MultiOracleWhirShape { ... }
struct TupleLeafOracleLayout { ... }
struct SharedQuerySchedule { ... }
struct MultiOracleBatchingChallenge { gamma: F }
struct MultiOracleOpenedTuple<F> { values: Vec<F> }
struct MultiOracleWhirProof { ... }
```

Shape should bind:

```text
field / extension field mode
domain size
rate
WHIR folding parameter
security level
number of oracles
oracle role labels
constraint layout
serialization version
```

### Prover flow

```text
1. Build same-domain oracle columns f_0, ..., f_{t-1}.
2. Construct tuple leaves leaf(x).
3. Commit once to tuple-leaf Merkle tree.
4. Absorb root and shape into transcript.
5. Sample gamma.
6. Derive f_star evaluations virtually from tuple leaves.
7. Run WHIR on f_star / batched constraints.
8. Emit opened tuples at shared query positions.
```

### Verifier flow

```text
1. Parse shape and proof.
2. Check shape compatibility.
3. Absorb tuple root and shape into transcript.
4. Recompute gamma.
5. Recompute shared query positions.
6. Verify one Merkle path per queried position.
7. Decode tuple leaf values.
8. Locally compute f_star(x).
9. Feed f_star values into the WHIR verifier.
10. Check batched constraints.
```

### Soundness note

The batching challenge `gamma` must be sampled after the commitment/root is bound to the transcript. It must be domain-separated from other WHIR and Symphony challenges.

Use explicit labels such as:

```text
symbt3.multi_oracle.shape.v1
symbt3.multi_oracle.root.v1
symbt3.multi_oracle.gamma.v1
symbt3.multi_oracle.query_schedule.v1
```

### Acceptance criteria

For `t = 1`, the multi-oracle path must match the single-oracle path modulo serialization differences.

For `t > 1`, verifier work should scale sublinearly compared to independent proofs.

Initial targets using `k_table = 4` single-oracle baseline:

```text
single-oracle baseline verify: 24.348 ms
single-oracle baseline prove:  25.078 ms
single-oracle baseline proof:  329,707 bytes
```

Target table:

| oracle count | verify target | proof target | note |
|---:|---:|---:|---|
| 2 | <= 30 ms | <= 1.25x single | shared queries should make this easy |
| 4 | <= 36 ms | <= 1.50x single | tuple leaves should still win |
| 8 | <= 45 ms | <= 2.00x single | may need partial-eval branch later |

---

## 8. Milestone 3 — Multi-Constraint Accumulator Interface

### Goal

Move from “many WHIR checks” to “one WHIR check with many constraints.”

### Bad shape

```rust
for constraint in constraints {
    verify_whir_constraint_separately(constraint)?;
}
```

### Target shape

```rust
verify_whir_with_constraints(
    batched_oracle,
    constraints = vec![constraint_0, constraint_1, ..., constraint_r],
)?;
```

### Constraint object

Suggested type:

```rust
struct WhirConstraintDescriptor<F> {
    constraint_id: ConstraintId,
    oracle_indices: Vec<usize>,
    weight_description: WeightDescription<F>,
    target: F,
    transcript_label: DomainSeparator,
}
```

### Needed distinction

Separate:

```text
oracle batching: combine columns/oracles into f_star
constraint batching: combine constraints into one WHIR constrained-code claim
```

Both are useful, but they should have separate transcript challenges and separate domain separators.

### Acceptance criteria

- One WHIR verifier call can represent multiple semantic constraints.
- Constraint batching challenge is bound after all constraint descriptors are transcript-bound.
- The verifier rejects if constraint descriptors are reordered, dropped, duplicated, or mutated.
- Existing single-constraint tests still pass.

---

## 9. Milestone 4 — Public Byte Cleanup

### Goal

Reduce the fixed SYMBT3 public-byte overhead.

Current public bytes:

```text
monolithic public bytes:
  k=1: 15,171
  k=2: 15,187
  k=4: 15,219
  k=8: 15,283

SYMBT3 public bytes:
  all rows: 18,715
```

SYMBT3 public data is constant, which is good, but it is about **3.4--3.5 KiB** larger than monolithic.

### Inspect public bytes by section

Possible sources:

```text
extra roots
domain descriptors
Fiat-Shamir seed material
opening points
accumulator metadata
serialized field-extension elements
duplicated public inputs
shape descriptors
manifest metadata
alignment/padding/versioning overhead
```

### Target

```text
public bytes <= monolithic public bytes + 1 KiB
```

or, if not possible:

```text
explain exactly why fixed overhead is necessary
```

### Acceptance criteria

- Public byte sections are reported in benchmark output.
- No duplicated public input material.
- Shape metadata is hashed where possible and expanded only in debug/profiling modes.
- Versioning remains explicit and safe.

---

## 10. Milestone 5 — Quasar-Style Partial-Evaluation Research Branch

### Goal

Prototype a more aggressive accumulator design for large oracle counts.

### Motivation

Tuple leaves are likely best for small oracle counts. For larger oracle counts, tuple width and opened payload may grow too much. A Quasar-style partial-evaluation accumulator may eventually win.

### Core idea

Represent all oracles as one bivariate/multilinear object:

```text
W(Y, X)
```

where:

```text
Y = oracle index / instance index variables
X = WHIR domain position variables
```

The prover commits to `W(Y, X)`. The verifier samples a random point `tau` for the oracle-index variables and reduces the multi-oracle object to a slice:

```text
W(tau, X)
```

Then WHIR checks the resulting slice.

### Relationship to tuple leaves

Tuple leaves:

```text
commit to all f_i(x) values at each x
batch locally with gamma powers
```

Partial evaluation:

```text
commit to W(Y, X)
use tau over index variables
prove that W(tau, X) is the correct partial evaluation
```

### When to test this

Do not start here.

Start this branch after the shared-query tuple-leaf path is working and benchmarked.

Trigger condition:

```text
oracle_count >= 8
or tuple-leaf proof payload starts scaling too aggressively
or verifier target for 8 oracles misses by > 25%
```

### Acceptance criteria

- Prototype supports powers-of-two oracle counts first.
- Soundness argument clearly separates index-axis batching from domain-axis WHIR proximity.
- Benchmarks compare against tuple-leaf batching at `t = 2, 4, 8, 16`.
- No changes to production path until it beats tuple leaves in at least one meaningful regime.

---

## 11. Milestone 6 — Parameter Sweep

### Goal

Find the true parameter knee for SYMBT3 multi-oracle WHIR.

### Sweep dimensions

Use explicit names:

```text
k_table ∈ {1, 2, 4, 8}
oracle_count ∈ {1, 2, 4, 8}
whir_folding_kappa ∈ {3, 4, 5, 6}
rate rho ∈ {1/2, 1/4, 1/8, 1/16}
security_mode ∈ {UD, CB}
```

If some modes are unavailable, mark them as unsupported rather than silently skipping.

### Metrics

```text
prove_ms
verify_ms
proof_bytes
public_bytes
num_roots
num_paths
num_queries
hash_count_estimate
field_ops_estimate
extension_field_ops_estimate
peak_alloc_bytes
```

### Output format

Emit both:

```text
CSV for plotting
JSON for structured diffing
Markdown summary for reports
```

### Acceptance criteria

- Identify default parameters for:
  - fastest demo,
  - best balanced development setting,
  - best proof-size setting,
  - best verifier setting,
  - best multi-oracle setting.
- Produce a short table of recommendations.

---

## 12. Milestone 7 — Fail-Closed Security and Replay Tests

### Goal

Make the multi-oracle accumulator robust against shape confusion, oracle replay, and transcript mistakes.

### Required negative tests

```text
reject wrong oracle count
reject wrong oracle ordering
reject same root under different shape
reject same oracle tuple under different role labels
reject dropped oracle
reject duplicated oracle
reject mutated constraint descriptor
reject reordered constraint descriptors
reject stale gamma from old transcript
reject stale query schedule
reject proof generated for k_table=a verified as k_table=b
reject proof generated under shape_id=a verified as shape_id=b
reject one-oracle-per-batch-item replay against fixed round profile
```

### Transcript binding tests

Ensure transcript absorbs:

```text
protocol version
shape id
oracle count
oracle role labels
field/domain/rate/folding parameters
constraint descriptors
root(s)
public statement digest
accumulator metadata digest
```

### Acceptance criteria

- All negative tests fail closed.
- Error messages distinguish malformed proof, shape mismatch, transcript mismatch, and semantic constraint failure.
- No test relies on debug-only behavior.

---

## 13. Milestone 8 — Documentation and Research Note

### Goal

Make the implementation understandable enough that another reviewer or LLM can audit it.

### Documents to update

```text
docs/whir.md
docs/symbt3_accumulator_authoritative_roadmap.md
docs/whir_public_performance_north_star_plan.md
benchmark output README / report
```

### Must explain

```text
single-oracle baseline
why k_table=4 is the default
multi-oracle tuple-leaf design
oracle batching vs constraint batching
transcript challenge order
shape binding
negative test suite
public byte layout
when Quasar-style partial evaluation becomes relevant
```

### Acceptance criteria

The docs should be sufficient for this prompt to be answered precisely:

> Read the SYMBT3 multi-oracle WHIR implementation and tell me whether it actually implements shared-query multi-oracle accumulation, or whether it secretly verifies independent WHIR proofs per oracle. Check transcript binding, shape binding, negative tests, and benchmark evidence.

---

## 14. Proposed Branch Sequence

Recommended branch order:

```text
1. bench/symbt3-accumulator-counters
2. whir/single-oracle-cleanup
3. whir/shared-query-tuple-leaves
4. whir/multi-constraint-accumulator
5. whir/public-byte-cleanup
6. whir/partial-eval-accumulator-experimental
7. bench/symbt3-multi-oracle-sweep
8. docs/symbt3-multi-oracle-roadmap
```

Do not merge the partial-evaluation branch into the production path until tuple leaves have been implemented and measured.

---

## 15. Success Criteria Summary

### Single-oracle path

Using current `k_table = 4` baseline:

```text
verify: 24.348 ms
prove:  25.078 ms
proof:  329,707 bytes
public: 18,715 bytes
```

Targets:

```text
no verifier regression
no proof-size regression
explain or fix k_table=2 prove anomaly
explain or fix k_table=8 prove/proof jump
public bytes reduced by ~2 KiB if possible
```

### Multi-oracle path

Initial targets:

| oracle count | verify target | proof target |
|---:|---:|---:|
| 2 | <= 30 ms | <= 1.25x single |
| 4 | <= 36 ms | <= 1.50x single |
| 8 | <= 45 ms | <= 2.00x single |

### Security/tests

```text
shape confusion rejected
oracle replay rejected
constraint replay rejected
transcript challenge order fixed
multi-oracle proof cannot be decomposed into independent unbound proofs
single-oracle compatibility preserved
```

---

## 16. Open Questions

1. Is `k_table` actually the accumulator arity, the number of folded instances, or another benchmark parameter? Rename it in reports.
2. Is WHIR alternate-domain verifier encoding already enabled in the SYMBT3 path?
3. Are public bytes constant because of fixed accumulator metadata, or because of duplicated fixed descriptors?
4. Does `k_table = 8` proof size increase due to more openings, more roots, or larger serialized oracle messages?
5. Can same-domain oracle tuple leaves be implemented without changing existing WHIR verifier internals too much?
6. Do we need separate oracle batching and constraint batching challenge domains?
7. At what oracle count does partial evaluation beat tuple leaves?
8. Does the CP-SNARK relation need new typed semantic descriptors for multi-oracle constraints?

---

## 17. References / Conceptual Anchors

This roadmap is based on the following conceptual anchors:

- **WHIR**: fast verification for constrained Reed--Solomon proximity testing, with low query complexity and batching of multiple constraints.
- **Symphony**: high-arity folding with a commit-and-prove compiler that avoids embedding Fiat--Shamir/random-oracle circuits inside the proven statement.
- **Quasar**: partial-evaluation style accumulation to reduce verifier-side work for multiple instances.
- **WARP / linear-time accumulation**: code-based accumulation and batching ideas that motivate keeping prover/verifier scaling under control.

---

## 18. Next Prompt to Feed Back In

Use this prompt to continue milestone-by-milestone:

```text
We have the SYMBT3 multi-oracle WHIR accumulator roadmap. Start with Milestone 0: benchmark hygiene and counters. Write the implementation plan in concrete Rust-level steps. Include the exact structs/counters to add, where to instrument prover and verifier code, what benchmark output format to emit, and what tests should fail/pass before moving to Milestone 1. Assume the current baseline is k_table=4 with verify=24.348ms, prove=25.078ms, proof=329707 bytes, public=18715 bytes.
```
