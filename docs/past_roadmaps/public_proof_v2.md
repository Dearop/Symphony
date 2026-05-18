# Symphony Public Proof v2

`ProofBundleV2` and `SymphonyProofV2` are the canonical public verifier
boundary for Symphony.

The product-facing API names are:

- `ModularProver::prove_public`
- `ModularVerifier::verify_public`
- `SymphonyProver::prove_public`
- `SymphonyVerifier::verify_public`

The older `prove_v2` / `verify_v2` names remain as compatibility aliases.

## API Boundary

| Category | APIs / Types | Intended use |
|---|---|---|
| Product public verifier | `prove_public`, `verify_public`, `ProofBundleV2`, `PublicProofBundle`, `SymphonyProofV2`, `PublicSymphonyProof`, `PublicProofEnvelope` | Canonical public-only boundary for downstream users and serialized public proofs |
| Compatibility verifier | `prove_v2`, `verify_v2`, legacy `prove`, legacy `verify`, `ProofBundle`, `SymphonyProof` | Backwards-compatible callers and full/private verification paths that may carry witness-side debug data |
| Debug/development support | raw typed CP context serializers, typed CP audit reports, WHIR payload codecs, explicit soundness helpers | Internal inspection, fixture generation, compatibility checks, and backend profiling |

Product public verification must use only the public proof fields below plus
caller-supplied public inputs and relation metadata. It must not access witness
bundles or fall back to legacy full verification.

The WHIR public verifier security review package is
`docs/whir_public_security_review.md`.

## Verifier Inputs

A public verifier receives:

- public R1CS inputs supplied out-of-band by the caller;
- relation metadata supplied out-of-band by the caller, currently the R1CS;
- public Fiat-Shamir commitments `fs_commitments`;
- public roots and digests:
  - `fs_root`;
  - `fold_root`;
  - `challenge_digest`;
  - `transcript_seed_digest`;
- the typed folded output instance;
- the CP backend proof;
- the output backend proof.

## Versioned Envelope

The canonical public proof wire envelope is versioned independently of backend
proof internals. Version 1 is defined by
`PUBLIC_PROOF_ENVELOPE_VERSION = 1` and starts with the fixed magic bytes:

```text
53 59 4d 50 55 42 32 00    # "SYMPUB2\0"
```

The envelope serializes fields in this exact order, using little-endian integers
and length-delimited byte arrays:

```text
magic[8]
version: u16
digest_scheme: u8             # 0 = Sha256, 1 = Poseidon2BabyBear
num_public_input_vectors: u64
  repeated:
    public_input_len: u64
    public_input_values: i64[public_input_len]
r1cs_num_constraints: u64
r1cs_num_variables: u64
r1cs_num_public: u64
fs_commitment_count: u64
  repeated:
    fs_commitment_len: u64
    fs_commitment_bytes
fs_root: bytes[32]
fold_root: bytes[32]
challenge_digest: bytes[32]
transcript_seed_digest: bytes[32]
folded_output_len: u64
folded_output_bytes
cp_proof_len: u64
cp_proof_bytes
output_proof_len: u64
output_proof_bytes
```

The backend proof payloads are opaque to this envelope: WHIR owns the canonical
serialization of WHIR CP and output proofs, while the public envelope owns their
ordering, versioning, and length delimiting. Decoders must reject unknown
versions, unknown digest schemes, truncated fields, integer-length overflows,
and trailing bytes.

WHIR proof payloads are also versioned. Version 2 starts with the fixed magic
bytes `SYMWHPF\0`, followed by the WHIR payload version, proof kind, sumcheck
rounds, public BabyBear evaluations, linear-check proof data, private opening
evaluations, optional development-only SYMBT2F family subproof payloads, and a
length-delimited upstream WHIR PCS proof serialization. These bytes are produced
by `canonical_whir_proof_bytes`, decoded by
`whir_proof_from_canonical_bytes`, and are the canonical payloads to place in
the public envelope's `cp_proof_bytes` and `output_proof_bytes` fields for
WHIR.

The golden version-2 WHIR public envelope fixture is:

```text
tests/fixtures/public_proof_v2_whir_minimal.hex
```

It is a deterministic wire-format fixture with canonical WHIR CP/output payloads.
Live WHIR public proofs are tested separately because public proving includes
randomized Fiat-Shamir openings.

## Explicit Non-Inputs

The public proof must not contain or require:

- Fiat-Shamir openings;
- Fiat-Shamir committed messages;
- fold inputs;
- folding proofs;
- original witnesses;
- folded witnesses;
- CP witness bundles;
- any witness-side debug data.

If verification needs one of these objects, it is not the public verifier path.

## Backend-Independent Checks

Every public verifier can recompute:

- `transcript_seed_digest` from public inputs and relation dimensions;
- `fs_root` from `fs_commitments`.

The helper methods `public_boundary_is_well_formed` perform only these public
checks under the legacy SHA-256 scheme. `verify_public` uses the CP backend's
selected public digest scheme instead, so the WHIR typed-CP path can move these
public-boundary bindings to Poseidon2/BabyBear without changing the proof
bundle shape.

Public digest schemes currently are:

- `Sha256`: default and compatibility scheme for the existing full verifier and
  non-authoritative typed CP paths.
- `Poseidon2BabyBear`: authoritative WHIR public scheme. Digests are serialized
  as 32 bytes: eight canonical BabyBear field elements, each little-endian
  `u32`.

Typed CP backends receive a `CpPublicStatement`, not only the compact
`CpPublicInstance`. This expanded public statement includes public inputs,
R1CS dimensions, the folded output, compact digests, and the digest scheme. This
lets WHIR use field-native public bindings without proving SHA-256 transcript
parsing.

For the Poseidon2/BabyBear scheme, Fiat-Shamir message commitments are:

```text
commit = Poseidon2BabyBear("fs-commit" || len(message) || message || opening)
```

where `opening` is 32 bytes and the digest output uses the same eight-limb
BabyBear serialization.

## Backend Authority

`verify_public` must fail closed unless:

- the CP backend advertises `has_authoritative_typed_cp()`;
- the output backend advertises `has_authoritative_typed_output()`;
- the corresponding typed backend verification calls return `Some(true)`.

Authority flags are security claims, not feature hints. A backend may expose
typed helper methods without being authoritative. Public verification must not
fall back to non-authoritative typed hooks or witness-side checks.

Typed CP setup is also authority-gated. When a backend advertises
`has_authoritative_typed_cp()`, the prover/verifier route through the backend's
typed CP relation description and cache keys for that concrete relation. If the
backend cannot provide that relation, public verification fails closed. When the
authority flag is false, orchestrators use the legacy CP proof path even if
typed CP helper hooks exist.

Raw typed CP context serializers remain compatibility/development helpers.
Authoritative product routing should use typed CP relation descriptions because
they include the concrete public, witness, and constraint dimensions.

## Current WHIR Status

WHIR typed CP is authoritative. WHIR public proofs use
`Poseidon2BabyBear` digests, and `verify_public` succeeds for WHIR+WHIR using
only public inputs, public FS commitments, public roots/digests, folded output,
CP proof, and output proof.

The CP backend owns the semantic claim that the typed folded output was derived
correctly from the original statements. The WHIR output proof transcript-binds
the public `FoldedOutputInstance`; typed CP enforces FS commitment openings,
fold/challenge digest binding, beta binding, folded output consistency,
original Ajtai openings, and original R1CS witness algebra.

The headline benchmark is:

```text
cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
```

By default this benchmark runs the conservative `k=1` public verifier point.
Use `SYMPHONY_WHIR_PUBLIC_VERIFY_KS` to request a curve over multiple fold
counts:

```text
SYMPHONY_WHIR_PUBLIC_VERIFY_KS=1,2 cargo bench --bench whir_scaling --features whir -- "public_verify_v2_vs_k"
```

## Performance Roadmap Envelope

The current product envelope is version 1 and includes the public
`fs_commitments` vector. The performance roadmap introduces a version 2
compressed envelope that omits that linear vector and keeps only `fs_root`,
`fold_root`, `challenge_digest`, `transcript_seed_digest`, folded output bytes,
and backend proof bytes.

Version 2 is currently a measured wire-shape target, not the active product
verifier route. `verify_public` still consumes `ProofBundleV2` until the typed
CP relation moves FS commitment digest outputs from public instance slots into
private witness data.
