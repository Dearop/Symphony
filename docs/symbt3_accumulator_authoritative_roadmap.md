# SYMBT3 Accumulator Authoritative Roadmap

## N1 Native Multi-Oracle WHIR Evaluation Layer

N1 is an additive WHIR evaluation layer for future SYMBT3 accumulator work. It
does not promote a product route and does not make any native-oracle statement
authoritative.

The milestone adds:

- versioned native oracle descriptors;
- descriptor/root transcript binding;
- canonical WHIR root policy binding;
- multiple named oracle openings inside one logical native-oracle envelope;
- focused negative tests for descriptor, root, point, value, and replay
  tampering;
- separate native-oracle counters.

The current layer is intended to support later milestones:

- N2: `NativeManifestOracleOpeningV1` native manifest/source membership;
- N3: committed-private NonZK manifest membership;
- N4: `NativeRoundMessageOraclesV1`;
- N5: `Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1` gate;
- later: versioned native product route, if explicitly promoted.

For manifest/source equality, future code should use
`WhirNativeEvalClaimKind::EqualitySide` for both sides and
`TranscriptDerived { domain_separator }` so both oracles open at the same
descriptor-bound challenge point.

N1 does not implement K5/ZK, private manifest membership, or native CP message
semantics. It also does not change any existing NonZK integrity route.

SYMBT3-N1b makes `NativeOracleRootPolicy::CanonicalWhirRootV1` the default. The
WHIR initial commitment is serialized from typed `MerkleCap<BabyBear,
[BabyBear; 8]>` roots with canonical BabyBear words. The old Debug-derived root
path is quarantined behind `NativeOracleRootPolicy::DebugDevelopmentOnly` and is
rejected by product, authority, native-manifest, and native-message verification
profiles.

With N1b, native-oracle roots and envelope metadata are hardened enough for N2
infrastructure work on `NativeManifestOracleOpeningV1`. N1b does not promote
product routing on its own.

## N2 Native Manifest/Source Membership

N2 implements the native manifest/source membership development path using the
N1 native multi-oracle envelope. It proves the NonZK equality:

```text
ManifestOracle(zeta_manifest_source) = SourceOracle(zeta_manifest_source)
```

The manifest side is a native WHIR oracle with role `Manifest` and commitment
policy `NativeManifestOracleOpeningV1`. The source side is a native WHIR oracle
with role `Source` and source policy `NativeSourceOracleOpeningV1`. Both are
opened at the same transcript-derived equality point under
`WhirNativeEvalClaimKind::EqualitySide`.

N2 binds the public native manifest root as:

```text
batch_manifest_root = H(
    "SYMBT3_NATIVE_MANIFEST",
    manifest_layout_digest,
    manifest_oracle_root,
    native_oracle_root_policy_digest
)
```

The verifier recomputes this root from the manifest descriptor root and rejects
mismatches. The N2 equality challenge also binds the proof relation id, public
statement digest, WHIR parameter digest, ordered native descriptor/root digest,
manifest/source layout digests, `batch_manifest_root`, and the
`SYMBT3_N2_MANIFEST_SOURCE_EQUALITY` domain. It is a proof-checking challenge,
not beta.

N2 keeps the N1 envelope shape for the smoke path:

- `top_level_whir_proof_count = 1`;
- `family_columnar_subproof_count = 0`;
- `native_oracle_count = 2`;
- `native_oracle_pcs_opening_count = 2`.

N2 does not replace K6a. `PublicCanonicalManifestViewV1` remains the existing
K6a route, and product `verify_public`/v2 routing remains unchanged. N2 does not
implement K5/ZK, does not claim private-manifest product authority, and rejects
`DebugDevelopmentOnly` roots under the native-manifest authority profile. N2 v1
requires equal manifest/source `num_vars`; mismatches reject rather than
applying a committed/private layout mapping. Native CP message oracles remain
deferred to N4.

## N3 Committed-Private NonZK Manifest Membership

N3 permits committed-private manifest/source components in the native N2
membership path. The visibility tag is
`Symbt3ManifestVisibility::CommittedPrivateNonZk`. It means the expanded
component values are witness-side oracle evaluations and are not serialized into
the public boundary canonical bytes. The public statement binds roots, layout
digests, component kinds, component order, visibility tags, and value counts.

N3 still proves the same NonZK equality:

```text
ManifestOracle(zeta_manifest_source) = SourceOracle(zeta_manifest_source)
```

The smoke fixture contains both public-boundary and committed-private
components inside the same native manifest/source oracle layout. Public
components may serialize their values. Committed-private components serialize
only metadata and roots; `committed_private_public_bytes = 0`.

Policy and authority rules:

- `PublicCanonicalManifestViewV1` rejects committed-private components;
- `NativeManifestOracleOpeningV1` plus `NativeSourceOracleOpeningV1` accepts
  committed-private components only in `NonZkIntegrityOnly` or explicit NonZK
  research mode;
- ZK-required profiles reject because K5 masking is not implemented;
- `DebugDevelopmentOnly` roots remain rejected under native-manifest authority.

N3 is not private in the cryptographic privacy sense. WHIR openings may reveal
queried private coordinates. It does not change product `verify_public`/v2
routing and does not replace the K6a public canonical manifest route. K5 masking
and native CP message oracles remain deferred.

## N4 Native CP Round-Message Oracles

N4 adds native CP round-message oracles as the next infrastructure layer. The
policy is `Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1`. Each CP
round message `M_i(T, U_i)` is represented by a native WHIR oracle descriptor:

- oracle id `1000 + i`;
- role `MessageRound { round: i }`;
- typed `Symbt3NativeRoundMessageOracleLayoutV1`;
- `WhirNativeEvalClaimKind::MessageView`;
- opening schedule domain `SYMBT3_N4_ROUND_MESSAGE_VIEW`.

N4b clarifies the batch-axis-native shape. Each message oracle is `M_i(T,U_i)`,
with `T` as an internal batch item axis and `U_i` as the typed coordinate axis
for round `i`. `Symbt3NativeRoundMessageOracleLayoutV1` binds
`batch_axis_log_size`, `message_axis_log_size`, and `total_num_vars`; increasing
batch size increases the per-round oracle domain, not the number of native
oracle descriptors. For a fixed CP round profile, `native_oracle_count` and
`native_oracle_pcs_opening_count` must remain constant in batch size.

Message roots are ordered by round index and compressed into
`message_oracle_roots_digest`. Layout metadata is compressed into
`message_round_layouts_digest`, and the policy is bound by
`message_oracle_policy_digest`. Full message values are not serialized into a
new public boundary.

N4 defines prefix-derived folding challenges from input-side message roots:

```text
round_challenge_i = H(
    "SYMBT3_ROUND_CHALLENGE_V1",
    folding_protocol_id,
    input_public_boundary_digest,
    batch_manifest_root,
    source_roots_digest,
    native_message_oracle_roots[0..=i],
    round_index = i,
    round_layout_digest_i,
    active_count,
    batch_size
)
```

Changing root `j <= i` changes challenge `i`; changing a later root does not
affect earlier challenges. Folded output and WHIR PCS opening payloads are not
folding-challenge inputs. Native WHIR opening challenges remain proof-checking
challenges, separate from the folding transcript challenge schedule.

N4 is NonZK, not a product route, and does not replace K6a. It does not
reconstruct byte transcripts, does not add message-to-trace bindings, and does
not implement K5 masking. It prepares the native round-message substrate needed
for a future `Symbt3NonZkFoldingIntegrityV1` route if that route is promoted
explicitly.

## N5 Native NonZK Folding-Integrity Gate

N5 adds the profile gate for the native NonZK folding-integrity shape:
`Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1`. The gate is intentionally
metadata-only and does not promote product routing. K6a remains the existing
explicit public-canonical manifest route, and product `verify_public` remains
unchanged.

The N5 gate requires:

- `NativeManifestOracleOpeningV1`;
- `NativeSourceOracleOpeningV1`;
- `NativeRoundMessageOraclesV1`;
- `CanonicalWhirRootV1`;
- committed-private components only in NonZK integrity or explicit NonZK
  research mode;
- one logical native-oracle envelope;
- no `family_columnar_subproofs`;
- no monolithic fallback;
- manifest/source native oracle count `= 2`;
- native message oracle count `= round_count`, not batch size.

It rejects `PublicCanonicalManifestViewV1`, missing native policies,
`DebugDevelopmentOnly`, digest-only message roots, one-oracle-per-batch message
layouts, `ZkRequired` without K5, stale semantic profile versions, missing
accumulator transition consistency, missing K1/K2/K3/K4 semantic families,
missing production norm/range bundle, and any product-default route attempt.

N5 is NonZK only. It makes no privacy claim, adds no masking, and does not
reconstruct byte transcripts. A future N6 must add the versioned proof envelope
and explicit native route before this gate can be used as product authority.
