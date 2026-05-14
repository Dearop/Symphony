# WHIR Public Performance North Star Plan

## N1 Native Multi-Oracle WHIR Evaluation Layer

SYMBT3-N1 introduces a versioned native multi-oracle WHIR evaluation envelope.
It is infrastructure only and does not change the current product
`verify_public` route.

N1 uses Option A: one logical SYMBT3/native-oracle proof envelope containing
multiple ordered native oracle descriptors and roots. It does not use
SYMBT2F-style family subproofs, does not add `family_columnar_subproofs`, and
does not replace any existing explicit NonZK integrity route.

The new descriptor layer records:

- `oracle_id`;
- oracle role;
- layout digest;
- `num_vars`;
- root;
- opening schedule.

The descriptor digest binds the ordered descriptors:

```text
H("SYMBT3_NATIVE_ORACLE_DESCRIPTORS_V1", ordered descriptors)
```

Opening points bind the proof relation id, public statement digest, WHIR
parameter digest, descriptor/root digest, root policy, opening schedule, and
claim kind.
For equality checks, all compared oracles should use
`WhirNativeEvalClaimKind::EqualitySide` and
`TranscriptDerived { domain_separator }`; this gives the compared oracles the
same point while still binding that point to all ordered roots/layouts/IDs.
`PerOraclePoint` is for independent claims.

Current implementation note: whir-p3 exposes one polynomial commitment per PCS
payload. N1 therefore stores one internal PCS opening payload per native oracle
inside the single logical envelope. These are reported as
`native_oracle_pcs_opening_count`, not `family_columnar_subproof_count`.

Counters added by N1:

- `native_oracle_count`;
- `native_oracle_descriptor_bytes`;
- `native_oracle_eval_claim_count`;
- `native_oracle_opening_count`;
- `native_oracle_pcs_opening_count`;
- `native_oracle_transcript_squeezes`;
- `native_oracle_verify_ms` in the verification report.

N1 deliberately does not implement:

- product routing;
- K5/ZK;
- private manifest membership;
- native CP message semantics;
- `NativeMessageOracleRootsV1`.

## N1b Canonical Native-Oracle Root Hardening

SYMBT3-N1b replaces the default N1 root derivation with
`NativeOracleRootPolicy::CanonicalWhirRootV1`. The whir-p3 initial commitment is
available as a typed `MerkleCap<BabyBear, [BabyBear; 8]>`, so the descriptor root
digest is derived from stable cap roots and canonical BabyBear words rather than
Rust formatting.

`NativeOracleRootPolicy::DebugDevelopmentOnly` remains only as an explicit
development policy. Product, authority, native-manifest, and native-message
verification profiles reject it. The native-oracle opening transcript and
envelope metadata digest both bind the root policy, so proofs cannot be replayed
under a different policy.

N1b also adds stable canonical bytes/digests for native oracle specs,
descriptors, roles, opening schedules, eval requests, eval claims, and the
proof-envelope metadata. The internal WHIR PCS payload remains backend-native;
the hardened metadata layer is what N2/N4 will build on.

## N2 Native Manifest/Source Membership

SYMBT3-N2 implements the `NativeManifestOracleOpeningV1` development path using
the N1 native multi-oracle envelope. It opens a native manifest oracle and a
native source oracle at the same transcript-derived equality point and checks:

```text
ManifestOracle(zeta_manifest_source) = SourceOracle(zeta_manifest_source)
```

N2 is NonZK. It adds no masking, does not implement K5, does not replace K6a,
and does not change the product `verify_public` or v2 public verifier route.
`PublicCanonicalManifestViewV1` remains the existing K6a route.

The N2 public manifest binding is:

```text
batch_manifest_root = H(
    "SYMBT3_NATIVE_MANIFEST",
    manifest_layout_digest,
    manifest_oracle_root,
    native_oracle_root_policy_digest
)
```

The verifier recomputes this binding from the manifest descriptor root. The N2
challenge binds the proof relation id, public statement digest, WHIR parameter
digest, native descriptor/root digest, manifest/source layout digests,
`batch_manifest_root`, the canonical root policy digest, and the
`SYMBT3_N2_MANIFEST_SOURCE_EQUALITY` domain. The compared claims both use
`WhirNativeEvalClaimKind::EqualitySide`.

The N2 smoke counters are expected to remain:

- `top_level_whir_proof_count = 1`;
- `family_columnar_subproof_count = 0`;
- `native_oracle_count = 2`;
- `native_oracle_eval_claim_count = 2`;
- `native_oracle_opening_count = 2`;
- `native_oracle_pcs_opening_count = 2`.

N2 v1 rejects manifest/source `num_vars` mismatches rather than applying a
layout mapping. Committed/private manifest membership is deferred to N3, and
native CP message oracles are deferred to N4.

## N3 Committed-Private NonZK Manifest Membership

SYMBT3-N3 adds the committed-private manifest/source development path on top of
N2. The new visibility tag is
`Symbt3ManifestVisibility::CommittedPrivateNonZk`. It means committed through
native manifest/source oracle roots but not included as expanded values in the
public boundary. It does not mean hidden from the WHIR verifier; queried
coordinates can be revealed by NonZK openings.

The N3 public statement contains component metadata, roots, layout digests,
value counts, and public-boundary component values. It omits committed-private
component values, so the smoke counter is expected to report:

- `committed_private_component_count > 0`;
- `committed_private_public_bytes = 0`;
- compressed `public_statement_bytes`;
- `native_oracle_pcs_opening_count = 2`.

Policy gates are:

- `PublicCanonicalManifestViewV1` rejects `CommittedPrivateNonZk`;
- `NativeManifestOracleOpeningV1` plus `NativeSourceOracleOpeningV1` accepts it
  only under `NonZkIntegrityOnly` or explicit NonZK research status;
- ZK-required profiles reject until K5 masking exists;
- `DebugDevelopmentOnly` native roots remain rejected by native-manifest
  authority.

N3 keeps product routing unchanged. K6a remains the public canonical manifest
view route, N3 is not privacy-preserving, and native CP message oracles remain
deferred to N4.

## N4 Native CP Round-Message Oracles

SYMBT3-N4 makes CP round messages native WHIR oracles under
`Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1`. Each round message has
a typed `Symbt3NativeRoundMessageOracleLayoutV1`, role
`MessageRound { round }`, stable oracle id `1000 + round`, and a native
`MessageView` opening.

SYMBT3-N4b makes the batch axis native to each round oracle. A round oracle is
`M_i(T, U_i)`: `T` is the internal batch item axis, and `U_i` is the typed
message-coordinate axis for round `i`. The layout records
`batch_axis_log_size`, `message_axis_log_size`, and `total_num_vars`; increasing
batch size changes `total_num_vars`, not the number of native oracle
descriptors. Round message coordinate domains may differ, but the native-oracle
count must scale with CP round count, not batch size.

N4 adds compressed native-message public metadata:

- `message_oracle_roots_digest`;
- `message_round_layouts_digest`;
- `message_oracle_policy_digest`.

The native message roots are input-side transcript data. Round challenges are
derived from ordered prefix roots plus the folding protocol id, input public
boundary digest, batch manifest root, source roots digest, round layout digest,
active count, and batch size. Later roots do not affect earlier challenges, and
folded output does not affect round challenges. WHIR proof-checking challenges
remain separate from folding challenges.

The round-count smoke counters are expected to report:

- `native_message_round_count = round_count`;
- `native_oracle_count = round_count`;
- `native_oracle_eval_claim_count = round_count`;
- `native_oracle_pcs_opening_count = round_count`;
- `message_to_trace_binding_count = 0`;
- `family_columnar_subproof_count = 0`;
- `top_level_whir_proof_count = 1`.

The N4b batch-size smoke counter uses `k` as batch size and keeps
`native_oracle_count` and `native_oracle_pcs_opening_count` constant for a fixed
`round_count`.

N4 is NonZK and infrastructure-only. It does not change K6a/product routing,
does not prove byte transcript reconstruction, does not add
`message_trace_values` or byte-body reconstruction, and does not implement
K5 masking. It prepares the native message-oracle substrate for a later
`Symbt3NonZkFoldingIntegrityV1` route if that route is explicitly promoted.

## N5 NonZK Folding-Integrity Profile Gate

SYMBT3-N5 adds the native-oracle NonZK folding-integrity gate:
`Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1`. This is a strong metadata
profile, not product routing. The product `verify_public` path remains
unchanged, and K6a remains the explicit `PublicCanonicalManifestViewV1` route.

The gate accepts only the native N2/N3/N4b shape:

- `NativeManifestOracleOpeningV1`;
- `NativeSourceOracleOpeningV1`;
- `NativeRoundMessageOraclesV1`;
- `CanonicalWhirRootV1`;
- committed-private components only under `NonZkIntegrityOnly` or explicit
  NonZK research status;
- no `DebugDevelopmentOnly`;
- no public-canonical manifest policy;
- no row-byte/digest-only message root policy;
- one logical native-oracle envelope;
- `top_level_whir_proof_count = 1`;
- `family_columnar_subproof_count = 0`;
- manifest/source native oracle count `= 2`;
- native message oracle count `= round_count`, not batch size;
- no monolithic fallback.

The gate also requires folding-integrity semantics to be present: the N2
manifest evaluation claim, accumulator transition consistency, K1/K2/K3/K4
semantic families, and the production norm/range bundle. `ZkRequired` rejects
because K5 masking is not implemented.

The gate-only smoke benchmark is
`symbt3_native_folding_integrity_gate_vs_k`. It reports:

- `native_oracle_count_manifest_source`;
- `native_oracle_count_messages`;
- `native_message_round_count`;
- `native_message_oracle_count`;
- `native_message_oracle_count_is_round_count`;
- `family_columnar_subproof_count`;
- `gate_ok`.

N5 prepares for a future N6 versioned proof envelope and opt-in native route.
It does not implement K5, byte transcript reconstruction, default routing, or
product promotion.
