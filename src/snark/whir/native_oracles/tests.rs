use super::*;
use crate::batched_cp::{
    symbt3_accumulator_coordinates_digest, symbt3_accumulator_transition_coordinates,
    BatchedCpBucket, BatchedCpItem, BatchedCpSymbt3RelationDescription,
    BatchedCpSymbt3SetupDescriptor,
};
use crate::commitment::Commitment;
use crate::cp_relation_core::CpPublicStatement;
use crate::digest_core::PublicDigestScheme;
use crate::params::{SymphonyParams, D};
use crate::proof_orchestrator::{ProofBundle, Prover};
use crate::r1cs::R1CSMatrices;
use crate::ring::{RingElement, RingVector};
use crate::snark::whir::WhirSnark;
use crate::snark::{BackendSnark, RelationDescription};
use crate::SumcheckSnark;
use p3_field::PrimeCharacteristicRing;

fn digest(label: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.finalize().into()
}

fn relation() -> RelationDescription {
    RelationDescription {
        num_instance_vars: 1,
        num_witness_vars: 1,
        num_constraints: 1,
        context: None,
    }
}

fn native_oracle_fixture() -> (
    WhirProvingKey,
    WhirVerifyingKey,
    Digest32,
    Digest32,
    Digest32,
    Vec<WhirNativeOracleSpec>,
    Vec<Vec<BabyBear>>,
    Vec<WhirNativeEvalRequest>,
    WhirNativeMultiOracleProof,
) {
    native_oracle_fixture_with_source(None)
}

fn native_oracle_fixture_with_source(
    source_override: Option<Vec<BabyBear>>,
) -> (
    WhirProvingKey,
    WhirVerifyingKey,
    Digest32,
    Digest32,
    Digest32,
    Vec<WhirNativeOracleSpec>,
    Vec<Vec<BabyBear>>,
    Vec<WhirNativeEvalRequest>,
    WhirNativeMultiOracleProof,
) {
    let (pk, vk) = WhirSnark::setup(&relation());
    let proof_relation_id = digest(b"n1-proof-relation");
    let public_statement_digest = digest(b"n1-public-statement");
    let whir_param_digest = digest(b"n1-whir-params");
    let specs = vec![
        WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: 1,
            role: WhirNativeOracleRole::Manifest,
            layout_digest: digest(b"manifest-layout"),
            num_vars: 2,
            opening_schedule: WhirNativeOpeningSchedule::TranscriptDerived {
                domain_separator: "N1_MANIFEST_SOURCE_EQUALITY",
            },
        },
        WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: 2,
            role: WhirNativeOracleRole::Source,
            layout_digest: digest(b"source-layout"),
            num_vars: 2,
            opening_schedule: WhirNativeOpeningSchedule::TranscriptDerived {
                domain_separator: "N1_MANIFEST_SOURCE_EQUALITY",
            },
        },
    ];
    let manifest = vec![
        BabyBear::from_u32(3),
        BabyBear::from_u32(5),
        BabyBear::from_u32(8),
        BabyBear::from_u32(13),
    ];
    let source = source_override.unwrap_or_else(|| manifest.clone());
    let requests = vec![
        WhirNativeEvalRequest {
            oracle_id: 1,
            claim_kind: WhirNativeEvalClaimKind::EqualitySide,
        },
        WhirNativeEvalRequest {
            oracle_id: 2,
            claim_kind: WhirNativeEvalClaimKind::EqualitySide,
        },
    ];
    let proof = whir_commit_and_prove_oracles(
        &pk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &specs,
        &[manifest.clone(), source.clone()],
        &requests,
    )
    .expect("native oracle proof");
    (
        pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        specs,
        vec![manifest, source],
        requests,
        proof,
    )
}

fn verify_fixture(
    vk: &WhirVerifyingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    proof: &WhirNativeMultiOracleProof,
) -> bool {
    whir_verify_oracle_openings(
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &proof.descriptors,
        proof,
        &proof.eval_claims,
    )
}

fn refresh_envelope_digest(proof: &mut WhirNativeMultiOracleProof) {
    proof.native_multi_oracle_envelope_digest = native_multi_oracle_envelope_digest(proof);
}

struct N2Fixture {
    pk: WhirProvingKey,
    vk: WhirVerifyingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    manifest_layout_digest: Digest32,
    source_layout_digest: Digest32,
    manifest_evals: Vec<BabyBear>,
    proof: NativeManifestSourceMembershipProof,
}

fn n2_fixture() -> N2Fixture {
    n2_fixture_with_source_and_policy(None, NativeOracleRootPolicy::CanonicalWhirRootV1, true)
}

fn n2_fixture_with_source_and_policy(
    source_override: Option<Vec<BabyBear>>,
    root_policy: NativeOracleRootPolicy,
    require_equal: bool,
) -> N2Fixture {
    let (pk, vk) = WhirSnark::setup(&relation());
    let proof_relation_id = digest(b"n2-proof-relation");
    let public_statement_digest = digest(b"n2-public-statement");
    let whir_param_digest = digest(b"n2-whir-params");
    let manifest_layout_digest = digest(b"n2-manifest-layout");
    let source_layout_digest = digest(b"n2-source-layout");
    let manifest_evals = vec![
        BabyBear::from_u32(3),
        BabyBear::from_u32(5),
        BabyBear::from_u32(8),
        BabyBear::from_u32(13),
    ];
    let source_evals = source_override.unwrap_or_else(|| manifest_evals.clone());
    let manifest_num_vars = num_vars_for_evals(&manifest_evals).expect("manifest num vars");
    let source_num_vars = num_vars_for_evals(&source_evals).expect("source num vars");

    let proof = if require_equal && root_policy == NativeOracleRootPolicy::CanonicalWhirRootV1 {
        prove_native_manifest_source_membership(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            manifest_layout_digest,
            source_layout_digest,
            &manifest_evals,
            &source_evals,
        )
        .expect("N2 native manifest/source membership proof")
    } else {
        let manifest_root =
            whir_initial_root_digest(&pk.seed, root_policy, manifest_num_vars, &manifest_evals)
                .expect("manifest root");
        let batch_manifest_root = native_batch_manifest_root(
            manifest_layout_digest,
            manifest_root,
            native_oracle_root_policy_digest(root_policy),
        );
        let specs = build_n2_native_manifest_source_oracle_specs(
            manifest_layout_digest,
            source_layout_digest,
            manifest_num_vars,
            source_num_vars,
            batch_manifest_root,
            root_policy,
        )
        .expect("N2 specs");
        let requests = native_manifest_source_membership_eval_requests();
        let native_proof = whir_commit_and_prove_oracles_with_root_policy(
            &pk,
            root_policy,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &specs,
            &[manifest_evals.clone(), source_evals.clone()],
            &requests,
        )
        .expect("N2 native oracle proof");
        NativeManifestSourceMembershipProof {
            batch_manifest_root,
            native_proof,
        }
    };

    N2Fixture {
        pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        manifest_layout_digest,
        source_layout_digest,
        manifest_evals,
        proof,
    }
}

fn verify_n2_fixture(
    fixture: &N2Fixture,
    proof: &NativeManifestSourceMembershipProof,
) -> WhirNativeOracleVerifyReport {
    verify_n2_fixture_with_batch(fixture, proof.batch_manifest_root, &proof.native_proof)
}

fn verify_n2_fixture_with_batch(
    fixture: &N2Fixture,
    batch_manifest_root: Digest32,
    proof: &WhirNativeMultiOracleProof,
) -> WhirNativeOracleVerifyReport {
    verify_native_manifest_source_membership(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        fixture.manifest_layout_digest,
        fixture.source_layout_digest,
        batch_manifest_root,
        ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
        SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &proof.descriptors,
        proof,
    )
}

struct N3Fixture {
    pk: WhirProvingKey,
    vk: WhirVerifyingKey,
    proof_relation_id: Digest32,
    whir_param_digest: Digest32,
    components: Vec<Symbt3ManifestSourceComponentValues>,
    proof: Symbt3CommittedPrivateManifestMembershipProof,
}

fn n3_components() -> Vec<Symbt3ManifestSourceComponentValues> {
    vec![
        Symbt3ManifestSourceComponentValues {
            component_id: 1,
            kind: Symbt3ManifestComponentKind::PublicBoundary,
            visibility: Symbt3ManifestVisibility::PublicBoundary,
            layout_digest: digest(b"n3-public-component-layout"),
            manifest_values: vec![BabyBear::from_u32(17), BabyBear::from_u32(19)],
            source_values: vec![BabyBear::from_u32(17), BabyBear::from_u32(19)],
        },
        Symbt3ManifestSourceComponentValues {
            component_id: 2,
            kind: Symbt3ManifestComponentKind::CommittedPrivateWitness,
            visibility: Symbt3ManifestVisibility::CommittedPrivateNonZk,
            layout_digest: digest(b"n3-committed-private-component-layout"),
            manifest_values: vec![BabyBear::from_u32(1_234_567), BabyBear::from_u32(7_654_321)],
            source_values: vec![BabyBear::from_u32(1_234_567), BabyBear::from_u32(7_654_321)],
        },
    ]
}

fn n3_fixture() -> N3Fixture {
    n3_fixture_with_components(n3_components(), Symbt3ZkStatus::NonZkIntegrityOnly)
}

fn n3_fixture_with_components(
    components: Vec<Symbt3ManifestSourceComponentValues>,
    zk_status: Symbt3ZkStatus,
) -> N3Fixture {
    let (pk, vk) = WhirSnark::setup(&relation());
    let proof_relation_id = digest(b"n3-proof-relation");
    let whir_param_digest = digest(b"n3-whir-params");
    let proof = prove_committed_private_manifest_membership(
        &pk,
        proof_relation_id,
        whir_param_digest,
        zk_status,
        &components,
    )
    .expect("N3 committed-private manifest membership proof");
    N3Fixture {
        pk,
        vk,
        proof_relation_id,
        whir_param_digest,
        components,
        proof,
    }
}

fn verify_n3_fixture(
    fixture: &N3Fixture,
    proof: &Symbt3CommittedPrivateManifestMembershipProof,
) -> Symbt3CommittedPrivateManifestVerifyReport {
    verify_committed_private_manifest_membership(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.whir_param_digest,
        proof,
    )
}

fn flatten_n3_components(
    components: &[Symbt3ManifestSourceComponentValues],
) -> (Vec<BabyBear>, Vec<BabyBear>) {
    let mut manifest_evals = Vec::new();
    let mut source_evals = Vec::new();
    for component in components {
        manifest_evals.extend_from_slice(&component.manifest_values);
        source_evals.extend_from_slice(&component.source_values);
    }
    (manifest_evals, source_evals)
}

fn low_level_n3_membership_proof_with_statement(
    pk: &WhirProvingKey,
    proof_relation_id: Digest32,
    whir_param_digest: Digest32,
    public_statement: &Symbt3CommittedPrivateManifestPublicStatement,
    manifest_evals: &[BabyBear],
    source_evals: &[BabyBear],
) -> NativeManifestSourceMembershipProof {
    let manifest_num_vars = num_vars_for_evals(manifest_evals).expect("manifest num vars");
    let source_num_vars = num_vars_for_evals(source_evals).expect("source num vars");
    let specs = build_n2_native_manifest_source_oracle_specs(
        public_statement.manifest_layout_digest,
        public_statement.source_layout_digest,
        manifest_num_vars,
        source_num_vars,
        public_statement.batch_manifest_root,
        public_statement.root_policy,
    )
    .expect("N3 native specs");
    let native_proof = whir_commit_and_prove_oracles_with_root_policy(
        pk,
        public_statement.root_policy,
        proof_relation_id,
        public_statement.digest(),
        whir_param_digest,
        &specs,
        &[manifest_evals.to_vec(), source_evals.to_vec()],
        &native_manifest_source_membership_eval_requests(),
    )
    .expect("N3 low-level native proof");
    NativeManifestSourceMembershipProof {
        batch_manifest_root: public_statement.batch_manifest_root,
        native_proof,
    }
}

struct N4Fixture {
    pk: WhirProvingKey,
    vk: WhirVerifyingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    challenge_context: Symbt3NativeRoundChallengeContext,
    batch_log_size: usize,
    round_layouts: Vec<Symbt3NativeRoundMessageOracleLayoutV1>,
    message_evals: Vec<Vec<BabyBear>>,
    proof: Symbt3NativeRoundMessageOracleProof,
}

fn n4_batch_size(batch_log_size: usize) -> u64 {
    1u64 << batch_log_size
}

fn n4_context(
    folded_output_digest: Digest32,
    batch_log_size: usize,
) -> Symbt3NativeRoundChallengeContext {
    Symbt3NativeRoundChallengeContext {
        folding_protocol_id: digest(b"n4-folding-protocol"),
        input_public_boundary_digest: digest(b"n4-input-public-boundary"),
        batch_manifest_root: digest(b"n4-batch-manifest-root"),
        source_roots_digest: digest(b"n4-source-roots"),
        active_count: 7,
        batch_size: n4_batch_size(batch_log_size),
        folded_output_digest,
    }
}

fn n4_layouts(
    round_count: usize,
    batch_log_size: usize,
) -> Vec<Symbt3NativeRoundMessageOracleLayoutV1> {
    (0..round_count)
        .map(|round| {
            let message_axis_log_size = if round % 2 == 0 { 1 } else { 2 };
            Symbt3NativeRoundMessageOracleLayoutV1 {
                round_index: round as u32,
                oracle_id: SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + round as u32,
                batch_axis_log_size: batch_log_size,
                message_axis_log_size,
                total_num_vars: batch_log_size + message_axis_log_size,
                layout_digest: digest(format!("n4-round-layout-{round}").as_bytes()),
                section_layout_digest: digest(format!("n4-section-layout-{round}").as_bytes()),
                view_map_digest: digest(format!("n4-view-map-{round}").as_bytes()),
            }
        })
        .collect()
}

fn n4_message_evals(
    round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
) -> Vec<Vec<BabyBear>> {
    round_layouts
        .iter()
        .map(|layout| {
            let len = 1usize << layout.total_num_vars;
            (0..len)
                .map(|i| {
                    BabyBear::from_u32(
                        ((layout.round_index as usize * 37 + i * 13 + 5) % 251) as u32,
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn n4_fixture(round_count: usize) -> N4Fixture {
    n4_fixture_with_batch_log_size(round_count, 1)
}

fn n4_fixture_with_batch_log_size(round_count: usize, batch_log_size: usize) -> N4Fixture {
    let (pk, vk) = WhirSnark::setup(&relation());
    let proof_relation_id = digest(b"n4-proof-relation");
    let public_statement_digest = digest(b"n4-public-statement");
    let whir_param_digest = digest(b"n4-whir-params");
    let challenge_context = n4_context(digest(b"n4-folded-output"), batch_log_size);
    let round_layouts = n4_layouts(round_count, batch_log_size);
    let message_evals = n4_message_evals(&round_layouts);
    let proof = prove_native_round_message_oracle_views(
        &pk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &challenge_context,
        batch_log_size,
        &round_layouts,
        &message_evals,
        &native_round_message_view_eval_requests(&round_layouts),
    )
    .expect("N4 native round-message proof");
    N4Fixture {
        pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        challenge_context,
        batch_log_size,
        round_layouts,
        message_evals,
        proof,
    }
}

fn verify_n4_fixture(
    fixture: &N4Fixture,
    proof: &Symbt3NativeRoundMessageOracleProof,
) -> Symbt3NativeRoundMessageOracleVerifyReport {
    verify_native_round_message_oracle_views(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &fixture.round_layouts,
        proof.message_oracle_roots_digest,
        proof.message_round_layouts_digest,
        proof.message_oracle_policy_digest,
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        proof,
    )
}

fn low_level_n4_proof_with_root_policy(
    pk: &WhirProvingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    challenge_context: &Symbt3NativeRoundChallengeContext,
    batch_log_size: usize,
    round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
    message_evals: &[Vec<BabyBear>],
    root_policy: NativeOracleRootPolicy,
) -> Symbt3NativeRoundMessageOracleProof {
    let specs = build_native_message_oracle_specs(round_layouts, batch_log_size).expect("N4 specs");
    let native_proof = whir_commit_and_prove_oracles_with_root_policy(
        pk,
        root_policy,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &specs,
        message_evals,
        &native_round_message_view_eval_requests(round_layouts),
    )
    .expect("N4 low-level native proof");
    let message_oracle_policy = Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1;
    let round_challenges =
        derive_native_round_challenges(&native_proof.descriptors, round_layouts, challenge_context)
            .expect("round challenges");
    Symbt3NativeRoundMessageOracleProof {
        message_oracle_policy,
        message_oracle_roots_digest: native_message_roots_digest(&native_proof.descriptors),
        message_round_layouts_digest: native_message_round_layouts_digest(round_layouts),
        message_oracle_policy_digest: symbt3_message_oracle_policy_digest(message_oracle_policy),
        round_challenges,
        native_proof,
    }
}

fn n4_round_challenge_for(fixture: &N4Fixture, roots: &[Digest32], round: usize) -> BabyBear {
    derive_native_round_challenge(
        fixture.round_layouts[round].round_index,
        &roots[..=round],
        fixture.round_layouts[round].layout_digest,
        &fixture.challenge_context,
    )
}

fn n5_valid_metadata() -> Symbt3NonZkFoldingIntegrityProfileMetadata {
    let n3 = n3_fixture();
    let n3_report = verify_n3_fixture(&n3, &n3.proof);
    assert!(n3_report.ok);

    let n4 = n4_fixture_with_batch_log_size(2, 2);
    let n4_report = verify_n4_fixture(&n4, &n4.proof);
    assert!(n4_report.ok);

    Symbt3NonZkFoldingIntegrityProfileMetadata {
        native_profile: Some(Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1),
        manifest_policy: Some(n3.proof.public_statement.manifest_policy),
        source_policy: Some(n3.proof.public_statement.source_policy),
        message_oracle_policy: Some(n4.proof.message_oracle_policy),
        root_policy: NativeOracleRootPolicy::CanonicalWhirRootV1,
        zk_status: n3.proof.public_statement.zk_status,
        committed_private_component_count: n3_report.committed_private_component_count,
        manifest_source_native_oracle_count: n3_report.native_report.counters.native_oracle_count,
        manifest_source_native_pcs_opening_count: n3_report
            .native_report
            .counters
            .native_oracle_pcs_opening_count,
        native_message_round_count: n4_report.native_message_round_count,
        native_message_oracle_count: n4_report.native_report.counters.native_oracle_count,
        native_message_pcs_opening_count: n4_report
            .native_report
            .counters
            .native_oracle_pcs_opening_count,
        batch_size: n4.challenge_context.batch_size as usize,
        batch_axis_log_size: n4.batch_log_size,
        message_round_layouts: n4.round_layouts,
        logical_native_envelope_count: 1,
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: 0,
        message_to_trace_binding_count: n4_report.message_to_trace_binding_count,
        semantic_profile_version: SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION,
        required_semantic_families: Symbt3FoldingIntegritySemanticFamilies::production_non_zk(),
        k5_masking_available: false,
        monolithic_fallback: false,
        product_default_route_attempted: false,
        product_eligible: false,
        native_product_route_version_exists: false,
    }
}

fn n5_report(
    metadata: &Symbt3NonZkFoldingIntegrityProfileMetadata,
) -> Symbt3NonZkFoldingIntegrityProfileReport {
    symbt3_non_zk_folding_integrity_profile_report(metadata)
}

struct N6aFixture {
    vk: WhirVerifyingKey,
    instance: Symbt3NativeFoldingIntegrityInstance,
    proof: Symbt3NativeFoldingIntegrityProof,
}

struct N6bFixture {
    vk: WhirVerifyingKey,
    public_profile: Symbt3NativeFoldingIntegrityPublicProfile,
    instance: Symbt3NativeFoldingIntegrityInstance,
    proof: Symbt3NativeFoldingIntegrityProof,
}

fn n6a_instance_witness(
    batch_log_size: usize,
    round_count: usize,
) -> (
    Symbt3NativeFoldingIntegrityInstance,
    Symbt3NativeFoldingIntegrityWitness,
) {
    let components = n3_components();
    let prepared =
        prepare_committed_private_manifest_witness(&components).expect("N6a manifest witness");
    let round_layouts = n4_layouts(round_count, batch_log_size);
    let witness = Symbt3NativeFoldingIntegrityWitness {
        main_witness: vec![11, 13, 17, 19, batch_log_size as u8, round_count as u8],
        manifest_evals: prepared.manifest_evals,
        source_evals: prepared.source_evals,
        message_oracle_evaluations: n4_message_evals(&round_layouts),
    };
    let batch_size = 1u64 << batch_log_size;
    let instance = Symbt3NativeFoldingIntegrityInstance {
        native_profile: Some(Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1),
        manifest_policy: ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
        source_policy: SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
        message_oracle_policy: Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        root_policy: NativeOracleRootPolicy::CanonicalWhirRootV1,
        zk_status: Symbt3ZkStatus::NonZkIntegrityOnly,
        symbt3_relation_id: digest(b"n6a-symbt3-relation"),
        whir_param_digest: digest(b"n6a-whir-params"),
        manifest_layout_digest: prepared.manifest_layout_digest,
        source_layout_digest: prepared.source_layout_digest,
        source_column_layout_digest: digest(b"n6a-source-column-layout"),
        folding_protocol_id: digest(b"n6a-folding-protocol"),
        input_public_boundary_digest: digest(b"n6a-input-public-boundary"),
        source_roots_digest: digest(b"n6a-source-roots"),
        active_count: batch_size,
        batch_size,
        folded_output_digest: digest(b"n6a-folded-output"),
        batch_axis_log_size: batch_log_size,
        round_layouts,
        committed_private_component_count: prepared.committed_private_component_count,
        semantic_profile_version: SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION,
        required_semantic_families: Symbt3FoldingIntegritySemanticFamilies::production_non_zk(),
        k5_masking_available: false,
        monolithic_fallback: false,
        product_default_route_attempted: false,
        product_eligible: false,
        native_product_route_version_exists: false,
        backend_table_count: 1,
        accumulator_transition_claims: 1,
        main_instance: vec![3, 5, 7, 9, batch_log_size as u8, round_count as u8],
    };
    (instance, witness)
}

fn n6a_fixture(batch_log_size: usize, round_count: usize) -> N6aFixture {
    let (pk, vk) = WhirSnark::setup(&relation());
    let (instance, witness) = n6a_instance_witness(batch_log_size, round_count);
    let proof = prove_symbt3_native_folding_integrity_non_zk(&pk, &instance, &witness)
        .expect("N6a native folding-integrity proof");
    N6aFixture {
        vk,
        instance,
        proof,
    }
}

fn verify_n6a_fixture(
    fixture: &N6aFixture,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeFoldingIntegrityProof,
) -> bool {
    verify_symbt3_native_folding_integrity_non_zk(&fixture.vk, instance, proof)
}

fn n6b_public_profile() -> Symbt3NativeFoldingIntegrityPublicProfile {
    Symbt3NativeFoldingIntegrityPublicProfile::explicit_non_zk()
}

fn n6b_fixture(batch_log_size: usize, round_count: usize) -> N6bFixture {
    let (pk, vk) = WhirSnark::setup(&relation());
    let (instance, witness) = n6a_instance_witness(batch_log_size, round_count);
    let public_profile = n6b_public_profile();
    let proof = prove_public_symbt3_native_folding_integrity_non_zk(
        &pk,
        &public_profile,
        &instance,
        &witness,
    )
    .expect("N6b public native folding-integrity proof");
    N6bFixture {
        vk,
        public_profile,
        instance,
        proof,
    }
}

fn verify_n6b_fixture(
    fixture: &N6bFixture,
    public_profile: &Symbt3NativeFoldingIntegrityPublicProfile,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeFoldingIntegrityProof,
) -> bool {
    verify_public_symbt3_native_folding_integrity_non_zk(
        &fixture.vk,
        public_profile,
        instance,
        proof,
    )
}

struct N7Fixture {
    vk: WhirVerifyingKey,
    instance: Symbt3NativeFoldingIntegrityInstance,
    proof: Symbt3NativeAccumulatorAuthorityProof,
}

struct K6aAdapterFixture {
    pk: WhirProvingKey,
    vk: WhirVerifyingKey,
    profile: Symbt3AuthorityProfile,
    accumulator_instance: Symbt3AccumulatorInstance,
    accumulator_witness: Symbt3AccumulatorWitness,
    proof: WhirProof,
    adapter: Symbt3NativeAccumulatorK6aWorkloadAdapter,
}

fn k6a_params() -> SymphonyParams {
    SymphonyParams {
        q: 257,
        d: D,
        kappa: 1,
        ell_np: 2,
        ell_h: D,
        lambda_pj: 4,
        n_bar: 4,
        m: 4,
        b: 16,
        k_cs: 1,
        n_in: 1,
        ntt: SymphonyParams::try_ntt(257, D),
    }
}

fn k6a_r1cs() -> (R1CSMatrices, Vec<i64>) {
    let mut r1cs = R1CSMatrices::new(4, 4, 1);
    r1cs.a.insert(0, 1, 1);
    r1cs.b.insert(0, 2, 1);
    r1cs.c.insert(0, 3, 1);
    r1cs.a.insert(1, 1, 1);
    r1cs.b.insert(1, 0, 1);
    r1cs.c.insert(1, 1, 1);
    (r1cs, vec![1, 3, 5, 15])
}

fn k6a_statement(
    prover: &Prover<SumcheckSnark, SumcheckSnark>,
    z: &[i64],
    n_in: usize,
) -> (Commitment, Vec<i64>, RingVector) {
    let full_ring = RingVector {
        elements: z
            .iter()
            .map(|&value| RingElement::from_constant(value))
            .collect(),
    };
    let (commitment, _) = prover.commit_witness(&full_ring);
    let witness_part = RingVector {
        elements: z[n_in..]
            .iter()
            .map(|&value| RingElement::from_constant(value))
            .collect(),
    };
    (commitment, z[..n_in].to_vec(), witness_part)
}

fn k6a_batched_item(
    prover: &Prover<SumcheckSnark, SumcheckSnark>,
    r1cs: &R1CSMatrices,
    z: &[i64],
    tag: u8,
) -> BatchedCpItem {
    let statements = vec![
        k6a_statement(prover, z, r1cs.num_public),
        k6a_statement(prover, z, r1cs.num_public),
    ];
    let public_inputs = statements
        .iter()
        .map(|(_, public_input, _)| public_input.clone())
        .collect::<Vec<_>>();
    let proof: ProofBundle<SumcheckSnark, SumcheckSnark> = prover.prove(&statements, r1cs);
    let public = CpPublicStatement::new(
        proof.cp_public_instance.clone(),
        public_inputs,
        r1cs,
        PublicDigestScheme::Sha256,
    );
    BatchedCpItem {
        item_tag: [tag; 32],
        public,
        witness: proof.witness_bundle,
    }
}

fn k6a_adapter_fixture() -> K6aAdapterFixture {
    k6a_adapter_fixture_with_batch_size(1)
}

fn k6a_adapter_fixture_with_batch_size(batch_size: usize) -> K6aAdapterFixture {
    let params = k6a_params();
    let (prover, _) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params);
    let (r1cs, z) = k6a_r1cs();
    let items = (0..batch_size)
        .map(|idx| k6a_batched_item(&prover, &r1cs, &z, idx as u8 + 1))
        .collect::<Vec<_>>();
    let bucket = BatchedCpBucket::new(items, digest(b"k6a-native-adapter-whir-params"))
        .expect("K6a adapter bucket");
    let descriptor = BatchedCpSymbt3SetupDescriptor::new(
        bucket.shape.clone(),
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );
    let relation =
        <WhirSnark as crate::cp_backend_api::CpBackend>::symbt3_relation_description(&descriptor)
            .expect("WHIR exposes SYMBT3 relation");
    let decoded_relation =
        BatchedCpSymbt3RelationDescription::from_context_bytes(relation.context.as_ref().unwrap())
            .expect("SYMBT3 relation context decodes");
    let (pk, vk) = <WhirSnark as crate::cp_backend_api::CpBackend>::setup(&relation);
    let public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
    let witness = bucket.symbt3_witness_for_relation(&decoded_relation);
    let profile =
        Symbt3AuthorityProfile::accumulator_non_zk_integrity_product_authority_from_relation(
            &decoded_relation,
            64,
        );
    let profile_digest = profile.digest(bucket.shape.accumulator_shape.digest_scheme);
    let accumulator_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
        bucket.shape.accumulator_shape.digest_scheme,
        profile_digest,
        public.old_accumulator_digest,
        public.new_accumulator_digest,
        &public,
    );
    let accumulator_witness =
        Symbt3AccumulatorWitness::from_symbt3_witness(&decoded_relation, &witness);
    let (proof, adapter) = prove_symbt3_native_accumulator_k6a_workload_adapter(
        &pk,
        &profile,
        &accumulator_instance,
        &accumulator_witness,
    )
    .expect("K6a native workload adapter proof");
    K6aAdapterFixture {
        pk,
        vk,
        profile,
        accumulator_instance,
        accumulator_witness,
        proof,
        adapter,
    }
}

fn k6a_compatible_n7b_tuple_leaf_parts(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
) -> (WhirVerifyingKey, Symbt3N7bNativeTupleLeafProofParts) {
    k6a_compatible_n7b_tuple_leaf_parts_with_repetitions(
        adapter,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT,
        SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS,
    )
}

fn k6a_compatible_n7b_tuple_leaf_parts_with_repetitions(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    rlc_repetition_count: usize,
    rlc_batching_bits_per_repetition: usize,
) -> (WhirVerifyingKey, Symbt3N7bNativeTupleLeafProofParts) {
    let (pk, vk) = WhirSnark::setup(&relation());
    let num_vars = 1;
    let opening_schedule = WhirNativeOpeningSchedule::TranscriptDerived {
        domain_separator: SYMBT3_N7_TUPLE_LEAF_OPENING_DOMAIN,
    };
    let specs = vec![
        WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: SYMBT3_N2_MANIFEST_ORACLE_ID,
            role: WhirNativeOracleRole::Manifest,
            layout_digest: digest(b"n7b-full-manifest-layout"),
            num_vars,
            opening_schedule: opening_schedule.clone(),
        },
        WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: SYMBT3_N2_SOURCE_ORACLE_ID,
            role: WhirNativeOracleRole::Source,
            layout_digest: digest(b"n7b-full-source-layout"),
            num_vars,
            opening_schedule: opening_schedule.clone(),
        },
        WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: SYMBT3_N4_MESSAGE_ORACLE_ID_BASE,
            role: WhirNativeOracleRole::MessageRound { round: 0 },
            layout_digest: digest(b"n7b-full-message-layout"),
            num_vars,
            opening_schedule,
        },
    ];
    let evaluations = vec![
        vec![BabyBear::from_u32(3), BabyBear::from_u32(5)],
        vec![BabyBear::from_u32(3), BabyBear::from_u32(7)],
        vec![BabyBear::from_u32(11), BabyBear::from_u32(13)],
    ];
    let eval_requests = specs
        .iter()
        .map(|spec| WhirNativeEvalRequest {
            oracle_id: spec.oracle_id,
            claim_kind: WhirNativeEvalClaimKind::DirectOpening,
        })
        .collect::<Vec<_>>();
    let proof = whir_commit_and_prove_same_domain_multi_oracle_with_repetitions(
        &pk,
        adapter.main_symbt3_relation_id,
        adapter.public_statement_digest,
        adapter.whir_param_digest,
        &specs,
        &evaluations,
        &eval_requests,
        rlc_repetition_count,
        rlc_batching_bits_per_repetition,
    )
    .expect("K6a-compatible tuple-leaf proof");
    let manifest_oracle_root = adapter.manifest_oracle_root;
    let source_oracle_root = digest(b"n7b-full-source-oracle-root");
    let message_oracle_root = digest(b"n7b-full-message-oracle-root");
    let descriptors = specs
        .iter()
        .zip([
            manifest_oracle_root,
            source_oracle_root,
            message_oracle_root,
        ])
        .map(|(spec, root)| spec.descriptor_with_root(root))
        .collect::<Vec<_>>();
    (
        vk,
        Symbt3N7bNativeTupleLeafProofParts {
            proof,
            native_oracle_descriptor_digest: native_oracle_descriptor_digest(&descriptors),
            native_message_roots_digest: adapter.native_message_roots_digest,
            manifest_oracle_root,
            source_oracle_root,
        },
    )
}

fn n7_instance_witness(
    batch_log_size: usize,
    round_count: usize,
) -> (
    Symbt3NativeFoldingIntegrityInstance,
    Symbt3NativeFoldingIntegrityWitness,
) {
    let (mut instance, witness) = n6a_instance_witness(batch_log_size, round_count);
    instance.semantic_profile_version =
        SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_MIN_SEMANTIC_PROFILE_VERSION;
    (instance, witness)
}

fn n7_fixture(batch_log_size: usize, round_count: usize) -> N7Fixture {
    let (pk, vk) = WhirSnark::setup(&relation());
    let (instance, witness) = n7_instance_witness(batch_log_size, round_count);
    let proof = prove_symbt3_native_accumulator_authority_non_zk(&pk, &instance, &witness)
        .expect("N7 native accumulator authority proof");
    N7Fixture {
        vk,
        instance,
        proof,
    }
}

fn verify_n7_fixture(
    fixture: &N7Fixture,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> bool {
    verify_symbt3_native_accumulator_authority_non_zk(&fixture.vk, instance, proof)
}

#[test]
fn native_oracle_two_oracle_roundtrip_and_counters() {
    let (
        _pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        _specs,
        _evals,
        _requests,
        proof,
    ) = native_oracle_fixture();

    let report = whir_verify_oracle_openings_with_counters(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &proof.descriptors,
        &proof,
        &proof.eval_claims,
    );
    assert!(report.ok);
    assert_eq!(proof.top_level_whir_proof_count(), 1);
    assert_eq!(proof.family_columnar_subproof_count(), 0);
    assert_eq!(proof.native_oracle_pcs_opening_count(), 2);
    assert_eq!(report.counters.native_oracle_count, 2);
    assert_eq!(report.counters.native_oracle_eval_claim_count, 2);
    assert_eq!(report.counters.native_oracle_pcs_opening_count, 2);
    assert_eq!(
        proof.root_policy,
        NativeOracleRootPolicy::CanonicalWhirRootV1
    );
    assert!(report.counters.native_oracle_descriptor_bytes > 0);
    assert!(report.native_oracle_verify_ms >= 0.0);
    assert_eq!(
        proof.native_oracle_descriptor_digest,
        native_oracle_descriptor_digest(&proof.descriptors)
    );
    assert_eq!(
        proof.native_oracle_eval_claims_digest,
        native_oracle_eval_claims_digest(&proof.eval_claims)
    );
    assert_eq!(
        proof.native_multi_oracle_envelope_digest,
        native_multi_oracle_envelope_digest(&proof)
    );
}

#[test]
fn symbt3_native_oracle_manifest_source_equality_smoke() {
    let (
        _pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        _specs,
        _evals,
        _requests,
        proof,
    ) = native_oracle_fixture();

    assert!(verify_fixture(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &proof
    ));
    assert_eq!(proof.eval_claims.len(), 2);
    assert_eq!(proof.descriptors[0].role, WhirNativeOracleRole::Manifest);
    assert_eq!(proof.descriptors[1].role, WhirNativeOracleRole::Source);
    assert_eq!(
        proof.eval_claims[0].claim_kind,
        WhirNativeEvalClaimKind::EqualitySide
    );
    assert_eq!(
        proof.eval_claims[1].claim_kind,
        WhirNativeEvalClaimKind::EqualitySide
    );
    assert_eq!(proof.eval_claims[0].value, proof.eval_claims[1].value);
}

#[test]
fn symbt3_n2_native_manifest_source_membership_roundtrip_and_counters() {
    let fixture = n2_fixture();
    let report = verify_n2_fixture(&fixture, &fixture.proof);
    assert!(report.ok);
    assert_eq!(
        fixture.proof.native_proof.root_policy,
        NativeOracleRootPolicy::CanonicalWhirRootV1
    );
    assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
    assert_eq!(
        fixture.proof.native_proof.family_columnar_subproof_count(),
        0
    );
    assert_eq!(
        fixture.proof.native_proof.native_oracle_pcs_opening_count(),
        2
    );
    assert_eq!(report.counters.native_oracle_count, 2);
    assert_eq!(report.counters.native_oracle_eval_claim_count, 2);
    assert_eq!(report.counters.native_oracle_opening_count, 2);
    assert_eq!(report.counters.native_oracle_pcs_opening_count, 2);
    assert!(report.counters.native_oracle_descriptor_bytes > 0);
    assert!(report.native_oracle_verify_ms >= 0.0);
    assert_eq!(
        fixture.proof.batch_manifest_root,
        native_batch_manifest_root(
            fixture.manifest_layout_digest,
            fixture.proof.native_proof.descriptors[0].root,
            native_oracle_root_policy_digest(NativeOracleRootPolicy::CanonicalWhirRootV1),
        )
    );
    assert_eq!(
        fixture.proof.native_proof.eval_claims[0].claim_kind,
        WhirNativeEvalClaimKind::EqualitySide
    );
    assert_eq!(
        fixture.proof.native_proof.eval_claims[1].claim_kind,
        WhirNativeEvalClaimKind::EqualitySide
    );
    assert_eq!(
        fixture.proof.native_proof.eval_claims[0].point_digest,
        fixture.proof.native_proof.eval_claims[1].point_digest
    );
    assert_eq!(
        fixture.proof.native_proof.eval_claims[0].value,
        fixture.proof.native_proof.eval_claims[1].value
    );
}

#[test]
fn symbt3_n2_build_specs_rejects_num_vars_mismatch() {
    let fixture = n2_fixture();
    assert!(build_n2_native_manifest_source_oracle_specs(
        fixture.manifest_layout_digest,
        fixture.source_layout_digest,
        2,
        3,
        fixture.proof.batch_manifest_root,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    )
    .is_none());
    assert!(prove_native_manifest_source_membership(
        &fixture.pk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        fixture.manifest_layout_digest,
        fixture.source_layout_digest,
        &fixture.manifest_evals,
        &[
            BabyBear::from_u32(3),
            BabyBear::from_u32(5),
            BabyBear::from_u32(8),
            BabyBear::from_u32(13),
            BabyBear::from_u32(21),
            BabyBear::from_u32(34),
            BabyBear::from_u32(55),
            BabyBear::from_u32(89),
        ],
    )
    .is_none());
}

#[test]
fn symbt3_n2_unequal_manifest_source_eval_rejects() {
    let honest = n2_fixture();
    let unequal_source = honest
        .manifest_evals
        .iter()
        .map(|&value| value + BabyBear::ONE)
        .collect::<Vec<_>>();
    assert!(prove_native_manifest_source_membership(
        &honest.pk,
        honest.proof_relation_id,
        honest.public_statement_digest,
        honest.whir_param_digest,
        honest.manifest_layout_digest,
        honest.source_layout_digest,
        &honest.manifest_evals,
        &unequal_source,
    )
    .is_none());

    let fixture = n2_fixture_with_source_and_policy(
        Some(unequal_source),
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        false,
    );
    assert_ne!(
        fixture.proof.native_proof.eval_claims[0].value,
        fixture.proof.native_proof.eval_claims[1].value
    );
    assert!(!verify_n2_fixture(&fixture, &fixture.proof).ok);
}

#[test]
fn symbt3_n2_manifest_root_swap_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[0].root = digest(b"wrong-n2-manifest-root");
    proof.batch_manifest_root = native_batch_manifest_root(
        fixture.manifest_layout_digest,
        proof.native_proof.descriptors[0].root,
        native_oracle_root_policy_digest(NativeOracleRootPolicy::CanonicalWhirRootV1),
    );
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_source_root_swap_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[1].root = digest(b"wrong-n2-source-root");
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_oracle_id_swap_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[0].oracle_id = SYMBT3_N2_SOURCE_ORACLE_ID;
    proof.native_proof.descriptors[1].oracle_id = SYMBT3_N2_MANIFEST_ORACLE_ID;
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_role_swap_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[0].role = WhirNativeOracleRole::Source;
    proof.native_proof.descriptors[1].role = WhirNativeOracleRole::Manifest;
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_layout_digest_swap_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[0].layout_digest = fixture.source_layout_digest;
    proof.native_proof.descriptors[1].layout_digest = fixture.manifest_layout_digest;
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_num_vars_mismatch_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[1].num_vars += 1;
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_debug_root_policy_rejects() {
    let fixture = n2_fixture_with_source_and_policy(
        None,
        NativeOracleRootPolicy::DebugDevelopmentOnly,
        false,
    );
    let report = verify_native_manifest_source_membership(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        fixture.manifest_layout_digest,
        fixture.source_layout_digest,
        fixture.proof.batch_manifest_root,
        ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
        SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
        NativeOracleRootPolicy::DebugDevelopmentOnly,
        &fixture.proof.native_proof.descriptors,
        &fixture.proof.native_proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n2_public_canonical_policy_rejects() {
    let fixture = n2_fixture();
    let report = verify_native_manifest_source_membership(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        fixture.manifest_layout_digest,
        fixture.source_layout_digest,
        fixture.proof.batch_manifest_root,
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
        SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &fixture.proof.native_proof.descriptors,
        &fixture.proof.native_proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n2_batch_manifest_root_mismatch_rejects() {
    let fixture = n2_fixture();
    assert!(
        !verify_n2_fixture_with_batch(
            &fixture,
            digest(b"wrong-n2-batch-manifest-root"),
            &fixture.proof.native_proof,
        )
        .ok
    );
}

#[test]
fn symbt3_n2_stale_public_statement_digest_rejects() {
    let fixture = n2_fixture();
    let report = verify_native_manifest_source_membership(
        &fixture.vk,
        fixture.proof_relation_id,
        digest(b"changed-n2-public-statement"),
        fixture.whir_param_digest,
        fixture.manifest_layout_digest,
        fixture.source_layout_digest,
        fixture.proof.batch_manifest_root,
        ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
        SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &fixture.proof.native_proof.descriptors,
        &fixture.proof.native_proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n2_stale_whir_param_digest_rejects() {
    let fixture = n2_fixture();
    let report = verify_native_manifest_source_membership(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        digest(b"changed-n2-whir-params"),
        fixture.manifest_layout_digest,
        fixture.source_layout_digest,
        fixture.proof.batch_manifest_root,
        ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
        SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &fixture.proof.native_proof.descriptors,
        &fixture.proof.native_proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n2_descriptors_out_of_order_reject() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors.reverse();
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_duplicate_oracle_id_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[1].oracle_id = proof.native_proof.descriptors[0].oracle_id;
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_extra_oracle_descriptor_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    let mut extra = proof.native_proof.descriptors[1].clone();
    extra.oracle_id = 3;
    proof.native_proof.descriptors.push(extra);
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_missing_oracle_descriptor_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors.pop();
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_wrong_claim_kind_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.eval_claims[0].claim_kind = WhirNativeEvalClaimKind::ManifestView;
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_point_digest_mutation_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.eval_claims[0].point_digest = digest(b"wrong-n2-point");
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n2_value_mutation_rejects() {
    let fixture = n2_fixture();
    let mut proof = fixture.proof.clone();
    proof.native_proof.eval_claims[0].value += BabyBear::ONE;
    assert!(!verify_n2_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_committed_private_manifest_membership_roundtrip_and_counters() {
    let fixture = n3_fixture();
    let report = verify_n3_fixture(&fixture, &fixture.proof);
    assert!(report.ok);
    assert_eq!(
        fixture.proof.public_statement.manifest_policy,
        ManifestCommitmentPolicy::NativeManifestOracleOpeningV1
    );
    assert_eq!(
        fixture.proof.public_statement.source_policy,
        SourceCommitmentPolicy::NativeSourceOracleOpeningV1
    );
    assert_eq!(
        fixture.proof.public_statement.zk_status,
        Symbt3ZkStatus::NonZkIntegrityOnly
    );
    assert_eq!(report.committed_private_component_count, 1);
    assert_eq!(report.committed_private_public_bytes, 0);
    assert!(report.public_statement_bytes > 0);
    assert_eq!(report.native_report.counters.native_oracle_count, 2);
    assert_eq!(
        report
            .native_report
            .counters
            .native_oracle_pcs_opening_count,
        2
    );
    assert_eq!(
        fixture
            .proof
            .membership_proof
            .native_proof
            .top_level_whir_proof_count(),
        1
    );
    assert_eq!(
        fixture
            .proof
            .membership_proof
            .native_proof
            .family_columnar_subproof_count(),
        0
    );
    assert_eq!(
        fixture.proof.membership_proof.native_proof.eval_claims[0].value,
        fixture.proof.membership_proof.native_proof.eval_claims[1].value
    );
    assert_eq!(
        fixture.proof.public_statement.batch_manifest_root,
        native_batch_manifest_root(
            fixture.proof.public_statement.manifest_layout_digest,
            fixture.proof.public_statement.manifest_oracle_root,
            native_oracle_root_policy_digest(NativeOracleRootPolicy::CanonicalWhirRootV1),
        )
    );
}

#[test]
fn symbt3_n3_public_boundary_excludes_committed_private_values() {
    let fixture = n3_fixture();
    let statement = &fixture.proof.public_statement;
    let private_component = &fixture.components[1];
    let mut private_value_bytes = Vec::new();
    push_babybear_vec(&mut private_value_bytes, &private_component.manifest_values);
    push_babybear_vec(&mut private_value_bytes, &private_component.source_values);

    assert_eq!(statement.committed_private_public_bytes(), 0);
    assert!(statement.components[1].public_manifest_values.is_empty());
    assert!(statement.components[1].public_source_values.is_empty());
    assert!(!statement
        .canonical_bytes()
        .windows(private_value_bytes.len())
        .any(|window| window == private_value_bytes.as_slice()));
    assert_eq!(
        statement.components[0].public_manifest_values,
        fixture.components[0].manifest_values
    );
}

#[test]
fn symbt3_n3_explicit_nonzk_research_policy_verifies() {
    let fixture =
        n3_fixture_with_components(n3_components(), Symbt3ZkStatus::ExplicitNonZkResearch);
    assert!(verify_n3_fixture(&fixture, &fixture.proof).ok);
}

#[test]
fn symbt3_n3_public_canonical_manifest_policy_rejects_committed_private() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.public_statement.manifest_policy =
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1;
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_zk_required_profile_rejects_without_k5() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.public_statement.zk_status = Symbt3ZkStatus::ZkRequired;
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
    assert!(prove_committed_private_manifest_membership(
        &fixture.pk,
        fixture.proof_relation_id,
        fixture.whir_param_digest,
        Symbt3ZkStatus::ZkRequired,
        &fixture.components,
    )
    .is_none());
}

#[test]
fn symbt3_n3_mutating_committed_private_manifest_value_rejects() {
    let fixture = n3_fixture();
    let mut components = fixture.components.clone();
    components[1].manifest_values[0] += BabyBear::ONE;
    let (manifest_evals, source_evals) = flatten_n3_components(&components);
    let membership_proof = low_level_n3_membership_proof_with_statement(
        &fixture.pk,
        fixture.proof_relation_id,
        fixture.whir_param_digest,
        &fixture.proof.public_statement,
        &manifest_evals,
        &source_evals,
    );
    let proof = Symbt3CommittedPrivateManifestMembershipProof {
        public_statement: fixture.proof.public_statement.clone(),
        membership_proof,
    };
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_mutating_committed_private_source_value_rejects() {
    let fixture = n3_fixture();
    let mut components = fixture.components.clone();
    components[1].source_values[1] += BabyBear::ONE;
    let (manifest_evals, source_evals) = flatten_n3_components(&components);
    let membership_proof = low_level_n3_membership_proof_with_statement(
        &fixture.pk,
        fixture.proof_relation_id,
        fixture.whir_param_digest,
        &fixture.proof.public_statement,
        &manifest_evals,
        &source_evals,
    );
    let proof = Symbt3CommittedPrivateManifestMembershipProof {
        public_statement: fixture.proof.public_statement.clone(),
        membership_proof,
    };
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_committed_private_component_layout_digest_mutation_rejects() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.public_statement.components[1].layout_digest = digest(b"wrong-n3-private-layout");
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_stale_private_component_root_rejects() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.public_statement.components[1].manifest_component_root =
        digest(b"wrong-n3-private-component-root");
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_debug_root_policy_rejects() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.public_statement.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_num_vars_mismatch_rejects() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.membership_proof.native_proof.descriptors[1].num_vars += 1;
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_wrong_visibility_tag_rejects() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.public_statement.components[1].visibility = Symbt3ManifestVisibility::PublicBoundary;
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_wrong_component_kind_rejects() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.public_statement.components[1].kind = Symbt3ManifestComponentKind::Auxiliary(99);
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_wrong_component_order_rejects() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.public_statement.components.reverse();
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_stale_public_statement_digest_rejects() {
    let fixture = n3_fixture();
    let mut proof = fixture.proof.clone();
    proof.membership_proof.native_proof.public_statement_digest =
        digest(b"changed-n3-public-statement-digest");
    assert!(!verify_n3_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n3_stale_whir_param_digest_rejects() {
    let fixture = n3_fixture();
    let report = verify_committed_private_manifest_membership(
        &fixture.vk,
        fixture.proof_relation_id,
        digest(b"changed-n3-whir-params"),
        &fixture.proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n4_one_round_message_oracle_verifies() {
    let fixture = n4_fixture(1);
    let report = verify_n4_fixture(&fixture, &fixture.proof);
    assert!(report.ok);
    assert_eq!(report.native_message_round_count, 1);
    assert_eq!(report.native_report.counters.native_oracle_count, 1);
    assert_eq!(
        report.native_report.counters.native_oracle_eval_claim_count,
        1
    );
    assert_eq!(
        report
            .native_report
            .counters
            .native_oracle_pcs_opening_count,
        1
    );
    assert_eq!(report.message_to_trace_binding_count, 0);
    assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
    assert_eq!(
        fixture.proof.native_proof.family_columnar_subproof_count(),
        0
    );
    assert_eq!(
        fixture.proof.native_proof.eval_claims[0].claim_kind,
        WhirNativeEvalClaimKind::MessageView
    );
}

#[test]
fn symbt3_n4_two_round_message_oracles_verify_with_counters() {
    let fixture = n4_fixture(2);
    let report = verify_n4_fixture(&fixture, &fixture.proof);
    assert!(report.ok);
    assert_eq!(report.native_message_round_count, 2);
    assert_eq!(report.native_report.counters.native_oracle_count, 2);
    assert_eq!(
        report.native_report.counters.native_oracle_eval_claim_count,
        2
    );
    assert_eq!(
        report
            .native_report
            .counters
            .native_oracle_pcs_opening_count,
        2
    );
    assert_eq!(report.message_to_trace_binding_count, 0);
    assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
    assert_eq!(
        fixture.proof.native_proof.family_columnar_subproof_count(),
        0
    );
    assert_ne!(
        fixture.proof.native_proof.descriptors[0].num_vars,
        fixture.proof.native_proof.descriptors[1].num_vars
    );
    assert_eq!(report.round_challenges, fixture.proof.round_challenges);
}

#[test]
fn symbt3_n4b_one_round_batch_axis_keeps_oracle_count_constant() {
    let mut observed_num_vars = Vec::new();
    for (batch_size, batch_log_size) in [(1usize, 0usize), (2, 1), (4, 2), (8, 3)] {
        let fixture = n4_fixture_with_batch_log_size(1, batch_log_size);
        let report = verify_n4_fixture(&fixture, &fixture.proof);
        assert!(report.ok);
        assert_eq!(fixture.challenge_context.batch_size, batch_size as u64);
        assert_eq!(report.native_message_round_count, 1);
        assert_eq!(report.native_report.counters.native_oracle_count, 1);
        assert_eq!(
            report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            1
        );
        assert_eq!(report.message_to_trace_binding_count, 0);
        assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
        assert_eq!(
            fixture.proof.native_proof.family_columnar_subproof_count(),
            0
        );
        assert_eq!(
            fixture.proof.native_proof.descriptors[0].num_vars,
            batch_log_size + fixture.round_layouts[0].message_axis_log_size
        );
        observed_num_vars.push(fixture.proof.native_proof.descriptors[0].num_vars);
    }
    assert_eq!(observed_num_vars, vec![1, 2, 3, 4]);
}

#[test]
fn symbt3_n4b_two_round_batch_axis_keeps_oracle_count_constant() {
    for batch_log_size in [0usize, 1, 2] {
        let fixture = n4_fixture_with_batch_log_size(2, batch_log_size);
        let report = verify_n4_fixture(&fixture, &fixture.proof);
        assert!(report.ok);
        assert_eq!(report.native_message_round_count, 2);
        assert_eq!(report.native_report.counters.native_oracle_count, 2);
        assert_eq!(
            report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            2
        );
        assert_eq!(report.message_to_trace_binding_count, 0);
        assert_eq!(
            fixture.proof.native_proof.family_columnar_subproof_count(),
            0
        );
        assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
        assert_eq!(
            fixture.proof.native_proof.descriptors[0].num_vars,
            batch_log_size + fixture.round_layouts[0].message_axis_log_size
        );
        assert_eq!(
            fixture.proof.native_proof.descriptors[1].num_vars,
            batch_log_size + fixture.round_layouts[1].message_axis_log_size
        );
    }
}

#[test]
fn symbt3_n4_prefix_challenges_bind_ordered_prefix_roots() {
    let fixture = n4_fixture(3);
    let mut roots = fixture
        .proof
        .native_proof
        .descriptors
        .iter()
        .map(|descriptor| descriptor.root)
        .collect::<Vec<_>>();
    let challenge_0 = n4_round_challenge_for(&fixture, &roots, 0);
    let challenge_1 = n4_round_challenge_for(&fixture, &roots, 1);

    roots[0] = digest(b"n4-mutated-root-0");
    assert_ne!(challenge_0, n4_round_challenge_for(&fixture, &roots, 0));
    assert_ne!(challenge_1, n4_round_challenge_for(&fixture, &roots, 1));

    roots = fixture
        .proof
        .native_proof
        .descriptors
        .iter()
        .map(|descriptor| descriptor.root)
        .collect::<Vec<_>>();
    roots[1] = digest(b"n4-mutated-root-1");
    assert_eq!(challenge_0, n4_round_challenge_for(&fixture, &roots, 0));
    assert_ne!(challenge_1, n4_round_challenge_for(&fixture, &roots, 1));

    roots = fixture
        .proof
        .native_proof
        .descriptors
        .iter()
        .map(|descriptor| descriptor.root)
        .collect::<Vec<_>>();
    roots[2] = digest(b"n4-mutated-later-root");
    assert_eq!(challenge_0, n4_round_challenge_for(&fixture, &roots, 0));
    assert_eq!(challenge_1, n4_round_challenge_for(&fixture, &roots, 1));
}

#[test]
fn symbt3_n4_prefix_challenges_bind_layout_counts_and_ignore_folded_output() {
    let fixture = n4_fixture(2);
    let roots = fixture
        .proof
        .native_proof
        .descriptors
        .iter()
        .map(|descriptor| descriptor.root)
        .collect::<Vec<_>>();
    let challenge = n4_round_challenge_for(&fixture, &roots, 1);

    let mut mutated_layouts = fixture.round_layouts.clone();
    mutated_layouts[1].layout_digest = digest(b"n4-mutated-round-layout");
    assert_ne!(
        challenge,
        derive_native_round_challenge(
            mutated_layouts[1].round_index,
            &roots[..=1],
            mutated_layouts[1].layout_digest,
            &fixture.challenge_context,
        )
    );

    let mut count_context = fixture.challenge_context.clone();
    count_context.active_count += 1;
    assert_ne!(
        challenge,
        derive_native_round_challenge(
            fixture.round_layouts[1].round_index,
            &roots[..=1],
            fixture.round_layouts[1].layout_digest,
            &count_context,
        )
    );

    let mut batch_context = fixture.challenge_context.clone();
    batch_context.batch_size += 1;
    assert_ne!(
        challenge,
        derive_native_round_challenge(
            fixture.round_layouts[1].round_index,
            &roots[..=1],
            fixture.round_layouts[1].layout_digest,
            &batch_context,
        )
    );

    let mut folded_context = fixture.challenge_context.clone();
    folded_context.folded_output_digest = digest(b"n4-mutated-folded-output");
    assert_eq!(
        challenge,
        derive_native_round_challenge(
            fixture.round_layouts[1].round_index,
            &roots[..=1],
            fixture.round_layouts[1].layout_digest,
            &folded_context,
        )
    );
}

#[test]
fn symbt3_n4_public_boundary_omits_message_values_and_challenges_ignore_opening_payloads() {
    let fixture = n4_fixture(2);
    let public_boundary = Symbt3NativeMessageOraclePublicBoundary {
        message_oracle_policy: Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        message_oracle_roots_digest: fixture.proof.message_oracle_roots_digest,
        message_round_layouts_digest: fixture.proof.message_round_layouts_digest,
        message_oracle_policy_digest: fixture.proof.message_oracle_policy_digest,
    };
    let mut first_message_bytes = Vec::new();
    push_babybear_vec(&mut first_message_bytes, &fixture.message_evals[0]);
    assert!(!public_boundary
        .canonical_bytes()
        .windows(first_message_bytes.len())
        .any(|window| window == first_message_bytes.as_slice()));

    let before = derive_native_round_challenges(
        &fixture.proof.native_proof.descriptors,
        &fixture.round_layouts,
        &fixture.challenge_context,
    )
    .expect("round challenges");
    let mut proof = fixture.proof.clone();
    proof.native_proof.eval_claims[0].value += BabyBear::ONE;
    assert_eq!(
        before,
        derive_native_round_challenges(
            &proof.native_proof.descriptors,
            &fixture.round_layouts,
            &fixture.challenge_context,
        )
        .expect("round challenges")
    );
}

#[test]
fn symbt3_n4_root_swap_between_rounds_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    let root_0 = proof.native_proof.descriptors[0].root;
    proof.native_proof.descriptors[0].root = proof.native_proof.descriptors[1].root;
    proof.native_proof.descriptors[1].root = root_0;
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_oracle_id_swap_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[0].oracle_id = SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + 1;
    proof.native_proof.descriptors[1].oracle_id = SYMBT3_N4_MESSAGE_ORACLE_ID_BASE;
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_role_round_index_swap_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[0].role = WhirNativeOracleRole::MessageRound { round: 1 };
    proof.native_proof.descriptors[1].role = WhirNativeOracleRole::MessageRound { round: 0 };
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_wrong_round_count_rejects() {
    let fixture = n4_fixture(2);
    let mut layouts = fixture.round_layouts.clone();
    layouts.pop();
    let report = verify_native_round_message_oracle_views(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &layouts,
        fixture.proof.message_oracle_roots_digest,
        native_message_round_layouts_digest(&layouts),
        fixture.proof.message_oracle_policy_digest,
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &fixture.proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n4_wrong_round_layout_digest_rejects() {
    let fixture = n4_fixture(2);
    let mut layouts = fixture.round_layouts.clone();
    layouts[1].layout_digest = digest(b"n4-wrong-layout");
    let report = verify_native_round_message_oracle_views(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &layouts,
        fixture.proof.message_oracle_roots_digest,
        fixture.proof.message_round_layouts_digest,
        fixture.proof.message_oracle_policy_digest,
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &fixture.proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n4_wrong_num_vars_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[1].num_vars += 1;
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4b_one_oracle_per_batch_item_under_fixed_round_count_rejects() {
    let fixture = n4_fixture_with_batch_log_size(1, 2);
    let item_style_round_layouts = n4_layouts(4, fixture.batch_log_size);
    let item_style_evals = n4_message_evals(&item_style_round_layouts);
    let proof = low_level_n4_proof_with_root_policy(
        &fixture.pk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &item_style_round_layouts,
        &item_style_evals,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    );
    assert_eq!(proof.native_proof.descriptors.len(), 4);

    let report = verify_native_round_message_oracle_views(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &fixture.round_layouts,
        proof.message_oracle_roots_digest,
        proof.message_round_layouts_digest,
        proof.message_oracle_policy_digest,
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n4b_wrong_batch_axis_log_size_rejects() {
    let fixture = n4_fixture_with_batch_log_size(1, 2);
    let mut layouts = fixture.round_layouts.clone();
    layouts[0].batch_axis_log_size += 1;
    assert!(build_native_message_oracle_specs(&layouts, fixture.batch_log_size).is_none());
    assert!(prove_native_round_message_oracle_views(
        &fixture.pk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &layouts,
        &fixture.message_evals,
        &native_round_message_view_eval_requests(&layouts),
    )
    .is_none());
}

#[test]
fn symbt3_n4b_wrong_message_axis_log_size_rejects() {
    let fixture = n4_fixture_with_batch_log_size(1, 2);
    let mut layouts = fixture.round_layouts.clone();
    layouts[0].message_axis_log_size += 1;
    assert!(build_native_message_oracle_specs(&layouts, fixture.batch_log_size).is_none());
    assert!(prove_native_round_message_oracle_views(
        &fixture.pk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &layouts,
        &fixture.message_evals,
        &native_round_message_view_eval_requests(&layouts),
    )
    .is_none());
}

#[test]
fn symbt3_n4b_item_root_style_replay_rejects() {
    let fixture = n4_fixture_with_batch_log_size(1, 2);
    let item_style_round_layouts = n4_layouts(4, fixture.batch_log_size);
    let item_style_evals = n4_message_evals(&item_style_round_layouts);
    let proof = low_level_n4_proof_with_root_policy(
        &fixture.pk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &item_style_round_layouts,
        &item_style_evals,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    );
    let report = verify_native_round_message_oracle_views(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &fixture.round_layouts,
        proof.message_oracle_roots_digest,
        fixture.proof.message_round_layouts_digest,
        proof.message_oracle_policy_digest,
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n4b_stale_challenge_prefix_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.round_challenges[1] += BabyBear::ONE;
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_wrong_message_value_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.native_proof.eval_claims[0].value += BabyBear::ONE;
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_wrong_point_digest_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.native_proof.eval_claims[0].point_digest = digest(b"n4-wrong-point");
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_wrong_claim_kind_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.native_proof.eval_claims[0].claim_kind = WhirNativeEvalClaimKind::DirectOpening;
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_descriptor_truncation_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors.pop();
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_descriptor_append_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    let mut extra = proof.native_proof.descriptors[1].clone();
    extra.oracle_id = SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + 2;
    proof.native_proof.descriptors.push(extra);
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_duplicate_oracle_id_rejects() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors[1].oracle_id = proof.native_proof.descriptors[0].oracle_id;
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_unsorted_descriptors_reject() {
    let fixture = n4_fixture(2);
    let mut proof = fixture.proof.clone();
    proof.native_proof.descriptors.reverse();
    assert!(!verify_n4_fixture(&fixture, &proof).ok);
}

#[test]
fn symbt3_n4_stale_public_statement_digest_rejects() {
    let fixture = n4_fixture(2);
    let report = verify_native_round_message_oracle_views(
        &fixture.vk,
        fixture.proof_relation_id,
        digest(b"changed-n4-public-statement"),
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &fixture.round_layouts,
        fixture.proof.message_oracle_roots_digest,
        fixture.proof.message_round_layouts_digest,
        fixture.proof.message_oracle_policy_digest,
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &fixture.proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n4_stale_whir_param_digest_rejects() {
    let fixture = n4_fixture(2);
    let report = verify_native_round_message_oracle_views(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        digest(b"changed-n4-whir-params"),
        &fixture.challenge_context,
        fixture.batch_log_size,
        &fixture.round_layouts,
        fixture.proof.message_oracle_roots_digest,
        fixture.proof.message_round_layouts_digest,
        fixture.proof.message_oracle_policy_digest,
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        &fixture.proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n4_debug_root_policy_rejects() {
    let fixture = n4_fixture(2);
    let proof = low_level_n4_proof_with_root_policy(
        &fixture.pk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &fixture.round_layouts,
        &fixture.message_evals,
        NativeOracleRootPolicy::DebugDevelopmentOnly,
    );
    let report = verify_native_round_message_oracle_views(
        &fixture.vk,
        fixture.proof_relation_id,
        fixture.public_statement_digest,
        fixture.whir_param_digest,
        &fixture.challenge_context,
        fixture.batch_log_size,
        &fixture.round_layouts,
        proof.message_oracle_roots_digest,
        proof.message_round_layouts_digest,
        proof.message_oracle_policy_digest,
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
        NativeOracleRootPolicy::DebugDevelopmentOnly,
        &proof,
    );
    assert!(!report.ok);
}

#[test]
fn symbt3_n5_native_nonzk_folding_integrity_gate_accepts_valid_profile() {
    let metadata = n5_valid_metadata();
    let report = n5_report(&metadata);

    assert!(report.ok);
    assert!(profile_meets_native_non_zk_folding_integrity(&metadata));
    assert!(report.native_profile_ok);
    assert!(report.native_manifest_policy_ok);
    assert!(report.native_source_policy_ok);
    assert!(report.native_message_policy_ok);
    assert!(report.canonical_root_policy_ok);
    assert!(report.committed_private_policy_ok);
    assert!(report.non_zk_status_ok);
    assert!(report.message_oracle_count_ok);
    assert!(report.manifest_source_oracle_count_ok);
    assert!(report.proof_shape_ok);
    assert!(report.required_families_ok);
    assert!(report.semantic_profile_version_ok);
    assert!(report.no_monolithic_fallback);
    assert!(report.product_routing_unchanged);
    assert_eq!(report.native_oracle_count_manifest_source, 2);
    assert_eq!(report.native_oracle_count_messages, 2);
    assert_eq!(report.native_message_round_count, 2);
    assert_eq!(report.native_message_oracle_count, 2);
    assert!(report.native_message_oracle_count_is_round_count);
    assert_eq!(report.family_columnar_subproof_count, 0);
}

#[test]
fn symbt3_n5_k6a_public_canonical_route_is_not_native_gate() {
    assert!(symbt3_manifest_visibility_allowed_for_policies(
        Symbt3ManifestVisibility::PublicBoundary,
        Symbt3ZkStatus::NonZkIntegrityOnly,
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
        SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
    ));

    let mut metadata = n5_valid_metadata();
    metadata.manifest_policy = Some(ManifestCommitmentPolicy::PublicCanonicalManifestViewV1);
    metadata.committed_private_component_count = 0;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.native_manifest_policy_ok);
}

#[test]
fn symbt3_n5_rejects_missing_native_policies_and_legacy_message_roots() {
    let mut metadata = n5_valid_metadata();
    metadata.manifest_policy = None;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.native_manifest_policy_ok);

    let mut metadata = n5_valid_metadata();
    metadata.source_policy = None;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.native_source_policy_ok);

    let mut metadata = n5_valid_metadata();
    metadata.message_oracle_policy = None;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.native_message_policy_ok);

    let mut metadata = n5_valid_metadata();
    metadata.message_oracle_policy = Some(Symbt3MessageOraclePolicy::DigestOnlyMessageRootsV1);
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.native_message_policy_ok);
}

#[test]
fn symbt3_n5_rejects_debug_roots_and_zk_required_committed_private() {
    let mut metadata = n5_valid_metadata();
    metadata.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.canonical_root_policy_ok);

    let mut metadata = n5_valid_metadata();
    metadata.zk_status = Symbt3ZkStatus::ZkRequired;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.non_zk_status_ok);
    assert!(!report.committed_private_policy_ok);
}

#[test]
fn symbt3_n5_rejects_one_oracle_per_batch_and_bad_message_layouts() {
    let mut metadata = n5_valid_metadata();
    metadata.native_message_round_count = 1;
    metadata.native_message_oracle_count = metadata.batch_size;
    metadata.native_message_pcs_opening_count = metadata.batch_size;
    metadata.message_round_layouts = n4_layouts(1, metadata.batch_axis_log_size);
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.message_oracle_count_ok);
    assert!(!report.native_message_oracle_count_is_round_count);

    let mut metadata = n5_valid_metadata();
    metadata.message_round_layouts[0].batch_axis_log_size += 1;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.message_oracle_count_ok);
}

#[test]
fn symbt3_n5_rejects_old_semantic_profile_and_missing_families() {
    let mut metadata = n5_valid_metadata();
    metadata.semantic_profile_version =
        SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION - 1;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.semantic_profile_version_ok);

    let mut metadata = n5_valid_metadata();
    metadata
        .required_semantic_families
        .manifest_evaluation_claim = false;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.required_families_ok);

    let mut metadata = n5_valid_metadata();
    metadata
        .required_semantic_families
        .accumulator_transition_consistency = false;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.required_families_ok);

    let mut metadata = n5_valid_metadata();
    metadata.required_semantic_families.k3_semantic_family = false;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.required_families_ok);

    let mut metadata = n5_valid_metadata();
    metadata
        .required_semantic_families
        .production_norm_range_bundle = false;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.required_families_ok);
}

#[test]
fn symbt3_n5_rejects_bad_proof_shape_monolithic_and_product_route() {
    let mut metadata = n5_valid_metadata();
    metadata.family_columnar_subproof_count = 1;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.proof_shape_ok);
    assert_eq!(report.family_columnar_subproof_count, 1);

    let mut metadata = n5_valid_metadata();
    metadata.logical_native_envelope_count = 2;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.proof_shape_ok);

    let mut metadata = n5_valid_metadata();
    metadata.monolithic_fallback = true;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.no_monolithic_fallback);
    assert!(!report.proof_shape_ok);

    let mut metadata = n5_valid_metadata();
    metadata.product_default_route_attempted = true;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.product_routing_unchanged);

    let mut metadata = n5_valid_metadata();
    metadata.product_eligible = true;
    let report = n5_report(&metadata);
    assert!(!report.ok);
    assert!(!report.product_routing_unchanged);
}

#[test]
fn symbt3_n6a_honest_profiles_verify_and_report_expected_counters() {
    for (batch_log_size, round_count) in [(0usize, 1usize), (1, 1), (1, 2)] {
        let fixture = n6a_fixture(batch_log_size, round_count);
        assert!(verify_n6a_fixture(
            &fixture,
            &fixture.instance,
            &fixture.proof
        ));
        assert_eq!(fixture.proof.version, 1);
        assert_eq!(
            fixture.proof.proof_kind,
            Symbt3NativeFoldingProofKind::NativeNonZkFoldingIntegrityV1
        );
        assert_eq!(fixture.proof.counters.top_level_whir_proof_count, 1);
        assert_eq!(fixture.proof.counters.family_columnar_subproof_count, 0);
        assert_eq!(fixture.proof.counters.backend_table_count, 1);
        assert_eq!(
            fixture.proof.counters.native_manifest_source_oracle_count,
            2
        );
        assert_eq!(
            fixture.proof.counters.native_message_oracle_count,
            round_count
        );
        assert_eq!(fixture.proof.counters.native_oracle_count, 2 + round_count);
        assert_eq!(
            fixture.proof.counters.native_oracle_pcs_opening_count,
            2 + round_count
        );
        assert_eq!(fixture.proof.counters.message_to_trace_binding_count, 0);
        assert_eq!(fixture.proof.counters.accumulator_transition_claims, 1);
        assert_eq!(
            fixture.proof.native_oracle_proof.descriptors.len(),
            2 + round_count
        );
        assert_eq!(
            fixture.proof.native_oracle_proof.pcs_openings.len(),
            2 + round_count
        );
        assert_eq!(
            fixture.proof.native_oracle_descriptor_digest,
            native_oracle_descriptor_digest(&fixture.proof.native_oracle_proof.descriptors)
        );
        assert_eq!(
            fixture.proof.native_message_roots_digest,
            native_message_roots_digest(&fixture.proof.native_oracle_proof.descriptors[2..])
        );
        assert_eq!(
            fixture.proof.binding_digest,
            native_folding_integrity_binding_digest(
                fixture.instance.symbt3_relation_id,
                fixture.instance.public_statement_digest(),
                fixture.proof.profile_digest,
                fixture.instance.whir_param_digest,
                fixture.proof.native_oracle_descriptor_digest,
                fixture.proof.native_message_roots_digest,
                fixture.proof.manifest_oracle_root,
                fixture.proof.source_oracle_root,
                fixture.proof.batch_manifest_root,
                fixture.instance.source_column_layout_digest,
                fixture.proof.message_oracle_policy_digest,
                fixture.proof.manifest_commitment_policy_digest,
                fixture.instance.active_count,
                fixture.instance.batch_size,
            )
        );

        let metadata = symbt3_native_folding_integrity_profile_metadata(
            &fixture.instance,
            &fixture.proof.counters,
        );
        assert!(profile_meets_native_non_zk_folding_integrity(&metadata));
    }
}

#[test]
fn symbt3_n6a_single_native_envelope_contains_n2_and_n4_claims() {
    let fixture = n6a_fixture(1, 2);
    let proof = &fixture.proof.native_oracle_proof;
    assert_eq!(proof.top_level_whir_proof_count(), 1);
    assert_eq!(proof.family_columnar_subproof_count(), 0);
    assert_eq!(proof.descriptors[0].oracle_id, SYMBT3_N2_MANIFEST_ORACLE_ID);
    assert_eq!(proof.descriptors[1].oracle_id, SYMBT3_N2_SOURCE_ORACLE_ID);
    assert_eq!(
        proof.descriptors[2].oracle_id,
        SYMBT3_N4_MESSAGE_ORACLE_ID_BASE
    );
    assert_eq!(
        proof.descriptors[3].oracle_id,
        SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + 1
    );
    assert_eq!(
        proof.eval_claims[0].claim_kind,
        WhirNativeEvalClaimKind::EqualitySide
    );
    assert_eq!(
        proof.eval_claims[1].claim_kind,
        WhirNativeEvalClaimKind::EqualitySide
    );
    assert_eq!(
        proof.eval_claims[2].claim_kind,
        WhirNativeEvalClaimKind::MessageView
    );
    assert_eq!(
        proof.eval_claims[3].claim_kind,
        WhirNativeEvalClaimKind::MessageView
    );
}

#[test]
fn symbt3_n6a_k6a_public_canonical_route_stays_separate() {
    assert!(symbt3_manifest_visibility_allowed_for_policies(
        Symbt3ManifestVisibility::PublicBoundary,
        Symbt3ZkStatus::NonZkIntegrityOnly,
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
        SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
    ));

    let fixture = n6a_fixture(1, 1);
    let mut instance = fixture.instance.clone();
    instance.manifest_policy = ManifestCommitmentPolicy::PublicCanonicalManifestViewV1;
    instance.committed_private_component_count = 0;
    assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));
}

#[test]
fn symbt3_n6a_rejects_binding_and_metadata_mismatches() {
    let fixture = n6a_fixture(1, 2);

    let mut proof = fixture.proof.clone();
    proof.binding_digest = digest(b"n6a-wrong-binding");
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.profile_digest = digest(b"n6a-wrong-profile");
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.public_statement_digest = digest(b"n6a-wrong-public-statement");
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.whir_param_digest = digest(b"n6a-wrong-whir-params");
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.native_oracle_descriptor_digest = digest(b"n6a-wrong-descriptor-digest");
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.manifest_oracle_root = digest(b"n6a-wrong-manifest-root");
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.source_oracle_root = digest(b"n6a-wrong-source-root");
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.native_message_roots_digest = digest(b"n6a-wrong-message-roots");
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));
}

#[test]
fn symbt3_n6a_rejects_stale_main_or_native_proof_components() {
    let fixture = n6a_fixture(1, 1);

    let mut proof = fixture.proof.clone();
    proof.symbt3_proof.z_eval += BabyBear::ONE;
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.native_oracle_proof.eval_claims[0].value += BabyBear::ONE;
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.native_oracle_proof.eval_claims[2].point_digest = digest(b"n6a-wrong-point");
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));
}

#[test]
fn symbt3_n6a_rejects_route_profile_and_proof_kind_mismatches() {
    let fixture = n6a_fixture(1, 1);

    let mut proof = fixture.proof.clone();
    proof.proof_kind = Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1;
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.proof_kind = Symbt3NativeFoldingProofKind::MonolithicTypedCpV1;
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut instance = fixture.instance.clone();
    instance.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
    assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.message_oracle_policy = Symbt3MessageOraclePolicy::DigestOnlyMessageRootsV1;
    assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.semantic_profile_version =
        SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION - 1;
    assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.zk_status = Symbt3ZkStatus::ZkRequired;
    assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.monolithic_fallback = true;
    assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

    let mut proof = fixture.proof.clone();
    proof.counters.family_columnar_subproof_count = 1;
    assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

    let mut instance = fixture.instance.clone();
    instance.product_default_route_attempted = true;
    assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));
}

#[test]
fn symbt3_n6a_rejects_message_shape_and_challenge_mutations() {
    let fixture = n6a_fixture(2, 1);
    let item_style = n6a_fixture(2, 4);
    assert_eq!(fixture.proof.counters.native_message_oracle_count, 1);
    assert_eq!(item_style.proof.counters.native_message_oracle_count, 4);
    assert!(!verify_n6a_fixture(
        &fixture,
        &fixture.instance,
        &item_style.proof
    ));

    let mut instance = fixture.instance.clone();
    instance.round_layouts[0].batch_axis_log_size += 1;
    assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.round_layouts[0].message_axis_log_size += 1;
    assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

    let two_round = n6a_fixture(1, 2);
    let mut proof = two_round.proof.clone();
    proof.native_oracle_proof.descriptors.swap(2, 3);
    assert!(!verify_n6a_fixture(&two_round, &two_round.instance, &proof));

    let mut proof = two_round.proof.clone();
    proof.round_challenges[1] += BabyBear::ONE;
    assert!(!verify_n6a_fixture(&two_round, &two_round.instance, &proof));
}

#[test]
fn symbt3_n6b_public_route_verifies_for_k1_and_k2() {
    for batch_log_size in [0usize, 1usize] {
        let fixture = n6b_fixture(batch_log_size, 1);
        assert!(verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &fixture.proof
        ));
        assert_eq!(
            fixture.proof.proof_kind,
            Symbt3NativeFoldingProofKind::Symbt3NativeNonZkFoldingIntegrityV1
        );
        assert_eq!(fixture.proof.counters.native_oracle_count, 3);
        assert_eq!(fixture.proof.counters.native_oracle_pcs_opening_count, 3);
        assert_eq!(fixture.proof.counters.top_level_whir_proof_count, 1);
        assert_eq!(fixture.proof.counters.family_columnar_subproof_count, 0);
        assert_eq!(fixture.proof.counters.backend_table_count, 1);
        assert_eq!(fixture.proof.counters.message_to_trace_binding_count, 0);
        assert!(symbt3_native_folding_integrity_public_route_selected(
            &fixture.public_profile
        ));
        assert!(!symbt3_native_folding_integrity_monolithic_fallback_used(
            &fixture.instance
        ));
    }
}

#[test]
fn symbt3_n6b_route_discriminator_separates_k6a_native_and_monolithic() {
    let fixture = n6b_fixture(1, 1);
    assert!(!verify_n6a_fixture(
        &n6a_fixture(1, 1),
        &fixture.instance,
        &fixture.proof
    ));
    assert!(!symbt3_k6a_public_canonical_route_accepts_proof_kind(
        fixture.proof.proof_kind
    ));
    assert!(!symbt3_monolithic_typed_cp_route_accepts_proof_kind(
        fixture.proof.proof_kind
    ));

    let mut proof = fixture.proof.clone();
    proof.proof_kind = Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &proof
    ));
    assert!(symbt3_k6a_public_canonical_route_accepts_proof_kind(
        proof.proof_kind
    ));

    let mut proof = fixture.proof.clone();
    proof.proof_kind = Symbt3NativeFoldingProofKind::MonolithicTypedCpV1;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &proof
    ));
    assert!(symbt3_monolithic_typed_cp_route_accepts_proof_kind(
        proof.proof_kind
    ));
}

#[test]
fn symbt3_n6b_rejects_route_profile_gate_failures() {
    let fixture = n6b_fixture(1, 1);

    let mut profile = fixture.public_profile.clone();
    profile.route_status = Symbt3NativeFoldingIntegrityRouteStatus::Disabled;
    assert!(!verify_n6b_fixture(
        &fixture,
        &profile,
        &fixture.instance,
        &fixture.proof
    ));

    let mut profile = fixture.public_profile.clone();
    profile.route_status = Symbt3NativeFoldingIntegrityRouteStatus::PublicCanonicalK6a;
    assert!(!verify_n6b_fixture(
        &fixture,
        &profile,
        &fixture.instance,
        &fixture.proof
    ));

    let mut profile = fixture.public_profile.clone();
    profile.route_status = Symbt3NativeFoldingIntegrityRouteStatus::DefaultVerifyPublic;
    assert!(!verify_n6b_fixture(
        &fixture,
        &profile,
        &fixture.instance,
        &fixture.proof
    ));

    let mut profile = fixture.public_profile.clone();
    profile.product_accepts_native_non_zk_folding_integrity = false;
    assert!(!verify_n6b_fixture(
        &fixture,
        &profile,
        &fixture.instance,
        &fixture.proof
    ));

    let mut profile = fixture.public_profile.clone();
    profile.k5_masking_required = true;
    assert!(!verify_n6b_fixture(
        &fixture,
        &profile,
        &fixture.instance,
        &fixture.proof
    ));

    let mut profile = fixture.public_profile.clone();
    profile.allow_monolithic_fallback = true;
    assert!(!verify_n6b_fixture(
        &fixture,
        &profile,
        &fixture.instance,
        &fixture.proof
    ));
}

#[test]
fn symbt3_n6b_rejects_native_profile_failures() {
    let fixture = n6b_fixture(1, 1);

    let mut instance = fixture.instance.clone();
    instance
        .required_semantic_families
        .accumulator_transition_consistency = false;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &instance,
        &fixture.proof
    ));

    let mut instance = fixture.instance.clone();
    instance.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &instance,
        &fixture.proof
    ));

    let mut instance = fixture.instance.clone();
    instance.manifest_policy = ManifestCommitmentPolicy::PublicCanonicalManifestViewV1;
    instance.committed_private_component_count = 0;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &instance,
        &fixture.proof
    ));

    let mut instance = fixture.instance.clone();
    instance.message_oracle_policy = Symbt3MessageOraclePolicy::DigestOnlyMessageRootsV1;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &instance,
        &fixture.proof
    ));

    let mut instance = fixture.instance.clone();
    instance.semantic_profile_version =
        SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION - 1;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &instance,
        &fixture.proof
    ));

    let mut instance = fixture.instance.clone();
    instance.zk_status = Symbt3ZkStatus::ZkRequired;
    let mut profile = fixture.public_profile.clone();
    profile.zk_status = Symbt3ZkStatus::ZkRequired;
    assert!(!verify_n6b_fixture(
        &fixture,
        &profile,
        &instance,
        &fixture.proof
    ));

    let mut instance = fixture.instance.clone();
    instance.monolithic_fallback = true;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &instance,
        &fixture.proof
    ));
}

#[test]
fn symbt3_n6b_rejects_binding_digest_and_stale_proofs() {
    let fixture = n6b_fixture(1, 1);

    let mut proof = fixture.proof.clone();
    proof.binding_digest = digest(b"n6b-wrong-binding");
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &proof
    ));

    let mut proof = fixture.proof.clone();
    proof.native_oracle_descriptor_digest = digest(b"n6b-wrong-descriptor");
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &proof
    ));

    let mut proof = fixture.proof.clone();
    proof.native_message_roots_digest = digest(b"n6b-wrong-message-roots");
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &proof
    ));

    let mut proof = fixture.proof.clone();
    proof.native_oracle_proof.eval_claims[0].value += BabyBear::ONE;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &proof
    ));

    let mut proof = fixture.proof.clone();
    proof.symbt3_proof.z_eval += BabyBear::ONE;
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &proof
    ));
}

#[test]
fn symbt3_n6b_rejects_one_oracle_per_batch_item_layout() {
    let fixed_round = n6b_fixture(2, 1);
    let item_style = n6b_fixture(2, 4);
    assert_eq!(fixed_round.proof.counters.native_message_oracle_count, 1);
    assert_eq!(item_style.proof.counters.native_message_oracle_count, 4);
    assert!(!verify_n6b_fixture(
        &fixed_round,
        &fixed_round.public_profile,
        &fixed_round.instance,
        &item_style.proof
    ));
}

#[test]
fn symbt3_n6c_route_matrix_separation_invariants() {
    let fixture = n6b_fixture(1, 1);
    assert!(verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &fixture.proof
    ));
    assert!(symbt3_native_folding_integrity_public_route_selected(
        &fixture.public_profile
    ));
    assert!(!symbt3_k6a_public_canonical_route_accepts_proof_kind(
        fixture.proof.proof_kind
    ));
    assert!(!symbt3_monolithic_typed_cp_route_accepts_proof_kind(
        fixture.proof.proof_kind
    ));

    let mut k6a_proof = fixture.proof.clone();
    k6a_proof.proof_kind = Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1;
    assert!(symbt3_k6a_public_canonical_route_accepts_proof_kind(
        k6a_proof.proof_kind
    ));
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &k6a_proof
    ));

    let mut monolithic_proof = fixture.proof.clone();
    monolithic_proof.proof_kind = Symbt3NativeFoldingProofKind::MonolithicTypedCpV1;
    assert!(symbt3_monolithic_typed_cp_route_accepts_proof_kind(
        monolithic_proof.proof_kind
    ));
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &fixture.instance,
        &monolithic_proof
    ));

    let mut profile = fixture.public_profile.clone();
    profile.route_status = Symbt3NativeFoldingIntegrityRouteStatus::Disabled;
    assert!(!verify_n6b_fixture(
        &fixture,
        &profile,
        &fixture.instance,
        &fixture.proof
    ));

    let mut instance = fixture.instance.clone();
    instance.monolithic_fallback = true;
    assert!(symbt3_native_folding_integrity_monolithic_fallback_used(
        &instance
    ));
    assert!(!verify_n6b_fixture(
        &fixture,
        &fixture.public_profile,
        &instance,
        &fixture.proof
    ));
}

#[test]
fn symbt3_n7_honest_native_accumulator_authority_verifies() {
    for batch_log_size in [0usize, 1, 2] {
        let fixture = n7_fixture(batch_log_size, 1);
        assert!(verify_n7_fixture(
            &fixture,
            &fixture.instance,
            &fixture.proof
        ));
        assert_eq!(
            fixture.proof.proof_kind,
            Symbt3NativeFoldingProofKind::Symbt3NativeAccumulatorAuthorityV1
        );
        assert_eq!(
            fixture.proof.workload_kind,
            Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1
        );
        assert!(!fixture.proof.counters.full_accumulator_workload);
        assert!(fixture.proof.counters.smoke_profile);
        assert_eq!(fixture.proof.counters.main_whir_num_vars, 2);
        assert_eq!(fixture.proof.counters.main_oracle_len, 4);
        assert!(fixture.proof.counters.native_multi_oracle);
        assert_eq!(
            fixture.proof.counters.tuple_leaf_layout,
            SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT
        );
        assert_eq!(fixture.proof.counters.whir_instance_count, 1);
        assert_eq!(fixture.proof.counters.root_count, 1);
        assert_eq!(fixture.proof.counters.query_schedule_count, 1);
        assert_eq!(fixture.proof.counters.transcript_count, 1);
        assert_eq!(fixture.proof.counters.native_oracle_pcs_opening_count, 1);
        assert_eq!(fixture.proof.counters.logical_oracle_count, 3);
        assert_eq!(
            fixture.proof.counters.native_manifest_source_oracle_count,
            2
        );
        assert_eq!(fixture.proof.counters.native_message_oracle_count, 1);
        assert_eq!(fixture.proof.counters.family_columnar_subproof_count, 0);
        assert_eq!(fixture.proof.counters.accumulator_transition_claims, 1);
        assert_eq!(
            fixture.proof.counters.rlc_batching_bits,
            SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
        );
        assert_eq!(
            fixture.proof.counters.rlc_repetition_count,
            SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT
        );
        assert_eq!(
            fixture.proof.counters.rlc_batching_bits_per_repetition,
            SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
        );
        assert_eq!(
            fixture.proof.counters.total_rlc_batching_bits,
            SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
        );
        assert_eq!(
            fixture.proof.counters.effective_soundness_bits,
            SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
        );
        assert_eq!(
            fixture
                .proof
                .rlc_tuple_leaf_multi_oracle_proof
                .counters
                .root_count,
            1
        );
    }
}

#[test]
fn symbt3_n7_profile_gate_accepts_tuple_leaf_authority_shape() {
    let fixture = n7_fixture(1, 1);
    let metadata = symbt3_native_accumulator_authority_profile_metadata(
        &fixture.instance,
        &fixture.proof.counters,
    );
    let report = symbt3_native_accumulator_authority_profile_report(&metadata);
    assert!(report.ok);
    assert!(profile_meets_native_accumulator_authority(&metadata));
    assert!(report.tuple_leaf_mode_ok);
    assert!(report.tuple_leaf_shape_ok);
    assert!(report.rlc_soundness_ok);
    assert!(!report.full_ok);
    assert!(!profile_meets_native_accumulator_authority_full(&metadata));
    assert!(!report.full_accumulator_workload);
    assert!(report.smoke_profile);
    assert_eq!(report.logical_oracle_count, 3);
    assert_eq!(report.native_oracle_pcs_opening_count, 1);
    assert_eq!(
        report.rlc_batching_bits,
        Some(SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS)
    );
}

#[test]
fn symbt3_n7_full_authority_gate_rejects_smoke_profile() {
    let fixture = n7_fixture(1, 1);
    assert!(
        symbt3_native_accumulator_k6a_workload_adapter(
            Symbt3NativeAccumulatorK6aWorkloadAdapterInput::NativeN7Smoke {
                instance: &fixture.instance,
                proof: &fixture.proof,
            },
        )
        .is_none(),
        "N7 smoke proofs must not enter the full K6a N7b helper boundary"
    );

    let mut metadata = symbt3_native_accumulator_authority_profile_metadata(
        &fixture.instance,
        &fixture.proof.counters,
    );
    metadata.workload_kind = Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1;
    metadata.full_accumulator_workload = true;
    metadata.smoke_profile = false;
    metadata.semantic_profile_version =
        SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_MIN_SEMANTIC_PROFILE_VERSION;
    metadata.target_soundness_bits = SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS;
    metadata.soundness_bound_bits = SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS;
    metadata.rlc_repetition_count = 1;
    metadata.rlc_batching_bits_per_repetition = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
    metadata.total_rlc_batching_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
    metadata.rlc_batching_bits = Some(SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS);
    metadata.effective_soundness_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
    let report = symbt3_native_accumulator_authority_profile_report(&metadata);
    assert!(!report.full_ok);
    assert!(!profile_meets_native_accumulator_authority_full(&metadata));
    assert!(!report.rlc_soundness_ok);

    metadata.rlc_repetition_count = SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT;
    metadata.rlc_batching_bits_per_repetition =
        SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_BATCHING_BITS_PER_REPETITION;
    metadata.total_rlc_batching_bits = metadata
        .rlc_repetition_count
        .saturating_mul(metadata.rlc_batching_bits_per_repetition);
    metadata.rlc_batching_bits = Some(metadata.total_rlc_batching_bits);
    metadata.effective_soundness_bits = metadata.total_rlc_batching_bits;
    let report = symbt3_native_accumulator_authority_profile_report(&metadata);
    assert!(report.rlc_soundness_ok);
    assert!(report.workload_kind_ok);
    assert!(report.full_ok);
}

#[test]
fn symbt3_n7b_k6a_adapter_extracts_full_workload() {
    let fixture = k6a_adapter_fixture();
    let adapter = &fixture.adapter;
    assert_eq!(
        adapter.workload_kind,
        Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
    );
    assert!(adapter.full_accumulator_workload);
    assert!(!adapter.smoke_profile);
    assert_eq!(
        adapter.proof_kind,
        ProductProofKind::Symbt3AccumulatorNonZkIntegrity
    );
    assert_eq!(
        adapter.old_accumulator_digest,
        fixture.accumulator_instance.old_accumulator_digest
    );
    assert_eq!(
        adapter.new_accumulator_digest,
        fixture.accumulator_instance.new_accumulator_digest
    );
    assert_eq!(
        adapter.batch_size,
        fixture.accumulator_instance.batch_capacity as u64
    );
    assert_eq!(
        adapter.active_count,
        fixture.accumulator_instance.active_count as u64
    );
    assert_eq!(
        adapter.main_symbt3_proof_digest,
        symbt3_main_whir_proof_digest(&fixture.proof)
    );
    assert_eq!(adapter.main_whir_num_vars, fixture.proof.num_vars);
    assert_eq!(adapter.main_oracle_len, 1usize << fixture.proof.num_vars);
    assert_eq!(adapter.top_level_whir_proof_count, 1);
    assert_eq!(adapter.family_columnar_subproof_count, 0);
    assert_eq!(adapter.backend_table_count, 1);
    assert_eq!(adapter.accumulator_transition_claims, 1);
    assert!(symbt3_native_accumulator_k6a_workload_adapter_matches(
        adapter,
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
        &fixture.proof,
    ));

    let from_input = symbt3_native_accumulator_k6a_workload_adapter(
        Symbt3NativeAccumulatorK6aWorkloadAdapterInput::FullK6a {
            vk: &fixture.vk,
            profile: &fixture.profile,
            accumulator_instance: &fixture.accumulator_instance,
            proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            proof: &fixture.proof,
        },
    )
    .expect("verified K6a adapter input");
    assert_eq!(from_input, *adapter);

    let smoke = n7_fixture(1, 1);
    assert!(
        symbt3_native_accumulator_k6a_workload_adapter(
            Symbt3NativeAccumulatorK6aWorkloadAdapterInput::NativeN7Smoke {
                instance: &smoke.instance,
                proof: &smoke.proof,
            },
        )
        .is_none(),
        "synthetic N7 smoke inputs must not be coerced into K6a workload metadata"
    );

    let mut stale_adapter = adapter.clone();
    stale_adapter.main_symbt3_proof_digest = digest(b"stale-k6a-proof-digest");
    assert!(!symbt3_native_accumulator_k6a_workload_adapter_matches(
        &stale_adapter,
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
        &fixture.proof,
    ));

    let mut stale_adapter = adapter.clone();
    stale_adapter.old_accumulator_digest = digest(b"stale-k6a-old-accumulator");
    assert!(!symbt3_native_accumulator_k6a_workload_adapter_matches(
        &stale_adapter,
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
        &fixture.proof,
    ));

    let mut stale_instance = fixture.accumulator_instance.clone();
    stale_instance.new_accumulator_digest = digest(b"stale-k6a-new-accumulator");
    assert!(
        symbt3_native_accumulator_k6a_workload_adapter(
            Symbt3NativeAccumulatorK6aWorkloadAdapterInput::FullK6a {
                vk: &fixture.vk,
                profile: &fixture.profile,
                accumulator_instance: &stale_instance,
                proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                proof: &fixture.proof,
            },
        )
        .is_none(),
        "mismatched accumulator instance digests must reject"
    );

    let mut missing = Symbt3NativeAccumulatorK6aWorkloadAdapterParts::from(adapter);
    missing.main_symbt3_proof_digest = None;
    assert!(symbt3_native_accumulator_k6a_workload_adapter_from_parts(missing).is_none());
}

fn assert_honest_full_n7b_verifies(batch_size: usize) -> Symbt3N7bFullAuthorityProof {
    let fixture = k6a_adapter_fixture_with_batch_size(batch_size);
    let proof = prove_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.pk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &fixture.accumulator_witness,
    )
    .expect("full N7b proof");
    assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &proof,
    ));
    let counters = &proof.wrapper.counters;
    assert!(counters.full_accumulator_workload);
    assert!(!counters.smoke_profile);
    assert!(counters.native_multi_oracle);
    assert_eq!(counters.whir_instance_count, 1);
    assert_eq!(counters.root_count, 1);
    assert_eq!(counters.query_schedule_count, 1);
    assert_eq!(counters.transcript_count, 1);
    assert_eq!(counters.native_oracle_pcs_opening_count, 1);
    assert_eq!(
        counters.logical_oracle_count,
        2 + fixture.accumulator_instance.message_oracle_roots.len()
    );
    assert_eq!(counters.family_columnar_subproof_count, 0);
    assert_eq!(
        counters.rlc_repetition_count,
        SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
    );
    assert!(
        counters.effective_soundness_bits
            >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS
    );
    assert!(!counters.fallback_used);
    proof
}

#[test]
fn symbt3_n7b_full_helper_honest_k1_round1_verifies() {
    assert_honest_full_n7b_verifies(1);
}

#[test]
fn symbt3_n7b_full_helper_honest_k2_round1_verifies() {
    assert_honest_full_n7b_verifies(2);
}

#[test]
fn symbt3_n7b_actual_serialized_bytes_use_compact_pcs_and_match_accounting() {
    let fixture = k6a_adapter_fixture_with_batch_size(1);
    let mut proof = prove_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.pk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &fixture.accumulator_witness,
    )
    .expect("full N7b proof");
    assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &proof,
    ));

    let serialized =
        symbt3_n7b_full_authority_proof_canonical_bytes(&proof).expect("N7b proof canonical bytes");
    let sections = symbt3_n7b_full_authority_proof_byte_sections(&proof);
    assert_eq!(serialized.len(), sections.total_bytes);
    assert_eq!(
        serialized.len(),
        symbt3_n7b_full_authority_proof_size_hint(&proof)
    );

    let compact_pcs =
        whir_pcs_compact_canonical_bytes(&proof.wrapper.native_tuple_leaf.proof.whir_pcs_proof)
            .expect("compact tuple PCS payload");
    assert!(
        serialized
            .windows(compact_pcs.len())
            .any(|window| window == compact_pcs.as_slice()),
        "actual N7b serialized bytes must contain the compact PCS payload"
    );

    let decoded_pcs =
        whir_pcs_from_compact_canonical_bytes(&compact_pcs).expect("decode compact PCS");
    assert_eq!(
        serde_json::to_value(&decoded_pcs).expect("decoded PCS JSON"),
        serde_json::to_value(&proof.wrapper.native_tuple_leaf.proof.whir_pcs_proof)
            .expect("original PCS JSON")
    );
    proof.wrapper.native_tuple_leaf.proof.whir_pcs_proof = decoded_pcs;
    assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &proof,
    ));
}

fn refresh_symbt3_n8_claim_plan_for_test(plan: &mut IntegratedK6aNativeClaimPlanV1) {
    plan.combined_logical_oracle_descriptor_digest =
        symbt3_n8_integrated_logical_oracle_descriptors_digest(&plan.logical_oracle_descriptors);
    plan.combined_constraint_descriptor_digest =
        symbt3_n8_integrated_constraint_descriptors_digest(&plan.constraint_descriptors);
    plan.combined_claim_descriptor_digest =
        symbt3_n8_integrated_claim_descriptors_digest(&plan.claim_descriptors);
    plan.claim_plan_digest = symbt3_n8_integrated_claim_plan_digest(plan);
}

fn refresh_symbt3_n8_committed_table_for_test(table: &mut IntegratedK6aNativeCommittedTableV1) {
    table.layout_digest = symbt3_n8_integrated_committed_table_layout_digest(table);
    table.table_digest = symbt3_n8_integrated_committed_table_digest(table);
    table.counters.layout_digest = table.layout_digest;
    table.counters.table_digest = table.table_digest;
}

fn refresh_symbt3_n8_real_evaluator_for_test(evaluator: &mut RealIntegratedK6aNativeEvaluatorV1) {
    evaluator.rows_digest = n8_integrated_evaluator_rows_digest(&evaluator.rows);
    evaluator.table_digest =
        n8_integrated_evaluator_table_digest(evaluator).expect("real evaluator table digest");
    evaluator.evaluator_digest = n8_integrated_evaluator_digest(evaluator);
}

fn refresh_symbt3_n8_k6a_semantic_constraints_for_test(
    constraints: &mut N8IntegratedK6aSemanticConstraintsV1,
) {
    constraints.rows_digest = n8_integrated_k6a_semantic_rows_digest(&constraints.rows);
}

fn refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
    constraints: &mut N8IntegratedTupleRlcSemanticConstraintsV1,
) {
    constraints.rows_digest = n8_integrated_tuple_rlc_semantic_rows_digest(&constraints.rows);
    constraints.descriptor_digest = n8_integrated_tuple_rlc_semantic_descriptor_digest(constraints);
}

fn refresh_symbt3_n8_descriptor_for_test(descriptor: &mut Symbt3IntegratedK6aNativeWhirRelationV1) {
    refresh_symbt3_n8_claim_plan_for_test(&mut descriptor.claim_plan);
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(descriptor);
}

fn semantic_n8_descriptor_fixture_for_test() -> (
    K6aAdapterFixture,
    Symbt3N7bFullAuthorityProof,
    Symbt3IntegratedK6aNativeWhirRelationV1,
) {
    let fixture = k6a_adapter_fixture_with_batch_size(1);
    let proof = prove_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.pk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &fixture.accumulator_witness,
    )
    .expect("full N7b proof");
    assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &proof,
    ));
    let relation = symbt3_k6a_relation_from_context(
        fixture
            .vk
            .relation
            .context
            .as_ref()
            .expect("K6a relation context"),
    )
    .expect("K6a relation decodes");
    let statement = fixture.accumulator_instance.to_public_statement();
    let descriptor =
        build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_with_k6a_semantics(
            &fixture.pk.seed,
            &relation,
            &statement,
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor with K6a semantics builds");
    (fixture, proof, descriptor)
}

fn direct_semantic_n8_descriptor_for_test(
    batch_size: usize,
) -> (
    K6aAdapterFixture,
    N8DirectSemanticInputsV1,
    Symbt3IntegratedK6aNativeWhirRelationV1,
) {
    let fixture = k6a_adapter_fixture_with_batch_size(batch_size);
    let inputs = build_n8_semantic_inputs_from_k6a_witness(
        &fixture.pk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &fixture.accumulator_witness,
    )
    .expect("direct N8 semantic inputs");
    let descriptor =
        build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_from_semantic_inputs(
            &inputs,
        )
        .expect("direct N8 descriptor");
    (fixture, inputs, descriptor)
}

struct N8AccumulationApiFixture {
    fixture: K6aAdapterFixture,
    batch: Symbt3AccumulationBatch,
    old_accumulator: Symbt3AccumulatorObject,
    new_accumulator: Symbt3AccumulatorObject,
    proof: Symbt3AccumulationProof,
}

fn n8_accumulation_api_fixture(batch_size: usize) -> N8AccumulationApiFixture {
    let fixture = k6a_adapter_fixture_with_batch_size(batch_size);
    let batch = Symbt3AccumulationBatch::from_accumulator_instance(
        fixture.profile.clone(),
        &fixture.accumulator_instance,
    );
    let old_public = Symbt3AccumulatorPublicInstance::from_old_public_statement(
        fixture.accumulator_instance.profile_digest,
        &batch.public_statement,
    );
    let old_accumulator = Symbt3AccumulatorObject::from_public_instance(old_public);
    let (new_accumulator, proof) = accumulate_symbt3_n8_non_zk(
        &fixture.pk,
        &batch,
        &old_accumulator,
        &fixture.accumulator_witness,
    )
    .expect("N8 accumulation API prover");
    N8AccumulationApiFixture {
        fixture,
        batch,
        old_accumulator,
        new_accumulator,
        proof,
    }
}

fn retarget_n8_batch_to_old_accumulator(
    pk: &WhirProvingKey,
    batch: &mut Symbt3AccumulationBatch,
    old_public: &Symbt3AccumulatorPublicInstance,
) {
    let relation = symbt3_k6a_relation_from_context(
        pk.relation
            .context
            .as_ref()
            .expect("SYMBT3 relation context"),
    )
    .expect("SYMBT3 relation");
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    batch.public_statement.old_accumulator_coordinates = old_public.accumulator_coordinates.clone();
    batch.public_statement.old_accumulator_digest = symbt3_accumulator_coordinates_digest(
        scheme,
        b"old",
        &batch.public_statement.old_accumulator_coordinates,
    );
    batch.public_statement.new_accumulator_coordinates =
        symbt3_accumulator_transition_coordinates(&relation, &batch.public_statement)
            .expect("retargeted accumulator transition");
    batch.public_statement.new_accumulator_digest = symbt3_accumulator_coordinates_digest(
        scheme,
        b"new",
        &batch.public_statement.new_accumulator_coordinates,
    );
}

fn n8_accumulation_api_nontrivial_fixture(batch_size: usize) -> N8AccumulationApiFixture {
    let fixture = k6a_adapter_fixture_with_batch_size(batch_size);
    for shift in 1..=8 {
        let mut batch = Symbt3AccumulationBatch::from_accumulator_instance(
            fixture.profile.clone(),
            &fixture.accumulator_instance,
        );
        let mut old_public = Symbt3AccumulatorPublicInstance::from_old_public_statement(
            fixture.accumulator_instance.profile_digest,
            &batch.public_statement,
        );
        old_public.accumulator_coordinates[0] += shift;
        old_public.accumulator_digest = symbt3_accumulator_coordinates_digest(
            PublicDigestScheme::Poseidon2BabyBear,
            b"state",
            &old_public.accumulator_coordinates,
        );
        retarget_n8_batch_to_old_accumulator(&fixture.pk, &mut batch, &old_public);
        let old_accumulator = Symbt3AccumulatorObject::from_public_instance(old_public);
        let Ok((new_accumulator, proof)) = accumulate_symbt3_n8_non_zk(
            &fixture.pk,
            &batch,
            &old_accumulator,
            &fixture.accumulator_witness,
        ) else {
            continue;
        };
        if old_accumulator.public_instance.accumulator_digest
            != new_accumulator.public_instance.accumulator_digest
        {
            return N8AccumulationApiFixture {
                fixture,
                batch,
                old_accumulator,
                new_accumulator,
                proof,
            };
        }
    }
    panic!("N8 fixture did not produce a nontrivial accumulator transition");
}

fn verify_n8_accumulation_fixture(
    fixture: &N8AccumulationApiFixture,
) -> Symbt3AccumulationVerificationReport {
    decide_symbt3_n8_accumulator_non_zk(
        Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1,
        &fixture.fixture.vk,
        &fixture.batch,
        &fixture.old_accumulator.public_instance,
        &fixture.new_accumulator.public_instance,
        &fixture.proof,
    )
}

fn assert_n8_accumulation_rejects(report: Symbt3AccumulationVerificationReport) {
    assert!(!report.ok);
    assert!(report.blocked);
    assert!(report.blocker.is_some());
}

fn assert_n8_accumulation_rejects_named(
    name: &'static str,
    report: Symbt3AccumulationVerificationReport,
) {
    assert!(
        !report.ok,
        "N8 accumulation accepted unexpected case {name}: {report:?}"
    );
    assert!(report.blocked, "N8 accumulation was not blocked for {name}");
    assert!(
        report.blocker.is_some(),
        "N8 accumulation blocker missing for {name}"
    );
}

fn decide_n8_accumulation_fixture_with_proof(
    fixture: &N8AccumulationApiFixture,
    proof: &Symbt3AccumulationProof,
) -> Symbt3AccumulationVerificationReport {
    decide_symbt3_n8_accumulator_non_zk(
        Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1,
        &fixture.fixture.vk,
        &fixture.batch,
        &fixture.old_accumulator.public_instance,
        &fixture.new_accumulator.public_instance,
        proof,
    )
}

fn mutate_first_i64(values: &mut Vec<i64>) {
    if let Some(value) = values.first_mut() {
        *value += 1;
    } else {
        values.push(1);
    }
}

fn mutate_first_nested_i64(values: &mut Vec<Vec<i64>>) {
    if let Some(row) = values.first_mut() {
        mutate_first_i64(row);
    } else {
        values.push(vec![1]);
    }
}

fn mutate_first_digest(values: &mut Vec<Digest32>, label: &'static [u8]) {
    if let Some(value) = values.first_mut() {
        *value = digest(label);
    } else {
        values.push(digest(label));
    }
}

fn assert_n8_accumulation_accepts(batch_size: usize) -> N8AccumulationApiFixture {
    let fixture = n8_accumulation_api_fixture(batch_size);
    let report = verify_n8_accumulation_fixture(&fixture);
    assert!(report.ok);
    assert!(!report.blocked);
    assert_eq!(report.blocker, None);
    assert!(report.semantic_completion.all_complete());
    assert_eq!(
        Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1.version(),
        SYMBT3_ACCUMULATION_AUTHORITY_PROFILE_VERSION
    );
    assert_eq!(fixture.proof.version, SYMBT3_N8_ACCUMULATION_PROOF_VERSION);
    assert_eq!(
        fixture.proof.output.version,
        N8_INTEGRATED_WHIR_PROVER_OUTPUT_VERSION
    );
    assert_eq!(
        fixture.proof.old_accumulator_digest,
        fixture.batch.public_statement.old_accumulator_digest
    );
    assert_eq!(
        fixture
            .old_accumulator
            .public_instance
            .accumulator_coordinates,
        fixture.batch.public_statement.old_accumulator_coordinates
    );
    assert_eq!(
        fixture.proof.new_accumulator_digest,
        fixture.batch.public_statement.new_accumulator_digest
    );
    assert_eq!(
        fixture
            .new_accumulator
            .public_instance
            .accumulator_coordinates,
        fixture.batch.public_statement.new_accumulator_coordinates
    );
    assert_eq!(
        fixture.proof.batch_size,
        fixture.batch.public_statement.batch_capacity as u64
    );
    assert_eq!(
        fixture.proof.active_count,
        fixture.batch.public_statement.active_count as u64
    );
    assert_eq!(fixture.proof.output.counters.whir_instance_count, 1);
    assert_eq!(fixture.proof.output.counters.root_count, 1);
    assert_eq!(fixture.proof.output.counters.query_schedule_count, 1);
    assert_eq!(fixture.proof.output.counters.tuple_pcs_proof_count, 0);
    assert!(
        !fixture
            .proof
            .output
            .counters
            .delegated_split_proof_material_present
    );
    assert!(!fixture.proof.output.counters.synthetic_non_authoritative);
    assert_eq!(
        fixture.old_accumulator.public_instance.canonical_bytes(),
        fixture.old_accumulator.public_instance.canonical_bytes()
    );
    assert_eq!(
        fixture.batch.canonical_bytes(),
        fixture.batch.canonical_bytes()
    );
    assert_eq!(
        fixture.new_accumulator.canonical_bytes(),
        fixture.new_accumulator.canonical_bytes()
    );
    assert_eq!(
        fixture.proof.canonical_bytes(),
        fixture.proof.canonical_bytes()
    );
    assert_ne!(fixture.proof.proof_digest(), [0u8; 32]);
    fixture
}

fn n8_successor_batch(
    fixture: &N8AccumulationApiFixture,
    old_accumulator_public: &Symbt3AccumulatorPublicInstance,
) -> Symbt3AccumulationBatch {
    let mut batch = fixture.batch.clone();
    retarget_n8_batch_to_old_accumulator(&fixture.fixture.pk, &mut batch, old_accumulator_public);
    batch
}

#[test]
fn symbt3_n8_accumulation_api_honest_k1_verifies() {
    assert_n8_accumulation_accepts(1);
}

#[test]
fn symbt3_n8_accumulation_api_honest_k2_verifies() {
    assert_n8_accumulation_accepts(2);
}

#[test]
fn symbt3_n8_accumulation_api_honest_k4_verifies() {
    assert_n8_accumulation_accepts(4);
}

#[test]
fn symbt3_n8_authoritative_decider_accepts_opt_in_profile_only() {
    let fixture = n8_accumulation_api_fixture(1);
    let report = decide_symbt3_n8_accumulator_non_zk(
        Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1,
        &fixture.fixture.vk,
        &fixture.batch,
        &fixture.old_accumulator.public_instance,
        &fixture.new_accumulator.public_instance,
        &fixture.proof,
    );
    assert!(report.ok);
    assert_eq!(
        Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1.canonical_bytes(),
        Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1.canonical_bytes()
    );
}

#[test]
fn symbt3_n8_accumulation_public_instance_mutation_matrix_rejects() {
    type InstanceMutation = (&'static str, fn(&mut Symbt3AccumulatorPublicInstance));
    let cases: &[InstanceMutation] = &[
        ("profile_digest", |instance| {
            instance.profile_digest = digest(b"n8-mutated-profile-digest")
        }),
        ("shape_id", |instance| {
            instance.shape_id = digest(b"n8-mutated-shape-id")
        }),
        ("accumulator_digest", |instance| {
            instance.accumulator_digest = digest(b"n8-mutated-accumulator-digest")
        }),
        ("accumulator_coordinates", |instance| {
            mutate_first_i64(&mut instance.accumulator_coordinates)
        }),
    ];

    let fixture = n8_accumulation_api_fixture(1);
    for (name, mutate) in cases {
        let mut old_public = fixture.old_accumulator.public_instance.clone();
        mutate(&mut old_public);
        assert_n8_accumulation_rejects(decide_symbt3_n8_accumulator_non_zk(
            Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1,
            &fixture.fixture.vk,
            &fixture.batch,
            &old_public,
            &fixture.new_accumulator.public_instance,
            &fixture.proof,
        ));

        let mut new_public = fixture.new_accumulator.public_instance.clone();
        mutate(&mut new_public);
        let report = decide_symbt3_n8_accumulator_non_zk(
            Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1,
            &fixture.fixture.vk,
            &fixture.batch,
            &fixture.old_accumulator.public_instance,
            &new_public,
            &fixture.proof,
        );
        assert!(
            !report.ok,
            "N8 authoritative route accepted mutated accumulator public field {name}"
        );
    }
}

#[test]
fn symbt3_n8_accumulation_public_batch_mutation_matrix_rejects() {
    type BatchMutation = (&'static str, fn(&mut Symbt3AccumulationBatch));
    let cases: &[BatchMutation] = &[
        ("profile", |batch| {
            batch.profile.relation_id = digest(b"n8-mutated-profile")
        }),
        ("shape_id", |batch| {
            batch.public_statement.shape_id = digest(b"n8-mutated-shape-id")
        }),
        ("batch_capacity", |batch| {
            batch.public_statement.batch_capacity += 1
        }),
        ("active_count", |batch| {
            batch.public_statement.active_count += 1
        }),
        ("old_accumulator_digest", |batch| {
            batch.public_statement.old_accumulator_digest = digest(b"n8-mutated-old-digest")
        }),
        ("new_accumulator_digest", |batch| {
            batch.public_statement.new_accumulator_digest = digest(b"n8-mutated-new-digest")
        }),
        ("old_accumulator_coordinates", |batch| {
            mutate_first_i64(&mut batch.public_statement.old_accumulator_coordinates)
        }),
        ("new_accumulator_coordinates", |batch| {
            mutate_first_i64(&mut batch.public_statement.new_accumulator_coordinates)
        }),
        ("input_public_boundary_digest", |batch| {
            batch.public_statement.input_public_boundary_digest =
                digest(b"n8-mutated-input-public-boundary")
        }),
        ("batch_manifest_root", |batch| {
            batch.public_statement.batch_manifest_root = digest(b"n8-mutated-batch-manifest-root")
        }),
        ("manifest_oracle_root", |batch| {
            batch.public_statement.manifest_oracle_root = digest(b"n8-mutated-manifest-root")
        }),
        ("manifest_eval_claim", |batch| {
            batch.public_statement.manifest_eval_claim =
                batch.public_statement.manifest_eval_claim.wrapping_add(1)
        }),
        ("batch_manifest_layout_digest", |batch| {
            batch.public_statement.batch_manifest_layout_digest =
                digest(b"n8-mutated-batch-manifest-layout")
        }),
        ("source_column_layout_digest", |batch| {
            batch.public_statement.source_column_layout_digest =
                digest(b"n8-mutated-source-column-layout")
        }),
        ("message_semantic_layout_digest", |batch| {
            batch.public_statement.message_semantic_layout_digest =
                digest(b"n8-mutated-message-semantic-layout")
        }),
        ("production_norm_range_layout_digest", |batch| {
            batch.public_statement.production_norm_range_layout_digest =
                digest(b"n8-mutated-production-norm-layout")
        }),
        ("structured_projection_layout_digest", |batch| {
            batch.public_statement.structured_projection_layout_digest =
                digest(b"n8-mutated-projection-layout")
        }),
        ("monomial_embedding_layout_digest", |batch| {
            batch.public_statement.monomial_embedding_layout_digest =
                digest(b"n8-mutated-monomial-layout")
        }),
        ("representative_layout_digest", |batch| {
            batch.public_statement.representative_layout_digest =
                digest(b"n8-mutated-representative-layout")
        }),
        ("norm_range_public_digest", |batch| {
            batch.public_statement.norm_range_public_digest =
                digest(b"n8-mutated-norm-range-public")
        }),
        ("input_public_values", |batch| {
            mutate_first_nested_i64(&mut batch.public_statement.input_public_values)
        }),
        ("input_commitment_values", |batch| {
            mutate_first_nested_i64(&mut batch.public_statement.input_commitment_values)
        }),
        ("input_evaluation_values", |batch| {
            mutate_first_nested_i64(&mut batch.public_statement.input_evaluation_values)
        }),
        ("input_accumulator_values", |batch| {
            mutate_first_nested_i64(&mut batch.public_statement.input_accumulator_values)
        }),
        ("source_assignment_roots", |batch| {
            mutate_first_digest(
                &mut batch.public_statement.source_assignment_roots,
                b"n8-mutated-source-assignment-root",
            )
        }),
        ("source_assignment_boundary_digest", |batch| {
            batch.public_statement.source_assignment_boundary_digest =
                digest(b"n8-mutated-source-assignment-boundary")
        }),
        ("source_ajtai_opening_roots", |batch| {
            mutate_first_digest(
                &mut batch.public_statement.source_ajtai_opening_roots,
                b"n8-mutated-source-ajtai-root",
            )
        }),
        ("source_ajtai_commitment_boundary_digest", |batch| {
            batch
                .public_statement
                .source_ajtai_commitment_boundary_digest =
                digest(b"n8-mutated-source-ajtai-boundary")
        }),
        ("message_oracle_roots", |batch| {
            mutate_first_digest(
                &mut batch.public_statement.message_oracle_roots,
                b"n8-mutated-message-oracle-root",
            )
        }),
        ("folded_public_input", |batch| {
            mutate_first_i64(&mut batch.public_statement.folded_public_input)
        }),
        ("folded_commitment", |batch| {
            mutate_first_i64(&mut batch.public_statement.folded_commitment)
        }),
        ("folded_evaluation", |batch| {
            mutate_first_i64(&mut batch.public_statement.folded_evaluation)
        }),
        ("folded_accumulator_coordinates", |batch| {
            mutate_first_i64(&mut batch.public_statement.folded_accumulator_coordinates)
        }),
        ("folded_ajtai_opening_root", |batch| {
            batch.public_statement.folded_ajtai_opening_root =
                digest(b"n8-mutated-folded-ajtai-root")
        }),
        ("folded_ajtai_commitment", |batch| {
            mutate_first_i64(&mut batch.public_statement.folded_ajtai_commitment)
        }),
        ("folded_gr1cs_boundary_digest", |batch| {
            batch.public_statement.folded_gr1cs_boundary_digest =
                digest(b"n8-mutated-folded-gr1cs-boundary")
        }),
        ("ring_module_layout_digest", |batch| {
            batch.public_statement.ring_module_layout_digest =
                digest(b"n8-mutated-ring-module-layout")
        }),
        ("ajtai_commit_layout_digest", |batch| {
            batch.public_statement.ajtai_commit_layout_digest =
                digest(b"n8-mutated-ajtai-commit-layout")
        }),
        ("r1cs_evaluator_layout_digest", |batch| {
            batch.public_statement.r1cs_evaluator_layout_digest =
                digest(b"n8-mutated-r1cs-evaluator-layout")
        }),
        ("gr1cs_residual_layout_digest", |batch| {
            batch.public_statement.gr1cs_residual_layout_digest =
                digest(b"n8-mutated-gr1cs-residual-layout")
        }),
        ("algebra_law_digest", |batch| {
            batch.public_statement.algebra_law_digest = digest(b"n8-mutated-algebra-law")
        }),
        ("ajtai_linear_algebra_layout_digest", |batch| {
            batch.public_statement.ajtai_linear_algebra_layout_digest =
                digest(b"n8-mutated-ajtai-linear-layout")
        }),
        ("ajtai_norm_range_layout_digest", |batch| {
            batch.public_statement.ajtai_norm_range_layout_digest =
                digest(b"n8-mutated-ajtai-norm-layout")
        }),
        ("projection_layout_digest", |batch| {
            batch.public_statement.projection_layout_digest =
                digest(b"n8-mutated-projection-layout")
        }),
        ("range_layout_digest", |batch| {
            batch.public_statement.range_layout_digest = digest(b"n8-mutated-range-layout")
        }),
        ("folded_gr1cs_product_residual_layout_digest", |batch| {
            batch
                .public_statement
                .folded_gr1cs_product_residual_layout_digest =
                digest(b"n8-mutated-product-residual-layout")
        }),
        ("folded_output_accumulator_root", |batch| {
            batch.public_statement.folded_output_accumulator_root =
                digest(b"n8-mutated-folded-output-root")
        }),
        ("whir_parameter_digest", |batch| {
            batch.public_statement.whir_parameter_digest = digest(b"n8-mutated-whir-params")
        }),
    ];

    let fixture = n8_accumulation_api_fixture(1);
    for (name, mutate) in cases {
        let mut batch = fixture.batch.clone();
        mutate(&mut batch);
        let report = decide_symbt3_n8_accumulator_non_zk(
            Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1,
            &fixture.fixture.vk,
            &batch,
            &fixture.old_accumulator.public_instance,
            &fixture.new_accumulator.public_instance,
            &fixture.proof,
        );
        assert!(
            !report.ok,
            "N8 authoritative route accepted mutated public batch field {name}"
        );
    }
}

#[test]
fn symbt3_n8_accumulation_proof_mutation_matrix_rejects() {
    type ProofMutation = (&'static str, fn(&mut Symbt3AccumulationProof));
    let cases: &[ProofMutation] = &[
        ("version", |proof| proof.version += 1),
        ("public_statement_digest", |proof| {
            proof.public_statement_digest = digest(b"n8-mutated-public-statement-digest")
        }),
        ("accumulator_instance_digest", |proof| {
            proof.accumulator_instance_digest = digest(b"n8-mutated-accumulator-instance-digest")
        }),
        ("old_accumulator_digest", |proof| {
            proof.old_accumulator_digest = digest(b"n8-mutated-proof-old")
        }),
        ("new_accumulator_digest", |proof| {
            proof.new_accumulator_digest = digest(b"n8-mutated-proof-new")
        }),
        ("batch_size", |proof| proof.batch_size += 1),
        ("active_count", |proof| proof.active_count += 1),
        ("k6a_relation_id", |proof| {
            proof.k6a_relation_id = digest(b"n8-mutated-k6a-relation")
        }),
        ("whir_param_digest", |proof| {
            proof.whir_param_digest = digest(b"n8-mutated-whir-param")
        }),
        ("tuple_leaf_root", |proof| {
            proof.tuple_leaf_root = digest(b"n8-mutated-tuple-root")
        }),
        ("tuple_leaf_layout_digest", |proof| {
            proof.tuple_leaf_layout_digest = digest(b"n8-mutated-tuple-layout")
        }),
        ("tuple_leaf_descriptor_digest", |proof| {
            proof.tuple_leaf_descriptor_digest = digest(b"n8-mutated-tuple-descriptor")
        }),
        ("native_oracle_descriptor_digest", |proof| {
            proof.native_oracle_descriptor_digest = digest(b"n8-mutated-native-descriptor")
        }),
        ("native_message_roots_digest", |proof| {
            proof.native_message_roots_digest = digest(b"n8-mutated-native-message-roots")
        }),
        ("n8_transcript_binding_digest", |proof| {
            proof.n8_transcript_binding_digest = digest(b"n8-mutated-transcript-binding")
        }),
        ("n8_claim_plan_digest", |proof| {
            proof.n8_claim_plan_digest = digest(b"n8-mutated-claim-plan")
        }),
        ("n8_committed_table_layout_digest", |proof| {
            proof.n8_committed_table_layout_digest = digest(b"n8-mutated-table-layout")
        }),
        ("n8_committed_table_digest", |proof| {
            proof.n8_committed_table_digest = digest(b"n8-mutated-table")
        }),
        ("semantic_completion", |proof| {
            proof.semantic_completion.transition_semantics_complete = false
        }),
        ("descriptor", |proof| {
            proof.descriptor.public_statement_digest = digest(b"n8-mutated-descriptor")
        }),
        ("output", |proof| proof.output.version += 1),
    ];

    let fixture = n8_accumulation_api_fixture(1);
    for (name, mutate) in cases {
        let mut proof = fixture.proof.clone();
        mutate(&mut proof);
        let report = decide_n8_accumulation_fixture_with_proof(&fixture, &proof);
        assert!(
            !report.ok,
            "N8 authoritative route accepted mutated proof field {name}"
        );
    }
}

#[test]
fn symbt3_n8_accumulation_wrong_versions_and_fallback_shapes_reject() {
    let fixture = n8_accumulation_api_fixture(1);

    let mut proof = fixture.proof.clone();
    proof.descriptor.version += 1;
    assert_eq!(
        decide_n8_accumulation_fixture_with_proof(&fixture, &proof).blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch)
    );

    let mut proof = fixture.proof.clone();
    proof.output.query_schedule.version += 1;
    assert_eq!(
        decide_n8_accumulation_fixture_with_proof(&fixture, &proof).blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch)
    );

    let mut proof = fixture.proof.clone();
    proof.output.counters.whir_instance_count = 0;
    proof.output.counters.root_count = 0;
    proof.output.counters.query_schedule_count = 0;
    assert_eq!(
        decide_n8_accumulation_fixture_with_proof(&fixture, &proof).blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing)
    );
}

#[test]
fn symbt3_n8_accumulation_api_multistep_replay_rejects() {
    let first = n8_accumulation_api_nontrivial_fixture(1);
    let second_batch = n8_successor_batch(&first, &first.new_accumulator.public_instance);
    let (second_new_accumulator, second_proof) = accumulate_symbt3_n8_non_zk(
        &first.fixture.pk,
        &second_batch,
        &first.new_accumulator,
        &first.fixture.accumulator_witness,
    )
    .expect("second N8 accumulation transition");

    assert!(verify_n8_accumulation_fixture(&first).ok);
    assert!(
        verify_symbt3_n8_accumulation_non_zk(
            &first.fixture.vk,
            &second_batch,
            &first.new_accumulator.public_instance,
            &second_new_accumulator.public_instance,
            &second_proof,
        )
        .ok
    );

    assert_n8_accumulation_rejects_named(
        "first proof as second transition",
        verify_symbt3_n8_accumulation_non_zk(
            &first.fixture.vk,
            &second_batch,
            &first.new_accumulator.public_instance,
            &second_new_accumulator.public_instance,
            &first.proof,
        ),
    );
    assert_n8_accumulation_rejects_named(
        "second proof as first transition",
        verify_symbt3_n8_accumulation_non_zk(
            &first.fixture.vk,
            &first.batch,
            &first.old_accumulator.public_instance,
            &first.new_accumulator.public_instance,
            &second_proof,
        ),
    );
    assert_n8_accumulation_rejects_named(
        "wrong old accumulator on second transition",
        verify_symbt3_n8_accumulation_non_zk(
            &first.fixture.vk,
            &second_batch,
            &first.old_accumulator.public_instance,
            &second_new_accumulator.public_instance,
            &second_proof,
        ),
    );
    assert_n8_accumulation_rejects_named(
        "wrong new accumulator on second transition",
        verify_symbt3_n8_accumulation_non_zk(
            &first.fixture.vk,
            &second_batch,
            &first.new_accumulator.public_instance,
            &first.new_accumulator.public_instance,
            &second_proof,
        ),
    );
}

#[test]
fn symbt3_n8_accumulation_api_old_accumulator_mutation_rejects() {
    let fixture = n8_accumulation_api_fixture(1);
    let mut old_public = fixture.old_accumulator.public_instance.clone();
    old_public.accumulator_digest = digest(b"mutated-old-accumulator");
    let report = verify_symbt3_n8_accumulation_non_zk(
        &fixture.fixture.vk,
        &fixture.batch,
        &old_public,
        &fixture.new_accumulator.public_instance,
        &fixture.proof,
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_accumulation_api_new_accumulator_mutation_rejects() {
    let fixture = n8_accumulation_api_fixture(1);
    let mut new_public = fixture.new_accumulator.public_instance.clone();
    new_public.accumulator_digest = digest(b"mutated-new-accumulator");
    let report = verify_symbt3_n8_accumulation_non_zk(
        &fixture.fixture.vk,
        &fixture.batch,
        &fixture.old_accumulator.public_instance,
        &new_public,
        &fixture.proof,
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_accumulation_api_malformed_accumulator_object_rejects() {
    let fixture = n8_accumulation_api_fixture(1);

    let mut old_public = fixture.old_accumulator.public_instance.clone();
    old_public.shape_id = digest(b"wrong-accumulator-shape");
    assert_n8_accumulation_rejects(verify_symbt3_n8_accumulation_non_zk(
        &fixture.fixture.vk,
        &fixture.batch,
        &old_public,
        &fixture.new_accumulator.public_instance,
        &fixture.proof,
    ));

    let mut new_public = fixture.new_accumulator.public_instance.clone();
    new_public.accumulator_coordinates[0] += 1;
    assert_n8_accumulation_rejects(verify_symbt3_n8_accumulation_non_zk(
        &fixture.fixture.vk,
        &fixture.batch,
        &fixture.old_accumulator.public_instance,
        &new_public,
        &fixture.proof,
    ));
}

#[test]
fn symbt3_n8_accumulation_api_batch_public_mutation_rejects() {
    let fixture = n8_accumulation_api_fixture(1);
    let mut batch = fixture.batch.clone();
    batch.public_statement.input_public_values[0][0] += 1;
    let report = verify_symbt3_n8_accumulation_non_zk(
        &fixture.fixture.vk,
        &batch,
        &fixture.old_accumulator.public_instance,
        &fixture.new_accumulator.public_instance,
        &fixture.proof,
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_accumulation_api_empty_public_batch_rejects() {
    let fixture = n8_accumulation_api_fixture(1);
    let mut batch = fixture.batch.clone();
    batch.public_statement.batch_capacity = 0;
    batch.public_statement.active_count = 0;
    assert_n8_accumulation_rejects(decide_symbt3_n8_accumulator_non_zk(
        Symbt3AccumulationAuthorityProfile::N8NonZkSameShapeV1,
        &fixture.fixture.vk,
        &batch,
        &fixture.old_accumulator.public_instance,
        &fixture.new_accumulator.public_instance,
        &fixture.proof,
    ));
}

#[test]
fn symbt3_n8_accumulation_api_active_count_and_batch_size_mismatch_reject() {
    let fixture = n8_accumulation_api_fixture(1);

    let mut proof = fixture.proof.clone();
    proof.active_count += 1;
    assert_eq!(
        verify_symbt3_n8_accumulation_non_zk(
            &fixture.fixture.vk,
            &fixture.batch,
            &fixture.old_accumulator.public_instance,
            &fixture.new_accumulator.public_instance,
            &proof,
        )
        .blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );

    let mut proof = fixture.proof.clone();
    proof.batch_size += 1;
    assert_eq!(
        verify_symbt3_n8_accumulation_non_zk(
            &fixture.fixture.vk,
            &fixture.batch,
            &fixture.old_accumulator.public_instance,
            &fixture.new_accumulator.public_instance,
            &proof,
        )
        .blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );

    let mut batch = fixture.batch.clone();
    batch.public_statement.active_count += 1;
    assert_n8_accumulation_rejects(verify_symbt3_n8_accumulation_non_zk(
        &fixture.fixture.vk,
        &batch,
        &fixture.old_accumulator.public_instance,
        &fixture.new_accumulator.public_instance,
        &fixture.proof,
    ));

    let mut batch = fixture.batch.clone();
    batch.public_statement.batch_capacity += 1;
    assert_n8_accumulation_rejects(verify_symbt3_n8_accumulation_non_zk(
        &fixture.fixture.vk,
        &batch,
        &fixture.old_accumulator.public_instance,
        &fixture.new_accumulator.public_instance,
        &fixture.proof,
    ));
}

#[test]
fn symbt3_n8_accumulation_api_witness_batch_mismatch_rejects() {
    let fixture = k6a_adapter_fixture_with_batch_size(1);
    let mismatched = k6a_adapter_fixture_with_batch_size(2);
    let batch = Symbt3AccumulationBatch::from_accumulator_instance(
        fixture.profile.clone(),
        &fixture.accumulator_instance,
    );
    let old_public = Symbt3AccumulatorPublicInstance::from_old_public_statement(
        fixture.accumulator_instance.profile_digest,
        &batch.public_statement,
    );
    let old_accumulator = Symbt3AccumulatorObject::from_public_instance(old_public);
    let result = accumulate_symbt3_n8_non_zk(
        &fixture.pk,
        &batch,
        &old_accumulator,
        &mismatched.accumulator_witness,
    );
    assert!(matches!(
        result,
        Err(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)
            | Err(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)
    ));
}

#[test]
fn symbt3_n8_accumulation_api_proof_replay_across_batches_rejects() {
    let source = n8_accumulation_api_fixture(1);
    let target = n8_accumulation_api_fixture(2);
    let report = verify_symbt3_n8_accumulation_non_zk(
        &target.fixture.vk,
        &target.batch,
        &target.old_accumulator.public_instance,
        &target.new_accumulator.public_instance,
        &source.proof,
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch)
    );
}

#[test]
fn symbt3_n8_accumulation_api_proof_old_new_digest_mutation_rejects() {
    let fixture = n8_accumulation_api_fixture(1);

    let mut proof = fixture.proof.clone();
    proof.old_accumulator_digest = digest(b"wrong-proof-old-accumulator");
    assert_eq!(
        verify_symbt3_n8_accumulation_non_zk(
            &fixture.fixture.vk,
            &fixture.batch,
            &fixture.old_accumulator.public_instance,
            &fixture.new_accumulator.public_instance,
            &proof,
        )
        .blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );

    let mut proof = fixture.proof.clone();
    proof.new_accumulator_digest = digest(b"wrong-proof-new-accumulator");
    assert_eq!(
        verify_symbt3_n8_accumulation_non_zk(
            &fixture.fixture.vk,
            &fixture.batch,
            &fixture.old_accumulator.public_instance,
            &fixture.new_accumulator.public_instance,
            &proof,
        )
        .blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_accumulation_api_rejects_n7b_proof_as_n8() {
    let api = n8_accumulation_api_fixture(1);
    let n7b = prove_symbt3_native_accumulator_authority_full_non_zk(
        &api.fixture.pk,
        &api.fixture.profile,
        &api.fixture.accumulator_instance,
        &api.fixture.accumulator_witness,
    )
    .expect("N7b full proof");
    let mut proof = api.proof.clone();
    proof.output.integrated_whir_proof = n7b.k6a_main_proof;
    assert_n8_accumulation_rejects(decide_n8_accumulation_fixture_with_proof(&api, &proof));
}

#[test]
fn symbt3_n8_accumulation_api_rejects_n7b_split_delegation_shape() {
    let api = n8_accumulation_api_fixture(1);
    let n7b = prove_symbt3_native_accumulator_authority_full_non_zk(
        &api.fixture.pk,
        &api.fixture.profile,
        &api.fixture.accumulator_instance,
        &api.fixture.accumulator_witness,
    )
    .expect("N7b split proof");
    assert_eq!(n7b.wrapper.counters.whir_instance_count, 1);

    let mut proof = api.proof.clone();
    proof.output.counters.tuple_pcs_proof_count = 1;
    proof.output.counters.delegated_split_proof_material_present = true;
    proof
        .output
        .proof_plan
        .delegated_split_proof_material_present = true;
    let report = decide_n8_accumulation_fixture_with_proof(&api, &proof);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
    );
}

#[test]
fn symbt3_n8_accumulation_api_rejects_smoke_proof_as_n8() {
    let api = n8_accumulation_api_fixture(1);
    let smoke = n7_fixture(1, 1);
    let mut proof = api.proof.clone();
    proof.output.integrated_whir_proof = smoke.proof.main_symbt3_whir_proof;
    assert_n8_accumulation_rejects(decide_n8_accumulation_fixture_with_proof(&api, &proof));
}

#[test]
fn symbt3_n8_accumulation_api_rejects_default_product_proof_as_n8() {
    let api = n8_accumulation_api_fixture(1);
    let mut proof = api.proof.clone();
    proof.output.integrated_whir_proof = api.fixture.proof.clone();
    assert_n8_accumulation_rejects(decide_n8_accumulation_fixture_with_proof(&api, &proof));
}

#[test]
fn symbt3_n8_accumulation_api_rejects_synthetic_n8_output() {
    let api = n8_accumulation_api_fixture(1);
    let plan = build_n8_integrated_whir_proof_plan(&N8IntegratedWhirProofInputs::from_descriptor(
        &api.proof.descriptor,
    ))
    .expect("N8 proof plan");
    let synthetic = prove_symbt3_synthetic_integrated_whir_from_claim_plan(
        &api.fixture.pk,
        &api.proof.descriptor,
        &plan,
    )
    .expect("synthetic N8 output");
    let proof = symbt3_n8_accumulation_proof_from_descriptor_output(
        api.proof.public_statement_digest,
        api.proof.accumulator_instance_digest,
        api.proof.descriptor.clone(),
        synthetic,
    );
    let report = decide_n8_accumulation_fixture_with_proof(&api, &proof);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SyntheticNonAuthoritativeOutput)
    );
}

#[test]
fn symbt3_n8_accumulation_api_wrong_digest_and_semantic_flags_reject() {
    let api = n8_accumulation_api_fixture(1);

    let mut proof = api.proof.clone();
    proof.tuple_leaf_root = digest(b"wrong-n8-tuple-root");
    let report = verify_symbt3_n8_accumulation_non_zk(
        &api.fixture.vk,
        &api.batch,
        &api.old_accumulator.public_instance,
        &api.new_accumulator.public_instance,
        &proof,
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );

    let mut proof = api.proof.clone();
    proof.semantic_completion.transition_semantics_complete = false;
    let report = verify_symbt3_n8_accumulation_non_zk(
        &api.fixture.vk,
        &api.batch,
        &api.old_accumulator.public_instance,
        &api.new_accumulator.public_instance,
        &proof,
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_accumulation_api_keeps_default_verify_public_routing_unchanged() {
    assert!(WhirSnark::has_authoritative_typed_cp());
    let api = assert_n8_accumulation_accepts(1);
    assert!(
        WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
            &api.fixture.vk,
            &api.fixture.profile,
            &api.fixture.accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &api.fixture.proof,
        )
    );
}

fn reference_n8_semantic_inputs_from_k6a_witness_for_test(
    pk: &WhirProvingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
) -> Option<N8DirectSemanticInputsV1> {
    let relation = symbt3_k6a_relation_from_context(pk.relation.context.as_ref()?)?;
    let statement =
        super::super::symbt3_accumulator_product_non_zk_integrity_statement_for_relation(
            profile,
            accumulator_instance,
            &relation,
        )?;
    let symbt3_witness = witness.to_symbt3_witness(&relation)?;
    let k6a_semantic_source = symbt3_n8_k6a_semantic_source_from_witness(
        &pk.seed,
        &relation,
        &statement,
        &symbt3_witness,
    )?;
    let k6a_adapter =
        symbt3_native_accumulator_k6a_workload_adapter_from_relation_statement_and_semantic_source(
            &relation,
            profile,
            accumulator_instance,
            &statement,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &k6a_semantic_source,
        )?;
    let native_tuple_leaf = build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness(
        pk,
        accumulator_instance,
        witness,
        &k6a_adapter,
    )?;
    Some(N8DirectSemanticInputsV1 {
        relation,
        statement,
        k6a_semantic_source,
        k6a_adapter,
        native_tuple_leaf,
        profile: N8DirectSemanticInputBuildProfileV1::default(),
    })
}

#[test]
fn symbt3_n8_optimized_direct_setup_matches_reference_direct_setup() {
    for batch_size in [1usize, 2] {
        let fixture = k6a_adapter_fixture_with_batch_size(batch_size);
        let optimized = build_n8_semantic_inputs_from_k6a_witness(
            &fixture.pk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
        )
        .expect("optimized direct N8 semantic inputs");
        let reference = reference_n8_semantic_inputs_from_k6a_witness_for_test(
            &fixture.pk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
        )
        .expect("reference direct N8 semantic inputs");

        assert_eq!(optimized.relation, reference.relation);
        assert_eq!(optimized.statement, reference.statement);
        assert_eq!(optimized.k6a_semantic_source, reference.k6a_semantic_source);
        assert_eq!(optimized.k6a_adapter, reference.k6a_adapter);
        assert_eq!(
            optimized.native_tuple_leaf.proof.packed_root,
            reference.native_tuple_leaf.proof.packed_root
        );
        assert_eq!(
            optimized.native_tuple_leaf.proof.logical_eval_claims,
            reference.native_tuple_leaf.proof.logical_eval_claims
        );
        assert_eq!(
            optimized.native_tuple_leaf.proof.packed_eval_claims,
            reference.native_tuple_leaf.proof.packed_eval_claims
        );
        assert_eq!(
            optimized.native_tuple_leaf.native_oracle_descriptor_digest,
            reference.native_tuple_leaf.native_oracle_descriptor_digest
        );
    }
}

fn assert_direct_n8_rows_match_source_proof_extraction(batch_size: usize) {
    let (fixture, direct_inputs, direct_descriptor) =
        direct_semantic_n8_descriptor_for_test(batch_size);
    let source_proof = prove_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.pk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &fixture.accumulator_witness,
    )
    .expect("reference N7b source proof");
    let source = symbt3_n8_k6a_semantic_source_from_proof(
        &fixture.pk.seed,
        &direct_inputs.relation,
        &direct_inputs.statement,
        &source_proof.k6a_main_proof,
    )
    .expect("source-proof-extracted K6a semantic material");
    assert_eq!(source, direct_inputs.k6a_semantic_source);
    let adapter = symbt3_native_accumulator_k6a_workload_adapter_from_relation_and_semantic_source(
        &direct_inputs.relation,
        &fixture.profile,
        &fixture.accumulator_instance,
        ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
        &source,
    )
    .expect("source-material adapter");
    let reference_inputs = N8DirectSemanticInputsV1 {
        relation: direct_inputs.relation.clone(),
        statement: direct_inputs.statement.clone(),
        k6a_semantic_source: source,
        k6a_adapter: adapter,
        native_tuple_leaf: source_proof.wrapper.native_tuple_leaf,
        profile: N8DirectSemanticInputBuildProfileV1::default(),
    };
    assert_eq!(
        reference_inputs.native_tuple_leaf.proof.packed_root,
        direct_inputs.native_tuple_leaf.proof.packed_root,
        "direct tuple root must match source-proof tuple root"
    );
    let reference_descriptor =
        build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_from_semantic_inputs(
            &reference_inputs,
        )
        .expect("reference descriptor from source proof material");
    assert_eq!(
        direct_descriptor.k6a_semantic_constraints.rows,
        reference_descriptor.k6a_semantic_constraints.rows
    );
    assert_eq!(
        direct_descriptor.tuple_rlc_semantic_constraints.rows,
        reference_descriptor.tuple_rlc_semantic_constraints.rows
    );
    assert_eq!(
        direct_descriptor
            .transition_binding_semantic_constraints
            .rows,
        reference_descriptor
            .transition_binding_semantic_constraints
            .rows
    );
    assert_eq!(
        direct_descriptor.real_evaluator.rows,
        reference_descriptor.real_evaluator.rows
    );
    assert_eq!(
        direct_descriptor.transcript_binding_digest,
        reference_descriptor.transcript_binding_digest
    );
}

#[test]
fn symbt3_n8_direct_builder_rows_match_source_proof_extracted_rows_k1() {
    assert_direct_n8_rows_match_source_proof_extraction(1);
}

#[test]
fn symbt3_n8_direct_builder_rows_match_source_proof_extracted_rows_k2() {
    assert_direct_n8_rows_match_source_proof_extraction(2);
}

#[test]
fn symbt3_n8_direct_builder_uses_claim_material_digest_not_k6a_proof_digest() {
    let (fixture, inputs, _descriptor) = direct_semantic_n8_descriptor_for_test(1);
    assert_eq!(
        inputs.k6a_adapter.main_symbt3_proof_digest,
        inputs.k6a_semantic_source.source_digest
    );
    assert_ne!(
        inputs.k6a_adapter.main_symbt3_proof_digest,
        symbt3_main_whir_proof_digest(&fixture.proof),
        "direct N8 must not bind the harness-built K6a proof digest"
    );
    assert_eq!(
        serde_json::to_value(&inputs.native_tuple_leaf.proof.whir_pcs_proof)
            .expect("direct tuple PCS placeholder serializes"),
        serde_json::to_value(WhirPcsProof::<F, EF, WhirMmcs>::default())
            .expect("default tuple PCS placeholder serializes")
    );
}

#[test]
fn symbt3_n8_direct_tuple_leaf_profiled_matches_unprofiled() {
    let (fixture, inputs, _descriptor) = direct_semantic_n8_descriptor_for_test(1);
    let unprofiled = build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness(
        &fixture.pk,
        &fixture.accumulator_instance,
        &fixture.accumulator_witness,
        &inputs.k6a_adapter,
    )
    .expect("unprofiled direct tuple leaf");
    let mut profile = N8DirectSemanticInputBuildProfileV1::default();
    let profiled = build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness_profiled(
        &fixture.pk,
        &fixture.accumulator_instance,
        &fixture.accumulator_witness,
        &inputs.k6a_adapter,
        Some(&mut profile),
    )
    .expect("profiled direct tuple leaf");

    assert_eq!(profiled.proof.packed_root, unprofiled.proof.packed_root);
    assert_eq!(
        profiled.proof.packed_root,
        inputs.native_tuple_leaf.proof.packed_root
    );
    assert_eq!(
        profiled.proof.packed_eval_claims,
        unprofiled.proof.packed_eval_claims
    );
    assert_eq!(
        profiled.proof.logical_eval_claims,
        unprofiled.proof.logical_eval_claims
    );
    assert_eq!(
        profiled.native_oracle_descriptor_digest,
        unprofiled.native_oracle_descriptor_digest
    );
    assert!(profile.tuple_rlc_input_ms == 0.0);
    assert!(profile.tuple_rlc_raw_values_ms >= 0.0);
    assert!(profile.tuple_rlc_descriptor_ms >= 0.0);
    assert!(profile.tuple_rlc_claims_ms >= 0.0);
    assert!(profile.tuple_rlc_packed_root_ms >= 0.0);
}

#[test]
fn symbt3_n8_root_only_commit_matches_full_empty_opening_proof_root() {
    let seed = [0x42u8; 32];
    let num_variables = 4;
    let evaluations = (0..(1usize << num_variables))
        .map(|value| BabyBear::from_u32((value as u32).wrapping_mul(17).wrapping_add(3)))
        .collect::<Vec<_>>();
    let root_only = whir_initial_root_digest(
        &seed,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        num_variables,
        &evaluations,
    )
    .expect("root-only WHIR commitment digest");
    let (proof, openings) = whir_commit_and_prove_multi(&seed, num_variables, &evaluations, &[]);
    assert!(openings.is_empty());
    let full_proof_root =
        whir_pcs_initial_root_digest(&proof, NativeOracleRootPolicy::CanonicalWhirRootV1)
            .expect("full WHIR proof root");
    assert_eq!(root_only, full_proof_root);
}

#[test]
fn symbt3_n8_root_only_tuple_leaf_is_not_standalone_verifier_authoritative() {
    let fixture = k6a_adapter_fixture_with_batch_size(1);
    let inputs = build_n8_semantic_inputs_from_k6a_witness(
        &fixture.pk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &fixture.accumulator_witness,
    )
    .expect("direct N8 semantic inputs");
    assert_eq!(
        serde_json::to_value(&inputs.native_tuple_leaf.proof.whir_pcs_proof)
            .expect("direct tuple PCS placeholder serializes"),
        serde_json::to_value(WhirPcsProof::<F, EF, WhirMmcs>::default())
            .expect("default tuple PCS placeholder serializes")
    );
    assert!(
            !whir_verify_same_domain_multi_oracle(
                &fixture.vk,
                inputs.k6a_adapter.main_symbt3_relation_id,
                inputs.k6a_adapter.public_statement_digest,
                inputs.k6a_adapter.whir_param_digest,
                &inputs.native_tuple_leaf.proof,
                &inputs.native_tuple_leaf.proof.logical_eval_claims,
            ),
            "N8's root-only tuple leaf is prover material for the integrated proof, not a standalone verifier proof"
        );
}

#[test]
fn symbt3_n8_direct_builder_authority_candidate_verifies() {
    let (fixture, _inputs, descriptor) = direct_semantic_n8_descriptor_for_test(1);
    let plan = build_n8_integrated_whir_proof_plan(&N8IntegratedWhirProofInputs::from_descriptor(
        &descriptor,
    ))
    .expect("direct N8 proof plan builds");
    let output = prove_symbt3_integrated_whir_from_claim_plan(&fixture.pk, &descriptor, &plan)
        .expect("direct N8 integrated output");
    let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &fixture.vk,
        &output.verifier_input(&descriptor),
    );
    assert!(backend_report.ok);
    let authority_report =
        verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
    assert!(authority_report.ok);
}

fn semantic_n8_output_fixture_for_test() -> (
    K6aAdapterFixture,
    Symbt3N7bFullAuthorityProof,
    Symbt3IntegratedK6aNativeWhirRelationV1,
    WhirVerifyingKey,
    N8IntegratedWhirProverOutput,
) {
    let (fixture, proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
    let plan = build_n8_integrated_whir_proof_plan(&N8IntegratedWhirProofInputs::from_descriptor(
        &descriptor,
    ))
    .expect("semantic N8 proof plan builds");
    let (pk, vk) = WhirSnark::setup(&relation());
    let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
        .expect("semantic integrated output");
    let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &output.verifier_input(&descriptor),
    );
    assert!(backend_report.ok);
    let authority_report =
        verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
    assert!(authority_report.ok);
    (fixture, proof, descriptor, vk, output)
}

fn assert_n8_transition_binding_semantic_mutation_rejects(
    mutate: impl FnOnce(&mut N8IntegratedTransitionBindingSemanticConstraintsV1),
) {
    let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
    mutate(&mut descriptor.transition_binding_semantic_constraints);
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
    );
}

fn refresh_symbt3_n8_table_descriptor_for_test(
    descriptor: &mut Symbt3IntegratedK6aNativeWhirRelationV1,
) {
    refresh_symbt3_n8_committed_table_for_test(&mut descriptor.committed_table);
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(descriptor);
}

fn refresh_symbt3_n8_evaluator_descriptor_for_test(
    descriptor: &mut Symbt3IntegratedK6aNativeWhirRelationV1,
) {
    refresh_symbt3_n8_real_evaluator_for_test(&mut descriptor.real_evaluator);
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(descriptor);
}

fn n8_integrated_plan_for_existing_proof_for_test(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    integrated_proof: &WhirProof,
) -> (Digest32, N8IntegratedWhirProofPlan) {
    let root = whir_pcs_initial_root_digest(
        &integrated_proof.whir_pcs_proof,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    )
    .expect("canonical integrated WHIR root");
    let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(descriptor);
    inputs.integrated_whir_root = Some(root);
    inputs.integrated_whir_proof = Some(integrated_proof);
    let plan = build_n8_integrated_whir_proof_plan(&inputs)
        .expect("N8 proof plan records integrated proof material");
    (root, plan)
}

fn assert_n8_real_evaluator_row_mutation_rejects(
    row_kind: RealIntegratedK6aNativeEvaluatorRowKindV1,
) {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let plan = build_n8_integrated_whir_proof_plan(&N8IntegratedWhirProofInputs::from_descriptor(
        &descriptor,
    ))
    .expect("N8 proof plan builds");
    let (pk, vk) = WhirSnark::setup(&relation());
    let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
        .expect("real integrated output");

    let mut mutated_descriptor = descriptor.clone();
    let row = mutated_descriptor
        .real_evaluator
        .rows
        .iter_mut()
        .find(|row| row.kind == row_kind)
        .expect("requested real evaluator row exists");
    row.value += BabyBear::ONE;
    refresh_symbt3_n8_evaluator_descriptor_for_test(&mut mutated_descriptor);

    let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&mutated_descriptor);
    inputs.integrated_whir_root = Some(output.integrated_whir_root);
    inputs.integrated_whir_proof = Some(&output.integrated_whir_proof);
    let mutated_plan =
        build_n8_integrated_whir_proof_plan(&inputs).expect("mutated descriptor proof plan builds");
    let mutated_schedule = build_n8_integrated_whir_query_schedule_for_claims(
        &mutated_plan,
        output.query_schedule.query_claims.clone(),
    );
    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &mutated_descriptor,
            &mutated_plan,
            Some(output.integrated_whir_root),
            Some(&output.integrated_whir_proof),
            Some(&mutated_schedule),
        ),
    );

    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch)
    );
}

#[test]
fn symbt3_n8_claim_plan_records_shapes_and_padding() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds from full N7b parts");
    let plan = &descriptor.claim_plan;
    let table = &descriptor.committed_table;

    assert_eq!(
        descriptor.version,
        SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_VERSION
    );
    assert_eq!(
        descriptor.workload_kind,
        Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
    );
    assert_eq!(
        plan.k6a_num_vars,
        proof.wrapper.k6a_adapter.main_whir_num_vars
    );
    assert_eq!(plan.k6a_oracle_len, 1usize << plan.k6a_num_vars);
    assert_eq!(
        plan.tuple_packed_oracle_len,
        1usize << plan.tuple_packed_num_vars
    );
    assert_eq!(
        plan.integrated_num_vars,
        plan.k6a_num_vars.max(plan.tuple_packed_num_vars)
    );
    assert_eq!(
        plan.integrated_oracle_len,
        1usize << plan.integrated_num_vars
    );
    assert_eq!(
        plan.k6a_padding_policy,
        symbt3_n8_k6a_padding_policy(plan.k6a_num_vars, plan.integrated_num_vars)
            .expect("deterministic K6a padding policy")
    );
    assert_eq!(
        plan.k6a_padding_policy.mode,
        if plan.k6a_num_vars == plan.integrated_num_vars {
            IntegratedK6aNativeK6aPaddingModeV1::NoPadding
        } else {
            IntegratedK6aNativeK6aPaddingModeV1::ZeroExtendRowsToIntegratedNumVars
        }
    );
    assert_eq!(
        plan.tuple_repetition_axis.repetition_axis_start,
        plan.tuple_logical_num_vars
    );
    assert_eq!(
        plan.tuple_repetition_axis.packed_num_vars,
        plan.tuple_packed_num_vars
    );
    assert_eq!(
        plan.tuple_repetition_axis.integrated_num_vars,
        plan.integrated_num_vars
    );
    assert!(descriptor.same_field);
    assert!(descriptor.same_rate);
    assert!(descriptor.same_folding_parameter);
    assert_eq!(plan.constraint_descriptors.len(), 3);
    assert_eq!(
        plan.constraint_descriptors[0].kind,
        Symbt3N8IntegratedConstraintKind::K6aAccumulatorMainV1
    );
    assert_eq!(
        plan.constraint_descriptors[1].kind,
        Symbt3N8IntegratedConstraintKind::NativeTupleLeafRepeatedRlcV1
    );
    assert_eq!(
        plan.constraint_descriptors[2].kind,
        Symbt3N8IntegratedConstraintKind::AccumulatorTransitionBindingV1
    );
    assert_eq!(
        plan.logical_oracle_descriptors.len(),
        2 + plan.tuple_logical_oracle_count
    );
    assert_eq!(plan.claim_descriptors.len(), 3);
    assert_eq!(table.plan_digest, plan.claim_plan_digest);
    assert_eq!(table.integrated_num_vars, plan.integrated_num_vars);
    assert_eq!(table.integrated_oracle_len, plan.integrated_oracle_len);
    assert_eq!(
        table.counters.k6a_padded_rows,
        plan.k6a_padding_policy.padded_row_count
    );
    assert_eq!(table.counters.tuple_rows, plan.tuple_packed_oracle_len);
    assert_eq!(
        table.counters.combined_constraint_count,
        plan.constraint_descriptors.len()
    );
    assert_eq!(table.logical_integrated_oracle_count, 1);
    assert!(!table.one_oracle_per_batch_item_layout);
    assert_eq!(table.introduced_whir_root_count, 0);
    assert_eq!(table.introduced_whir_proof_count, 0);
    assert_eq!(
        table.layout_digest,
        symbt3_n8_integrated_committed_table_layout_digest(table)
    );
    assert_eq!(
        table.table_digest,
        symbt3_n8_integrated_committed_table_digest(table)
    );
    assert_ne!(descriptor.transcript_binding_digest, [0u8; 32]);
    assert_eq!(
        descriptor.transcript_binding_digest,
        symbt3_n8_integrated_transcript_binding_digest(&descriptor)
    );

    let rebuilt = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor rebuild");
    assert_eq!(
        plan.k6a_padding_policy,
        rebuilt.claim_plan.k6a_padding_policy
    );
    assert_eq!(plan.claim_plan_digest, rebuilt.claim_plan.claim_plan_digest);
    assert_eq!(table.table_digest, rebuilt.committed_table.table_digest);
    assert_eq!(table.layout_digest, rebuilt.committed_table.layout_digest);
    assert_eq!(
        descriptor.transcript_binding_digest,
        rebuilt.transcript_binding_digest
    );
}

#[test]
fn symbt3_n8_committed_table_mutations_reject() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let original_table_digest = descriptor.committed_table.table_digest;

    let rebuilt = build_integrated_k6a_native_committed_table_v1(&descriptor.claim_plan)
        .expect("N8 committed table rebuild");
    assert_eq!(descriptor.committed_table, rebuilt);

    let mut bad_padding = descriptor.clone();
    bad_padding
        .committed_table
        .k6a_padding_policy
        .padded_row_count += 1;
    refresh_symbt3_n8_table_descriptor_for_test(&mut bad_padding);
    assert_ne!(
        original_table_digest,
        bad_padding.committed_table.table_digest
    );
    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_padding);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::PaddingPolicyMismatch)
    );

    let mut bad_row_order = descriptor.clone();
    bad_row_order.committed_table.row_ownership.reverse();
    refresh_symbt3_n8_table_descriptor_for_test(&mut bad_row_order);
    assert_ne!(
        original_table_digest,
        bad_row_order.committed_table.table_digest
    );
    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_row_order);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::CommittedTableLayoutMismatch)
    );

    let mut bad_axis = descriptor.clone();
    bad_axis
        .committed_table
        .tuple_repetition_axis
        .repetition_axis_start += 1;
    refresh_symbt3_n8_table_descriptor_for_test(&mut bad_axis);
    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_axis);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)
    );

    let mut bad_integrated = descriptor.clone();
    bad_integrated.committed_table.integrated_num_vars += 1;
    bad_integrated.committed_table.integrated_oracle_len =
        1usize << bad_integrated.committed_table.integrated_num_vars;
    bad_integrated.committed_table.counters.integrated_num_vars =
        bad_integrated.committed_table.integrated_num_vars;
    bad_integrated
        .committed_table
        .counters
        .integrated_oracle_len = bad_integrated.committed_table.integrated_oracle_len;
    refresh_symbt3_n8_table_descriptor_for_test(&mut bad_integrated);
    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_integrated);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch)
    );
}

#[test]
fn symbt3_n8_descriptor_axis_and_integrated_shape_mutations_reject() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");

    let original_plan_digest = descriptor.claim_plan.claim_plan_digest;
    let mut mutated_descriptor = descriptor.clone();
    mutated_descriptor.claim_plan.constraint_descriptors[1].descriptor_digest =
        digest(b"symbt3-n8-mutated-tuple-constraint-descriptor");
    refresh_symbt3_n8_claim_plan_for_test(&mut mutated_descriptor.claim_plan);
    assert_ne!(
        original_plan_digest,
        mutated_descriptor.claim_plan.claim_plan_digest
    );

    let mut bad_axis = descriptor.clone();
    bad_axis
        .claim_plan
        .tuple_repetition_axis
        .repetition_axis_start += 1;
    refresh_symbt3_n8_descriptor_for_test(&mut bad_axis);
    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_axis);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)
    );

    let mut bad_integrated = descriptor.clone();
    bad_integrated.claim_plan.integrated_num_vars += 1;
    bad_integrated.claim_plan.integrated_oracle_len =
        1usize << bad_integrated.claim_plan.integrated_num_vars;
    bad_integrated.claim_plan.k6a_padding_policy = symbt3_n8_k6a_padding_policy(
        bad_integrated.claim_plan.k6a_num_vars,
        bad_integrated.claim_plan.integrated_num_vars,
    )
    .expect("mutated padding policy");
    bad_integrated.claim_plan.tuple_repetition_axis = symbt3_n8_tuple_repetition_axis_mapping(
        bad_integrated.claim_plan.tuple_logical_num_vars,
        bad_integrated.claim_plan.rlc_repetition_count,
        bad_integrated.claim_plan.integrated_num_vars,
    )
    .expect("mutated repetition axis");
    for logical_descriptor in &mut bad_integrated.claim_plan.logical_oracle_descriptors {
        logical_descriptor.integrated_num_vars = bad_integrated.claim_plan.integrated_num_vars;
    }
    for constraint_descriptor in &mut bad_integrated.claim_plan.constraint_descriptors {
        constraint_descriptor.integrated_num_vars = bad_integrated.claim_plan.integrated_num_vars;
        constraint_descriptor.integrated_oracle_len =
            bad_integrated.claim_plan.integrated_oracle_len;
    }
    refresh_symbt3_n8_descriptor_for_test(&mut bad_integrated);
    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_integrated);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch)
    );
}

#[test]
fn symbt3_n8_integrated_whir_plan_records_claim_bridge() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);

    let plan = build_n8_integrated_whir_proof_plan(&inputs).expect("N8 proof plan builds");

    assert_eq!(plan.version, N8_INTEGRATED_WHIR_PROOF_PLAN_VERSION);
    assert_eq!(
        plan.table_representation,
        N8IntegratedWhirTableRepresentationV1::SameDomainMultipleLogicalColumns
    );
    assert_eq!(plan.workload_kind, descriptor.workload_kind);
    assert_eq!(
        plan.descriptor_transcript_digest,
        descriptor.transcript_binding_digest
    );
    assert_eq!(
        plan.claim_plan_digest,
        descriptor.claim_plan.claim_plan_digest
    );
    assert_eq!(
        plan.committed_table_layout_digest,
        descriptor.committed_table.layout_digest
    );
    assert_eq!(
        plan.committed_table_digest,
        descriptor.committed_table.table_digest
    );
    assert_eq!(
        plan.integrated_num_vars,
        descriptor.claim_plan.integrated_num_vars
    );
    assert_eq!(
        plan.integrated_oracle_len,
        descriptor.claim_plan.integrated_oracle_len
    );
    assert_eq!(plan.integrated_whir_root_count, 0);
    assert_eq!(plan.integrated_whir_proof_count, 0);
    assert!(!plan.delegated_split_proof_material_present);
    assert_eq!(plan.bridge_claim_descriptors.len(), 3);
    assert_eq!(
        plan.bridge_claim_descriptors[0].kind,
        N8IntegratedWhirClaimBridgeKindV1::K6aAccumulatorConstraintsV1
    );
    assert_eq!(
        plan.bridge_claim_descriptors[1].kind,
        N8IntegratedWhirClaimBridgeKindV1::NativeTupleLeafRepeatedRlcConstraintsV1
    );
    assert_eq!(
        plan.bridge_claim_descriptors[2].kind,
        N8IntegratedWhirClaimBridgeKindV1::AccumulatorTransitionBindingConstraintsV1
    );
    assert_eq!(
        plan.combined_bridge_claim_descriptor_digest,
        n8_integrated_whir_claim_bridge_descriptors_digest(&plan.bridge_claim_descriptors)
    );
    assert_eq!(plan.semantic_batching.version, N8_SEMANTIC_BATCHING_VERSION);
    assert!(plan.semantic_batching.enabled);
    assert_eq!(
        plan.semantic_batching.descriptor_binding_digest,
        n8_semantic_batching_binding_digest(&descriptor)
    );
    assert_eq!(
        plan.semantic_batching.descriptor_digest,
        n8_semantic_batching_descriptor_digest(&plan.semantic_batching)
    );
    assert_ne!(plan.transcript_digest, [0u8; 32]);
    assert_eq!(
        plan.transcript_digest,
        n8_integrated_whir_proof_plan_transcript_digest(&plan)
    );
}

#[test]
fn symbt3_n8_real_evaluator_rows_are_deterministic() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let rebuilt = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor rebuilds");

    assert_eq!(descriptor.real_evaluator, rebuilt.real_evaluator);
    assert_eq!(
        descriptor.real_evaluator.counters.k6a_claim_rows,
        symbt3_n8_k6a_claim_row_count(&proof.k6a_main_proof)
    );
    assert_eq!(
        descriptor.real_evaluator.counters.tuple_claim_rows,
        proof
            .wrapper
            .native_tuple_leaf
            .proof
            .packed_eval_claims
            .len()
            + proof
                .wrapper
                .native_tuple_leaf
                .proof
                .logical_eval_claims
                .len()
            + proof
                .wrapper
                .native_tuple_leaf
                .proof
                .counters
                .rlc_repetition_count
    );
    assert_eq!(
        descriptor.real_evaluator.rows_digest,
        n8_integrated_evaluator_rows_digest(&descriptor.real_evaluator.rows)
    );
    assert_eq!(
        descriptor.real_evaluator.table_digest,
        n8_integrated_evaluator_table_digest(&descriptor.real_evaluator)
            .expect("real evaluator table digest")
    );
}

#[test]
fn symbt3_n8_semantic_rows_honest_pass_and_reach_authority_candidate() {
    let (_fixture, _proof, descriptor) = semantic_n8_descriptor_fixture_for_test();

    assert!(descriptor.k6a_semantic_constraints.complete);
    assert!(descriptor.tuple_rlc_semantic_constraints.complete);
    assert!(descriptor.transition_binding_semantic_constraints.complete);
    assert!(descriptor.semantic_completion.k6a_semantics_complete);
    assert!(descriptor.semantic_completion.tuple_rlc_semantics_complete);
    assert!(descriptor.semantic_completion.transition_semantics_complete);
    assert_eq!(
        descriptor.real_evaluator.counters.k6a_semantic_rows,
        descriptor.k6a_semantic_constraints.rows.len()
    );
    assert!(descriptor
        .k6a_semantic_constraints
        .rows
        .iter()
        .any(|row| row.kind == N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1));
    assert_eq!(
        descriptor.tuple_rlc_semantic_constraints.residual_row_count,
        descriptor.claim_plan.rlc_repetition_count
    );
    assert!(
        descriptor
            .tuple_rlc_semantic_constraints
            .rows
            .iter()
            .filter(|row| row.kind
                == N8IntegratedTupleRlcSemanticConstraintRowKindV1::RlcResidualZeroV1)
            .all(|row| row.value == BabyBear::ZERO)
    );
    assert_eq!(
        descriptor.real_evaluator.counters.transition_binding_rows,
        descriptor
            .transition_binding_semantic_constraints
            .rows
            .len()
    );
    assert!(descriptor
        .transition_binding_semantic_constraints
        .rows
        .iter()
        .all(|row| row.value == BabyBear::ZERO));

    let relation_report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(relation_report.ok);
    assert_eq!(relation_report.blocker, None);
    assert!(relation_report.semantic_completion.k6a_semantics_complete);
    assert!(
        relation_report
            .semantic_completion
            .tuple_rlc_semantics_complete
    );
    assert!(
        relation_report
            .semantic_completion
            .transition_semantics_complete
    );

    let plan = build_n8_integrated_whir_proof_plan(&N8IntegratedWhirProofInputs::from_descriptor(
        &descriptor,
    ))
    .expect("semantic N8 proof plan builds");
    let (pk, vk) = WhirSnark::setup(&relation());
    let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
        .expect("semantic integrated output");
    let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &output.verifier_input(&descriptor),
    );
    assert!(backend_report.ok);

    let authority_report =
        verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
    assert!(authority_report.ok);
    assert_eq!(authority_report.blocker, None);
    assert!(authority_report.semantic_completion.k6a_semantics_complete);
    assert!(
        authority_report
            .semantic_completion
            .tuple_rlc_semantics_complete
    );
    assert!(
        authority_report
            .semantic_completion
            .transition_semantics_complete
    );
}

#[test]
fn symbt3_n8_audit_semantic_output_is_one_proof_non_delegating() {
    let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
    let verifier_input = output.verifier_input(&descriptor);

    assert_eq!(output.counters.whir_instance_count, 1);
    assert_eq!(output.counters.root_count, 1);
    assert_eq!(output.counters.query_schedule_count, 1);
    assert_eq!(output.counters.tuple_pcs_proof_count, 0);
    assert!(!output.counters.delegated_split_proof_material_present);
    assert!(!output.counters.synthetic_non_authoritative);
    assert_eq!(output.proof_plan.integrated_whir_root_count, 1);
    assert_eq!(output.proof_plan.integrated_whir_proof_count, 1);
    assert_eq!(
        output.integrated_whir_proof.num_vars,
        output.proof_plan.integrated_num_vars
    );
    assert!(!output.integrated_whir_proof.is_output);
    assert!(output
        .integrated_whir_proof
        .family_columnar_subproofs
        .is_empty());
    assert!(verifier_input.legacy_k6a_proof.is_none());
    assert!(verifier_input.legacy_tuple_leaf_proof.is_none());
    assert_eq!(verifier_input.extra_whir_root_count, 0);
    assert_eq!(verifier_input.extra_whir_proof_count, 0);
    assert_eq!(
        output.query_schedule.transcript_digest,
        output.proof_plan.transcript_digest
    );
    assert_eq!(
        output.query_schedule.query_claims,
        n8_integrated_whir_real_query_claims(
            &descriptor.real_evaluator,
            &output.proof_plan.semantic_batching,
        )
        .expect("real query claims derive from integrated evaluator")
    );
}

#[test]
fn symbt3_n8_semantic_batching_challenges_are_domain_separated() {
    let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
    let batching = output.proof_plan.semantic_batching;

    assert_eq!(
        batching.descriptor_binding_digest,
        n8_semantic_batching_binding_digest(&descriptor)
    );
    assert!(batching.k6a_source.enabled);
    assert_ne!(
        batching.k6a_source.descriptor.challenge_point_digest,
        [0u8; 32]
    );
    assert_ne!(batching.k6a.challenge_point_digest, [0u8; 32]);
    assert_ne!(batching.tuple_rlc.challenge_point_digest, [0u8; 32]);
    assert_ne!(
        batching.transition_binding.challenge_point_digest,
        [0u8; 32]
    );
    assert_ne!(
        batching.k6a_source.descriptor.challenge_point_digest,
        batching.k6a.challenge_point_digest
    );
    assert_ne!(
        batching.k6a_source.descriptor.challenge_point_digest,
        batching.tuple_rlc.challenge_point_digest
    );
    assert_ne!(
        batching.k6a_source.descriptor.challenge_point_digest,
        batching.transition_binding.challenge_point_digest
    );
    assert_ne!(
        batching.k6a.challenge_point_digest,
        batching.tuple_rlc.challenge_point_digest
    );
    assert_ne!(
        batching.k6a.challenge_point_digest,
        batching.transition_binding.challenge_point_digest
    );
    assert_ne!(
        batching.tuple_rlc.challenge_point_digest,
        batching.transition_binding.challenge_point_digest
    );
    assert_eq!(
        batching.effective_soundness_bits,
        N8_SEMANTIC_BATCHING_CHALLENGE_SOUNDNESS_BITS
    );
}

#[test]
fn symbt3_n8_semantic_batching_reduces_opening_count() {
    let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
    let k6a_source_rows = descriptor
        .real_evaluator
        .rows
        .iter()
        .filter(|row| n8_integrated_evaluator_row_is_k6a_source(row))
        .count();
    let batching = output.proof_plan.semantic_batching;
    assert_eq!(
        batching.k6a_source.unbatched_source_opening_count,
        k6a_source_rows
    );
    assert_eq!(batching.k6a_source.batched_source_opening_count, 1);
    let expected_openings = batching
        .k6a_source
        .batched_source_opening_count
        .saturating_add(batching.k6a.batched_query_count)
        .saturating_add(batching.tuple_rlc.batched_query_count)
        .saturating_add(batching.transition_binding.batched_query_count);

    assert_eq!(output.query_schedule.query_claims.len(), expected_openings);
    assert_eq!(output.query_schedule.query_claims.len(), 4);
    assert!(output.query_schedule.query_claims.len() < descriptor.real_evaluator.rows.len());
    assert_eq!(
        batching.unbatched_semantic_opening_count,
        batching
            .k6a
            .source_row_count
            .saturating_add(batching.tuple_rlc.source_row_count)
            .saturating_add(batching.transition_binding.source_row_count)
    );
    assert_eq!(
        batching.batched_semantic_opening_count,
        batching
            .k6a
            .batched_query_count
            .saturating_add(batching.tuple_rlc.batched_query_count)
            .saturating_add(batching.transition_binding.batched_query_count)
    );
}

#[test]
fn symbt3_n8_semantic_batching_descriptor_mutation_rejects() {
    let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
    let mut bad_output = output.clone();
    bad_output
        .proof_plan
        .semantic_batching
        .k6a
        .challenge_point_digest[0] ^= 0x01;
    bad_output
        .proof_plan
        .semantic_batching
        .k6a
        .descriptor_digest =
        n8_semantic_batching_family_descriptor_digest(&bad_output.proof_plan.semantic_batching.k6a);
    bad_output.proof_plan.semantic_batching.descriptor_digest =
        n8_semantic_batching_descriptor_digest(&bad_output.proof_plan.semantic_batching);
    bad_output.proof_plan.transcript_digest =
        n8_integrated_whir_proof_plan_transcript_digest(&bad_output.proof_plan);

    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
    );
}

#[test]
fn symbt3_n8_k6a_source_row_batching_descriptor_mutation_rejects() {
    let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
    let mut bad_output = output.clone();
    bad_output
        .proof_plan
        .semantic_batching
        .k6a_source
        .descriptor
        .row_digest[0] ^= 0x01;
    bad_output
        .proof_plan
        .semantic_batching
        .k6a_source
        .descriptor
        .descriptor_digest = n8_semantic_batching_family_descriptor_digest(
        &bad_output
            .proof_plan
            .semantic_batching
            .k6a_source
            .descriptor,
    );
    bad_output
        .proof_plan
        .semantic_batching
        .k6a_source
        .descriptor_digest = n8_k6a_source_row_batching_descriptor_digest(
        &bad_output.proof_plan.semantic_batching.k6a_source,
    );
    bad_output.proof_plan.semantic_batching.descriptor_digest =
        n8_semantic_batching_descriptor_digest(&bad_output.proof_plan.semantic_batching);
    bad_output.proof_plan.transcript_digest =
        n8_integrated_whir_proof_plan_transcript_digest(&bad_output.proof_plan);

    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
    );
}

#[test]
fn symbt3_n8_semantic_batching_row_mutations_still_reject() {
    let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
    for row_kind in [
        RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorOpeningClaimV1,
        RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticFinalResidualZeroV1,
        RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1,
        RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1,
    ] {
        let mut bad_descriptor = descriptor.clone();
        bad_descriptor
            .real_evaluator
            .rows
            .iter_mut()
            .find(|row| row.kind == row_kind)
            .expect("batched semantic row exists")
            .value += BabyBear::ONE;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(matches!(
            report.blocker,
            Some(
                Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch
                    | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
            )
        ));
    }
}

#[test]
fn symbt3_n8_audit_coherent_k6a_opening_row_replay_rejects() {
    let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
    let semantic_row = descriptor
        .k6a_semantic_constraints
        .rows
        .iter_mut()
        .find(|row| row.kind == N8IntegratedK6aSemanticConstraintRowKindV1::VerifierOpeningClaimV1)
        .expect("K6a verifier-opening semantic row exists");
    let source_index = semantic_row.source_index;
    semantic_row.value += BabyBear::ONE;
    refresh_symbt3_n8_k6a_semantic_constraints_for_test(&mut descriptor.k6a_semantic_constraints);

    let evaluator_row = descriptor
        .real_evaluator
        .rows
        .iter_mut()
        .find(|row| {
            row.kind == RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticVerifierOpeningClaimV1
                && row.source_index == source_index
        })
        .expect("matching integrated K6a semantic evaluator row exists");
    evaluator_row.value += BabyBear::ONE;
    refresh_symbt3_n8_evaluator_descriptor_for_test(&mut descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_audit_authority_candidate_output_mutations_reject() {
    let (_fixture, _proof, descriptor, vk, output) = semantic_n8_output_fixture_for_test();

    let mut bad_descriptor = descriptor.clone();
    bad_descriptor
        .real_evaluator
        .rows
        .iter_mut()
        .find(|row| {
            row.kind == RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticFinalResidualZeroV1
        })
        .expect("integrated K6a semantic row exists")
        .value += BabyBear::ONE;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
    assert!(matches!(
        report.blocker,
        Some(
            Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch
                | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
        )
    ));

    let mut bad_descriptor = descriptor.clone();
    bad_descriptor
        .real_evaluator
        .rows
        .iter_mut()
        .find(|row| {
            row.kind
                == RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1
        })
        .expect("integrated tuple-RLC semantic row exists")
        .value += BabyBear::ONE;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
    assert!(matches!(
        report.blocker,
        Some(
            Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch
                | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
        )
    ));

    let mut bad_descriptor = descriptor.clone();
    bad_descriptor
        .real_evaluator
        .rows
        .iter_mut()
        .find(|row| {
            row.kind
                == RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1
        })
        .expect("integrated transition semantic row exists")
        .value += BabyBear::ONE;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
    assert!(matches!(
        report.blocker,
        Some(
            Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch
                | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
        )
    ));

    let mut bad_descriptor = descriptor.clone();
    bad_descriptor.public_statement_digest[0] ^= 0x01;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
    assert!(report.blocked);

    let mut bad_descriptor = descriptor.clone();
    bad_descriptor
        .transition_binding_semantic_constraints
        .old_accumulator_digest[0] ^= 0x02;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
    assert!(report.blocked);

    let mut bad_descriptor = descriptor.clone();
    bad_descriptor
        .transition_binding_semantic_constraints
        .new_accumulator_digest[0] ^= 0x04;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
    assert!(report.blocked);

    let mut bad_descriptor = descriptor.clone();
    bad_descriptor
        .transition_binding_semantic_constraints
        .tuple_leaf_root[0] ^= 0x08;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
    assert!(report.blocked);

    let mut bad_descriptor = descriptor.clone();
    bad_descriptor.tuple_leaf_layout_digest[0] ^= 0x10;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
    assert!(report.blocked);

    let mut bad_output = output.clone();
    bad_output.proof_plan.claim_plan_digest[0] ^= 0x20;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
    );

    let mut bad_output = output.clone();
    bad_output.proof_plan.committed_table_digest[0] ^= 0x40;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
    );

    let mut bad_output = output.clone();
    bad_output.integrated_whir_root[0] ^= 0x80;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch)
    );
    let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &bad_output.verifier_input(&descriptor),
    );
    assert_eq!(
        backend_report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch)
    );

    let mut bad_output = output.clone();
    bad_output.query_schedule.query_claims[0].value += BabyBear::ONE;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch)
    );
    let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &bad_output.verifier_input(&descriptor),
    );
    assert_eq!(
        backend_report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch)
    );

    let mut bad_descriptor = descriptor;
    bad_descriptor
        .semantic_completion
        .transition_semantics_complete = false;
    let report = verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
    assert!(report.blocked);
}

#[test]
fn symbt3_n8_audit_synthetic_semantic_output_authority_rejects() {
    let (_fixture, _proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
    let plan = build_n8_integrated_whir_proof_plan(&N8IntegratedWhirProofInputs::from_descriptor(
        &descriptor,
    ))
    .expect("semantic N8 proof plan builds");
    let (pk, vk) = WhirSnark::setup(&relation());
    let output = prove_symbt3_synthetic_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
        .expect("synthetic semantic backend plumbing output");

    let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &output.verifier_input(&descriptor),
    );
    assert!(backend_report.ok);
    let authority_report =
        verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
    assert_eq!(
        authority_report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SyntheticNonAuthoritativeOutput)
    );
}

#[test]
fn symbt3_n8_audit_n7b_full_proof_rejected_as_n8_candidate() {
    let (_fixture, proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
    let (root, plan) =
        n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
    let empty_schedule = build_n8_integrated_whir_query_schedule_for_claims(&plan, Vec::new());
    let (_, vk) = WhirSnark::setup(&relation());

    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &plan,
            Some(root),
            Some(&proof.k6a_main_proof),
            Some(&empty_schedule),
        ),
    );

    assert!(!report.ok);
    assert!(report.blocked);
    assert!(matches!(
        report.blocker,
        Some(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch
                | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
                | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected
        )
    ));
}

#[test]
fn symbt3_n8_transition_binding_semantic_rows_honest_pass() {
    let (_fixture, _proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
    let constraints = &descriptor.transition_binding_semantic_constraints;
    assert!(constraints.complete);
    assert_eq!(constraints.rows.len(), 8);
    assert_eq!(
        constraints.rows_digest,
        n8_integrated_transition_binding_semantic_rows_digest(&constraints.rows)
    );
    assert_eq!(
        constraints.transition_binding_digest,
        n8_integrated_transition_binding_semantic_digest(constraints)
    );
    assert_eq!(
        constraints.descriptor_digest,
        n8_integrated_transition_binding_semantic_descriptor_digest(constraints)
    );
    assert!(constraints
        .rows
        .iter()
        .all(|row| row.value == BabyBear::ZERO));
    assert_eq!(
        descriptor.real_evaluator.counters.transition_binding_rows,
        constraints.rows.len()
    );
    assert!(verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor).ok);
}

#[test]
fn symbt3_n8_transition_old_accumulator_digest_mutation_rejects() {
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.old_accumulator_digest[0] ^= 0x01;
    });
}

#[test]
fn symbt3_n8_transition_new_accumulator_digest_mutation_rejects() {
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.new_accumulator_digest[0] ^= 0x02;
    });
}

#[test]
fn symbt3_n8_transition_public_statement_digest_mutation_rejects() {
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.public_statement_digest[0] ^= 0x04;
    });
}

#[test]
fn symbt3_n8_transition_k6a_proof_digest_mutation_rejects() {
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.k6a_proof_digest[0] ^= 0x08;
    });
}

#[test]
fn symbt3_n8_transition_tuple_root_layout_mutation_rejects() {
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.tuple_leaf_root[0] ^= 0x10;
    });
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.tuple_leaf_layout_digest[0] ^= 0x20;
    });
}

#[test]
fn symbt3_n8_transition_native_message_roots_mutation_rejects() {
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.native_oracle_descriptor_digest[0] ^= 0x40;
    });
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.native_message_roots_digest[0] ^= 0x80;
    });
}

#[test]
fn symbt3_n8_transition_batch_size_active_count_mutation_rejects() {
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.batch_size += 1;
    });
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.active_count += 1;
    });
}

#[test]
fn symbt3_n8_transition_plan_table_digest_mutation_rejects() {
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.n8_claim_plan_digest[0] ^= 0x01;
    });
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.n8_committed_table_layout_digest[0] ^= 0x02;
    });
    assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
        constraints.n8_committed_table_digest[0] ^= 0x04;
    });
}

#[test]
fn symbt3_n8_authority_gate_rejects_unless_all_semantic_flags_true() {
    for mutate in [
        |flags: &mut N8IntegratedSemanticCompletionFlagsV1| {
            flags.k6a_semantics_complete = false;
        },
        |flags: &mut N8IntegratedSemanticCompletionFlagsV1| {
            flags.tuple_rlc_semantics_complete = false;
        },
        |flags: &mut N8IntegratedSemanticCompletionFlagsV1| {
            flags.transition_semantics_complete = false;
        },
    ] {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        mutate(&mut descriptor.semantic_completion);
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&descriptor);
        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete)
        );
    }
}

#[test]
fn symbt3_n8_keeps_default_verify_public_routing_unchanged() {
    assert!(WhirSnark::has_authoritative_typed_cp());
    let smoke = n7_fixture(1, 1);
    assert!(verify_symbt3_native_accumulator_authority_non_zk(
        &smoke.vk,
        &smoke.instance,
        &smoke.proof,
    ));
    assert!(symbt3_native_accumulator_k6a_workload_adapter(
        Symbt3NativeAccumulatorK6aWorkloadAdapterInput::NativeN7Smoke {
            instance: &smoke.instance,
            proof: &smoke.proof,
        },
    )
    .is_none());
}

#[test]
fn symbt3_n8_k6a_semantic_constraint_row_mutation_rejects() {
    let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
    let row = descriptor
        .k6a_semantic_constraints
        .rows
        .iter_mut()
        .find(|row| row.kind == N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1)
        .expect("K6a final residual semantic row exists");
    row.value += BabyBear::ONE;
    refresh_symbt3_n8_k6a_semantic_constraints_for_test(&mut descriptor.k6a_semantic_constraints);
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_k6a_semantic_padding_mutation_rejects() {
    let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
    let row = descriptor
        .k6a_semantic_constraints
        .rows
        .iter_mut()
        .find(|row| row.kind == N8IntegratedK6aSemanticConstraintRowKindV1::K6aPaddingZeroV1)
        .expect("K6a semantic padding row exists");
    row.value += BabyBear::ONE;
    refresh_symbt3_n8_k6a_semantic_constraints_for_test(&mut descriptor.k6a_semantic_constraints);
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_k6a_semantic_descriptor_mutation_rejects() {
    let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
    descriptor.k6a_semantic_constraints.descriptor_digest[0] ^= 0x40;
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_tuple_rlc_semantic_weak_repetition_or_bits_reject() {
    let fixture = k6a_adapter_fixture_with_batch_size(1);
    let relation = symbt3_k6a_relation_from_context(
        fixture
            .vk
            .relation
            .context
            .as_ref()
            .expect("K6a relation context"),
    )
    .expect("K6a relation decodes");
    let statement = fixture.accumulator_instance.to_public_statement();

    for (repetition_count, bits_per_repetition) in [(1usize, 31usize), (4, 0), (4, 20)] {
        let (_tuple_leaf_vk, native_tuple_leaf) =
            k6a_compatible_n7b_tuple_leaf_parts_with_repetitions(
                &fixture.adapter,
                repetition_count,
                bits_per_repetition,
            );
        let err =
            build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_with_k6a_semantics(
                &fixture.pk.seed,
                &relation,
                &statement,
                &fixture.adapter,
                &native_tuple_leaf,
                &fixture.proof,
            )
            .expect_err("weak tuple-RLC semantic evidence must reject");
        assert_eq!(
            err,
            Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak
        );
    }
}

#[test]
fn symbt3_n8_tuple_rlc_semantic_domain_mutation_rejects() {
    let (_fixture, _proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
    let mut gamma_descriptor = descriptor.clone();
    gamma_descriptor
        .tuple_rlc_semantic_constraints
        .packing_challenge_digest = digest(b"n8-mutated-tuple-rlc-gamma-domain");
    refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
        &mut gamma_descriptor.tuple_rlc_semantic_constraints,
    );
    gamma_descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&gamma_descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&gamma_descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
    );

    let mut zeta_descriptor = descriptor;
    zeta_descriptor
        .tuple_rlc_semantic_constraints
        .opening_points_digest = digest(b"n8-mutated-tuple-rlc-zeta-domain");
    refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
        &mut zeta_descriptor.tuple_rlc_semantic_constraints,
    );
    zeta_descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&zeta_descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&zeta_descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_tuple_rlc_semantic_repetition_swap_rejects() {
    let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
    descriptor.tuple_rlc_semantic_constraints.rows.swap(0, 1);
    refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
        &mut descriptor.tuple_rlc_semantic_constraints,
    );
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_tuple_rlc_semantic_logical_oracle_order_mutation_rejects() {
    let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
    let logical_base = descriptor
        .tuple_rlc_semantic_constraints
        .rlc_repetition_count;
    descriptor
        .tuple_rlc_semantic_constraints
        .rows
        .swap(logical_base, logical_base + 1);
    refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
        &mut descriptor.tuple_rlc_semantic_constraints,
    );
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_tuple_rlc_semantic_residual_mutation_rejects() {
    let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
    let row = descriptor
        .tuple_rlc_semantic_constraints
        .rows
        .iter_mut()
        .find(|row| row.kind == N8IntegratedTupleRlcSemanticConstraintRowKindV1::RlcResidualZeroV1)
        .expect("tuple RLC residual semantic row exists");
    row.value += BabyBear::ONE;
    refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
        &mut descriptor.tuple_rlc_semantic_constraints,
    );
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_tuple_rlc_semantic_descriptor_mutation_rejects() {
    let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
    descriptor.tuple_rlc_semantic_constraints.descriptor_digest[0] ^= 0x20;
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
    );
}

#[test]
fn symbt3_n8_tuple_pcs_proof_material_rejects() {
    let (_fixture, proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
    let (_, vk) = WhirSnark::setup(&relation());
    let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
    inputs.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);

    let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
    );
}

#[test]
fn symbt3_n8_k6a_semantic_split_delegation_still_rejects() {
    let (_fixture, proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
    let (_, vk) = WhirSnark::setup(&relation());
    let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
    inputs.legacy_k6a_proof = Some(&proof.k6a_main_proof);
    inputs.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);

    let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
    );
}

#[test]
fn symbt3_n8_integrated_prover_output_verifies_through_backend() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
    let plan = build_n8_integrated_whir_proof_plan(&inputs).expect("N8 proof plan builds");
    let (pk, vk) = WhirSnark::setup(&relation());

    let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
        .expect("real integrated WHIR prover output");

    assert_eq!(output.version, N8_INTEGRATED_WHIR_PROVER_OUTPUT_VERSION);
    assert_eq!(
        output.mode,
        N8IntegratedWhirProverModeV1::RealIntegratedK6aNativeEvaluatorV1
    );
    assert_eq!(output.counters.whir_instance_count, 1);
    assert_eq!(output.counters.root_count, 1);
    assert_eq!(output.counters.query_schedule_count, 1);
    assert_eq!(output.counters.tuple_pcs_proof_count, 0);
    assert!(!output.counters.delegated_split_proof_material_present);
    assert!(!output.counters.synthetic_non_authoritative);
    assert_eq!(output.proof_plan.integrated_whir_root_count, 1);
    assert_eq!(output.proof_plan.integrated_whir_proof_count, 1);
    assert_eq!(
        output.integrated_whir_proof.num_vars,
        output.proof_plan.integrated_num_vars
    );
    assert_eq!(
        output.query_schedule.integrated_num_vars,
        output.proof_plan.integrated_num_vars
    );
    let expected_claim_count: usize = output
        .proof_plan
        .bridge_claim_descriptors
        .iter()
        .map(|descriptor| descriptor.claim_count)
        .sum();
    assert_eq!(
        output.query_schedule.query_claims.len(),
        expected_claim_count
    );

    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &output.verifier_input(&descriptor),
    );
    assert!(report.ok);
    assert!(!report.blocked);
    let authority_report =
        verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
    assert_eq!(
        authority_report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete)
    );
}

#[test]
fn symbt3_n8_integrated_prover_output_mutations_reject() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
    let plan = build_n8_integrated_whir_proof_plan(&inputs).expect("N8 proof plan builds");
    let (pk, vk) = WhirSnark::setup(&relation());
    let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
        .expect("real integrated WHIR prover output");

    let mut bad_num_vars = output.integrated_whir_proof.clone();
    bad_num_vars.num_vars += 1;
    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &output.proof_plan,
            Some(output.integrated_whir_root),
            Some(&bad_num_vars),
            Some(&output.query_schedule),
        ),
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch)
    );

    let mut bad_root = output.integrated_whir_root;
    bad_root[0] ^= 0x80;
    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &output.proof_plan,
            Some(bad_root),
            Some(&output.integrated_whir_proof),
            Some(&output.query_schedule),
        ),
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch)
    );

    let mut bad_schedule = output.query_schedule.clone();
    bad_schedule.transcript_digest[0] ^= 0x40;
    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &output.proof_plan,
            Some(output.integrated_whir_root),
            Some(&output.integrated_whir_proof),
            Some(&bad_schedule),
        ),
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch)
    );

    let mut mutated_bridge_descriptors = output.proof_plan.bridge_claim_descriptors.clone();
    mutated_bridge_descriptors[0].claim_count += 1;
    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &N8IntegratedWhirVerifierInput {
            combined_claim_descriptors: &mutated_bridge_descriptors,
            ..output.verifier_input(&descriptor)
        },
    );
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
    );

    let mut split_input = output.verifier_input(&descriptor);
    split_input.legacy_k6a_proof = Some(&proof.k6a_main_proof);
    split_input.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);
    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &split_input);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
    );
}

#[test]
fn symbt3_n8_real_evaluator_k6a_row_mutation_rejects() {
    assert_n8_real_evaluator_row_mutation_rejects(
        RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorOpeningClaimV1,
    );
}

#[test]
fn symbt3_n8_real_evaluator_tuple_rlc_row_mutation_rejects() {
    assert_n8_real_evaluator_row_mutation_rejects(
        RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1,
    );
}

#[test]
fn symbt3_n8_real_evaluator_padding_row_mutation_rejects() {
    assert_n8_real_evaluator_row_mutation_rejects(
        RealIntegratedK6aNativeEvaluatorRowKindV1::K6aZeroPaddingClaimV1,
    );
}

#[test]
fn symbt3_n8_real_evaluator_transition_binding_row_mutation_rejects() {
    assert_n8_real_evaluator_row_mutation_rejects(
        RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1,
    );
}

#[test]
fn symbt3_n8_synthetic_output_verifies_only_backend_plumbing_and_authority_rejects() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let plan = build_n8_integrated_whir_proof_plan(&N8IntegratedWhirProofInputs::from_descriptor(
        &descriptor,
    ))
    .expect("N8 proof plan builds");
    let (pk, vk) = WhirSnark::setup(&relation());
    let output = prove_symbt3_synthetic_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
        .expect("synthetic backend plumbing output");

    assert_eq!(
        output.mode,
        N8IntegratedWhirProverModeV1::SyntheticNonAuthoritativeV1
    );
    assert!(output.counters.synthetic_non_authoritative);
    let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
        &vk,
        &output.verifier_input(&descriptor),
    );
    assert!(backend_report.ok);
    let authority_report =
        verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
    assert_eq!(
        authority_report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SyntheticNonAuthoritativeOutput)
    );
}

#[test]
fn symbt3_n8_integrated_backend_rejects_missing_integrated_proof() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
    let plan = build_n8_integrated_whir_proof_plan(&inputs).expect("N8 proof plan builds");
    let (_, vk) = WhirSnark::setup(&relation());
    let verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
        &descriptor,
        &plan,
        None,
        None,
        None,
    );

    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing)
    );
}

#[test]
fn symbt3_n8_integrated_backend_rejects_proof_num_vars_mismatch() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let mut bad_integrated_proof = proof.k6a_main_proof.clone();
    bad_integrated_proof.num_vars = descriptor.claim_plan.integrated_num_vars + 1;
    let (root, plan) =
        n8_integrated_plan_for_existing_proof_for_test(&descriptor, &bad_integrated_proof);
    let (_, vk) = WhirSnark::setup(&relation());
    let verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
        &descriptor,
        &plan,
        Some(root),
        Some(&bad_integrated_proof),
        None,
    );

    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch)
    );
}

#[test]
fn symbt3_n8_integrated_backend_rejects_second_root_or_proof() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let (root, plan) =
        n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
    let (_, vk) = WhirSnark::setup(&relation());
    let mut verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
        &descriptor,
        &plan,
        Some(root),
        Some(&proof.k6a_main_proof),
        None,
    );
    verifier_input.extra_whir_root_count = 1;
    verifier_input.extra_whir_proof_count = 1;

    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot)
    );
}

#[test]
fn symbt3_n8_integrated_backend_rejects_split_k6a_tuple_delegation() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let (root, plan) =
        n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
    let (_, vk) = WhirSnark::setup(&relation());
    let mut verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
        &descriptor,
        &plan,
        Some(root),
        Some(&proof.k6a_main_proof),
        None,
    );
    verifier_input.legacy_k6a_proof = Some(&proof.k6a_main_proof);
    verifier_input.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);

    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
    );
}

#[test]
fn symbt3_n8_integrated_backend_rejects_claim_descriptor_mutation() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let (root, plan) =
        n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
    let (_, vk) = WhirSnark::setup(&relation());
    let mut mutated_bridge_descriptors = plan.bridge_claim_descriptors.clone();
    mutated_bridge_descriptors[1].claim_count += 1;
    let verifier_input = N8IntegratedWhirVerifierInput {
        combined_claim_descriptors: &mutated_bridge_descriptors,
        ..N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &plan,
            Some(root),
            Some(&proof.k6a_main_proof),
            None,
        )
    };

    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
    );
}

#[test]
fn symbt3_n8_integrated_backend_rejects_current_n7b_as_integrated_proof() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let (root, plan) =
        n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
    let empty_schedule = build_n8_integrated_whir_query_schedule_for_claims(&plan, Vec::new());
    let (_, vk) = WhirSnark::setup(&relation());
    let verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
        &descriptor,
        &plan,
        Some(root),
        Some(&proof.k6a_main_proof),
        Some(&empty_schedule),
    );

    let report = verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

    assert!(!report.ok);
    assert!(report.blocked);
    assert!(matches!(
        report.blocker,
        Some(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch
                | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
                | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected
        )
    ));
}

#[test]
fn symbt3_n8_rejects_ambiguous_selector_gated_overlap() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
    inputs.table_representation =
        N8IntegratedWhirTableRepresentationV1::ScalarOracleSelectorGatedRegions;

    let err = build_n8_integrated_whir_proof_plan(&inputs)
        .expect_err("overlapping current layout cannot be selector-gated");

    assert_eq!(
        err,
        Symbt3N8IntegratedPrototypeBlocker::AmbiguousIntegratedLayout
    );
}

#[test]
fn symbt3_n8_rejects_second_whir_root_or_proof() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let (_, vk) = WhirSnark::setup(&relation());
    let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
    inputs.integrated_whir_root = Some(digest(b"n8-integrated-root-placeholder"));
    inputs.integrated_whir_proof = Some(&proof.k6a_main_proof);
    inputs.extra_whir_root_count = 1;
    inputs.extra_whir_proof_count = 1;

    let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);

    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot)
    );
}

#[test]
fn symbt3_n8_rejects_split_k6a_tuple_delegation_attempt() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let (_, vk) = WhirSnark::setup(&relation());
    let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
    inputs.legacy_k6a_proof = Some(&proof.k6a_main_proof);
    inputs.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);
    let plan = build_n8_integrated_whir_proof_plan(&inputs)
        .expect("legacy material is recorded but not accepted");
    assert!(plan.delegated_split_proof_material_present);

    let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);

    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
    );
}

#[test]
fn symbt3_n8_descriptor_mutation_changes_proof_plan_transcript() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds");
    let original_plan = build_n8_integrated_whir_proof_plan(
        &N8IntegratedWhirProofInputs::from_descriptor(&descriptor),
    )
    .expect("original N8 proof plan builds");

    let mut mutated = descriptor.clone();
    mutated
        .transition_binding_semantic_constraints
        .descriptor_digest[0] ^= 0x10;
    mutated.transcript_binding_digest = symbt3_n8_integrated_transcript_binding_digest(&mutated);
    let mutated_err = build_n8_integrated_whir_proof_plan(
        &N8IntegratedWhirProofInputs::from_descriptor(&mutated),
    )
    .expect_err("transition semantic descriptor mutation rejects");

    assert_ne!(
        original_plan.descriptor_transcript_digest,
        mutated.transcript_binding_digest
    );
    assert_eq!(
        mutated_err,
        Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation
    );
}

#[test]
fn symbt3_n8_current_n7b_object_fails_closed_before_authority() {
    let proof = assert_honest_full_n7b_verifies(1);
    let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
        &proof.wrapper.k6a_adapter,
        &proof.wrapper.native_tuple_leaf,
        &proof.k6a_main_proof,
    )
    .expect("N8 descriptor builds from current N7b object");

    let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete)
    );

    let (pk, vk) = WhirSnark::setup(&relation());
    let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
    inputs.legacy_k6a_proof = Some(&proof.k6a_main_proof);
    inputs.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);
    let proof_err = prove_symbt3_n8_integrated_whir_non_zk(&pk, &inputs)
        .expect_err("N8 prover skeleton remains fail-closed");
    assert_eq!(
        proof_err,
        Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt
    );
    let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);
    assert!(!report.ok);
    assert!(report.blocked);
    assert_eq!(
        report.blocker,
        Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
    );
}

#[test]
fn symbt3_n7b_full_helper_rejects_stale_components_and_mutations() {
    let fixture = k6a_adapter_fixture_with_batch_size(1);
    let other = k6a_adapter_fixture_with_batch_size(2);
    let proof = prove_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.pk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &fixture.accumulator_witness,
    )
    .expect("full N7b proof");
    assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &proof,
    ));

    let mut stale_k6a = proof.clone();
    stale_k6a.k6a_main_proof = other.proof;
    let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &stale_k6a,
    );
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N7bFullAuthorityBlocker::K6aProofMismatch)
    );

    let other_proof = prove_symbt3_native_accumulator_authority_full_non_zk(
        &other.pk,
        &other.profile,
        &other.accumulator_instance,
        &other.accumulator_witness,
    )
    .expect("other full N7b proof");
    let mut stale_native = proof.clone();
    stale_native.wrapper.native_tuple_leaf = other_proof.wrapper.native_tuple_leaf;
    stale_native.wrapper.binding_digest =
        build_symbt3_n7b_full_authority_binding_digest(&symbt3_n7b_full_authority_binding_inputs(
            &stale_native.wrapper.k6a_adapter,
            &stale_native.wrapper.native_tuple_leaf,
        ));
    let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &stale_native,
    );
    assert!(!report.ok);

    let mut bad_binding = proof.clone();
    bad_binding.wrapper.binding_digest = digest(b"n7b-full-helper-bad-binding");
    let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &bad_binding,
    );
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N7bFullAuthorityBlocker::BindingDigestMismatch)
    );

    let mut weak_rlc = proof.clone();
    weak_rlc.wrapper.counters.rlc_repetition_count = 1;
    weak_rlc.wrapper.counters.total_rlc_batching_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
    weak_rlc.wrapper.counters.effective_soundness_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
    weak_rlc.wrapper.counters.rlc_batching_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
    let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &weak_rlc,
    );
    assert!(!report.ok);

    let mut public_canonical = proof;
    public_canonical.proof_kind = ProductProofKind::MonolithicTypedCp;
    let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
        &fixture.vk,
        &fixture.profile,
        &fixture.accumulator_instance,
        &public_canonical,
    );
    assert!(!report.ok);
    assert_eq!(
        report.blocker,
        Some(Symbt3N7bFullAuthorityBlocker::PublicCanonicalOrMonolithicAuthority)
    );
}

#[test]
fn symbt3_n7b_full_binding_digest_is_deterministic_and_field_bound() {
    let fixture = k6a_adapter_fixture();
    let (_, native_tuple_leaf) = k6a_compatible_n7b_tuple_leaf_parts(&fixture.adapter);
    let inputs = symbt3_n7b_full_authority_binding_inputs(&fixture.adapter, &native_tuple_leaf);
    let binding_digest = build_symbt3_n7b_full_authority_binding_digest(&inputs);
    assert_eq!(
        binding_digest,
        build_symbt3_n7b_full_authority_binding_digest(&inputs)
    );

    let mut changed = inputs.clone();
    changed.main_symbt3_proof_digest = digest(b"n7b-changed-k6a-proof-digest");
    assert_ne!(
        binding_digest,
        build_symbt3_n7b_full_authority_binding_digest(&changed)
    );

    let mut changed = inputs.clone();
    changed.tuple_leaf_root = digest(b"n7b-changed-tuple-leaf-root");
    assert_ne!(
        binding_digest,
        build_symbt3_n7b_full_authority_binding_digest(&changed)
    );

    let mut changed = inputs.clone();
    changed.old_accumulator_digest = digest(b"n7b-changed-old-accumulator");
    assert_ne!(
        binding_digest,
        build_symbt3_n7b_full_authority_binding_digest(&changed)
    );

    let mut changed = inputs;
    changed.new_accumulator_digest = digest(b"n7b-changed-new-accumulator");
    assert_ne!(
        binding_digest,
        build_symbt3_n7b_full_authority_binding_digest(&changed)
    );
}

#[test]
fn symbt3_n7b_full_wrapper_advances_past_repeated_rlc_blocker_when_evidence_verifies() {
    let fixture = k6a_adapter_fixture();
    let (tuple_leaf_vk, native_tuple_leaf) = k6a_compatible_n7b_tuple_leaf_parts(&fixture.adapter);
    let wrapper = compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
        workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
        k6a_adapter: Some(fixture.adapter.clone()),
        native_tuple_leaf: Some(native_tuple_leaf),
        binding_digest: None,
        fallback_used: false,
    })
    .expect("N7b full wrapper has all typed components");
    assert_eq!(
        wrapper.binding_digest,
        build_symbt3_n7b_full_authority_binding_digest(&symbt3_n7b_full_authority_binding_inputs(
            &wrapper.k6a_adapter,
            &wrapper.native_tuple_leaf,
        ))
    );
    assert!(wrapper.counters.full_accumulator_workload);
    assert!(!wrapper.counters.smoke_profile);
    assert_eq!(wrapper.counters.whir_instance_count, 1);
    assert_eq!(wrapper.counters.root_count, 1);
    assert_eq!(wrapper.counters.family_columnar_subproof_count, 0);
    assert_eq!(
        wrapper.counters.rlc_repetition_count,
        SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
    );
    let report = verify_symbt3_n7b_full_authority_wrapper_non_zk(
        &Symbt3N7bFullAuthorityVerificationContext {
            k6a_vk: &fixture.vk,
            tuple_leaf_vk: &tuple_leaf_vk,
            profile: &fixture.profile,
            accumulator_instance: &fixture.accumulator_instance,
            proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            k6a_proof: &fixture.proof,
        },
        &wrapper,
    );
    assert!(report.ok);
    assert!(!report.blocked);
    assert_eq!(report.blocker, None);
}

#[test]
fn symbt3_n7b_full_wrapper_rejects_weak_or_missing_repeated_rlc_evidence() {
    let fixture = k6a_adapter_fixture();
    for (repetition_count, bits_per_repetition) in [(1usize, 31usize), (4, 0), (4, 20)] {
        let (tuple_leaf_vk, native_tuple_leaf) =
            k6a_compatible_n7b_tuple_leaf_parts_with_repetitions(
                &fixture.adapter,
                repetition_count,
                bits_per_repetition,
            );
        let wrapper =
            compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
                workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
                k6a_adapter: Some(fixture.adapter.clone()),
                native_tuple_leaf: Some(native_tuple_leaf),
                binding_digest: None,
                fallback_used: false,
            })
            .expect("weak-RLC wrapper is structurally composed");
        let report = verify_symbt3_n7b_full_authority_wrapper_non_zk(
            &Symbt3N7bFullAuthorityVerificationContext {
                k6a_vk: &fixture.vk,
                tuple_leaf_vk: &tuple_leaf_vk,
                profile: &fixture.profile,
                accumulator_instance: &fixture.accumulator_instance,
                proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                k6a_proof: &fixture.proof,
            },
            &wrapper,
        );
        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N7bFullAuthorityBlocker::RepeatedRlcSoundnessMissingOrWeak)
        );
    }
}

#[test]
fn symbt3_n7b_full_wrapper_rejects_missing_tuple_smoke_and_bad_binding() {
    let fixture = k6a_adapter_fixture();
    assert_eq!(
        compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
            workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
            k6a_adapter: Some(fixture.adapter.clone()),
            native_tuple_leaf: None,
            binding_digest: None,
            fallback_used: false,
        })
        .unwrap_err(),
        Symbt3N7bFullAuthorityBlocker::MissingNativeTupleLeafProof
    );

    let (_, native_tuple_leaf) = k6a_compatible_n7b_tuple_leaf_parts(&fixture.adapter);
    let mut smoke_adapter = fixture.adapter.clone();
    smoke_adapter.full_accumulator_workload = false;
    smoke_adapter.smoke_profile = true;
    assert_eq!(
        compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
            workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
            k6a_adapter: Some(smoke_adapter),
            native_tuple_leaf: Some(native_tuple_leaf.clone()),
            binding_digest: None,
            fallback_used: false,
        })
        .unwrap_err(),
        Symbt3N7bFullAuthorityBlocker::SmokeProfile
    );

    assert_eq!(
        compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
            workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
            k6a_adapter: Some(fixture.adapter.clone()),
            native_tuple_leaf: Some(native_tuple_leaf),
            binding_digest: Some(digest(b"n7b-wrong-binding")),
            fallback_used: false,
        })
        .unwrap_err(),
        Symbt3N7bFullAuthorityBlocker::BindingDigestMismatch
    );
}

#[test]
fn symbt3_n7b_full_wrapper_keeps_default_verify_public_routing_unchanged() {
    assert!(WhirSnark::has_authoritative_typed_cp());
    let smoke = n7_fixture(1, 1);
    assert!(verify_symbt3_native_accumulator_authority_non_zk(
        &smoke.vk,
        &smoke.instance,
        &smoke.proof,
    ));
    assert!(symbt3_native_accumulator_k6a_workload_adapter(
        Symbt3NativeAccumulatorK6aWorkloadAdapterInput::NativeN7Smoke {
            instance: &smoke.instance,
            proof: &smoke.proof,
        },
    )
    .is_none());
}

#[test]
fn symbt3_n7_rejects_k6a_monolithic_and_compatibility_routes() {
    let fixture = n7_fixture(1, 1);

    let mut proof = fixture.proof.clone();
    proof.proof_kind = Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
    assert!(symbt3_k6a_public_canonical_route_accepts_proof_kind(
        proof.proof_kind
    ));

    let mut proof = fixture.proof.clone();
    proof.proof_kind = Symbt3NativeFoldingProofKind::MonolithicTypedCpV1;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
    assert!(symbt3_monolithic_typed_cp_route_accepts_proof_kind(
        proof.proof_kind
    ));

    let n6a = n6a_fixture(1, 1);
    assert!(!symbt3_k6a_public_canonical_route_accepts_proof_kind(
        fixture.proof.proof_kind
    ));
    assert!(!verify_n6a_fixture(&n6a, &fixture.instance, &n6a.proof));

    let mut proof = fixture.proof.clone();
    proof.counters.whir_instance_count = 2;
    proof.counters.native_multi_oracle = false;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
}

#[test]
fn symbt3_n7_rejects_profile_gate_failures() {
    let fixture = n7_fixture(1, 1);

    let mut instance = fixture.instance.clone();
    instance.manifest_policy = ManifestCommitmentPolicy::PublicCanonicalManifestViewV1;
    instance.committed_private_component_count = 0;
    assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.message_oracle_policy = Symbt3MessageOraclePolicy::DigestOnlyMessageRootsV1;
    assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
    assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.zk_status = Symbt3ZkStatus::ZkRequired;
    assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.semantic_profile_version =
        SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_MIN_SEMANTIC_PROFILE_VERSION - 1;
    assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance
        .required_semantic_families
        .production_norm_range_bundle = false;
    assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

    let mut instance = fixture.instance.clone();
    instance.monolithic_fallback = true;
    assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

    let mut proof = fixture.proof.clone();
    proof.counters.family_columnar_subproof_count = 1;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut metadata = symbt3_native_accumulator_authority_profile_metadata(
        &fixture.instance,
        &fixture.proof.counters,
    );
    metadata.rlc_batching_bits = None;
    let report = symbt3_native_accumulator_authority_profile_report(&metadata);
    assert!(!report.ok);
    assert!(!report.rlc_soundness_ok);
}

#[test]
fn symbt3_n7_rejects_binding_and_digest_mutations() {
    let fixture = n7_fixture(1, 1);

    let mut proof = fixture.proof.clone();
    proof.native_binding_digest = digest(b"n7-wrong-binding");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.profile_digest = digest(b"n7-wrong-profile");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.accumulator_instance_digest = digest(b"n7-wrong-instance");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.public_statement_digest = digest(b"n7-wrong-public-statement");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.whir_param_digest = digest(b"n7-wrong-whir-params");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.native_oracle_descriptor_digest = digest(b"n7-wrong-descriptor");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.rlc_tuple_leaf_root = digest(b"n7-wrong-rlc-root");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.native_message_roots_digest = digest(b"n7-wrong-message-roots");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.old_accumulator_digest = digest(b"n7-wrong-old-acc");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.new_accumulator_digest = digest(b"n7-wrong-new-acc");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
}

#[test]
fn symbt3_n7_rejects_tuple_leaf_native_and_accumulator_mutations() {
    let fixture = n7_fixture(2, 1);

    let mut proof = fixture.proof.clone();
    proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims[0].value += BabyBear::ONE;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims[2].value += BabyBear::ONE;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.rlc_tuple_leaf_multi_oracle_proof.packed_eval_claims[0].value += BabyBear::ONE;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof
        .rlc_tuple_leaf_multi_oracle_proof
        .packing_challenge_digest = digest(b"n7-wrong-packing-domain");
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof
        .rlc_tuple_leaf_multi_oracle_proof
        .logical_descriptors
        .swap(1, 2);
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims[0].claim_kind =
        WhirNativeEvalClaimKind::EqualitySide;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let two_round = n7_fixture(1, 2);
    let mut proof = two_round.proof.clone();
    proof.native_message_roots.swap(0, 1);
    assert!(!verify_n7_fixture(&two_round, &two_round.instance, &proof));

    let item_style = n7_fixture(2, 4);
    assert_eq!(fixture.proof.counters.native_message_oracle_count, 1);
    assert_eq!(item_style.proof.counters.native_message_oracle_count, 4);
    assert!(!verify_n7_fixture(
        &fixture,
        &fixture.instance,
        &item_style.proof
    ));

    let mut instance = fixture.instance.clone();
    instance.folded_output_digest = digest(b"n7-mutated-folded-output");
    assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

    let mut proof = fixture.proof.clone();
    proof.main_symbt3_whir_proof.z_eval += BabyBear::ONE;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
}

#[test]
fn symbt3_n7_rejects_stale_main_or_native_components() {
    let fixture = n7_fixture(1, 1);
    let stale = n7_fixture(2, 1);

    let mut proof = fixture.proof.clone();
    proof.main_symbt3_whir_proof = stale.proof.main_symbt3_whir_proof.clone();
    proof.main_symbt3_proof_digest = symbt3_main_whir_proof_digest(&proof.main_symbt3_whir_proof);
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

    let mut proof = fixture.proof.clone();
    proof.rlc_tuple_leaf_multi_oracle_proof = stale.proof.rlc_tuple_leaf_multi_oracle_proof.clone();
    proof.rlc_tuple_leaf_root = proof.rlc_tuple_leaf_multi_oracle_proof.packed_root;
    proof.rlc_tuple_leaf_layout_digest = proof
        .rlc_tuple_leaf_multi_oracle_proof
        .tuple_leaf_layout_digest;
    assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
}

#[test]
fn symbt3_n1bench_helpers_build_sorted_specs_and_evals() {
    let specs = build_native_oracle_benchmark_specs(4, 5).expect("N1bench specs");
    assert_eq!(specs.len(), 4);
    assert!(specs
        .windows(2)
        .all(|pair| pair[0].oracle_id < pair[1].oracle_id));
    assert!(specs
        .iter()
        .all(|spec| spec.num_vars == 5 && spec.role == WhirNativeOracleRole::Auxiliary));

    let requests =
        build_native_oracle_benchmark_eval_requests(&specs, WhirNativeEvalClaimKind::DirectOpening);
    assert_eq!(requests.len(), specs.len());
    assert!(requests
        .iter()
        .zip(specs.iter())
        .all(|(request, spec)| request.oracle_id == spec.oracle_id
            && request.claim_kind == WhirNativeEvalClaimKind::DirectOpening));

    let evals = build_native_oracle_benchmark_evals(&specs, 17).expect("N1bench evals");
    assert_eq!(evals.len(), specs.len());
    assert!(evals.iter().all(|oracle| oracle.len() == 32));
}

#[test]
fn symbt3_n1bench_batch_axis_keeps_oracle_count_fixed() {
    let round_count = 2usize;
    let message_axis_log_size = 3usize;
    for k in [1usize, 2, 4, 8] {
        let batch_log_size = k.trailing_zeros() as usize;
        let specs = build_native_oracle_batch_axis_benchmark_specs(
            round_count,
            batch_log_size,
            message_axis_log_size,
        )
        .expect("N1bench batch-axis specs");
        assert_eq!(specs.len(), round_count);
        assert!(specs.iter().enumerate().all(|(round, spec)| spec.oracle_id
            == SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + round as u32
            && spec.num_vars == batch_log_size + message_axis_log_size
            && spec.role
                == WhirNativeOracleRole::MessageRound {
                    round: round as u32
                }));
    }
}

fn tuple_leaf_fixture(
    logical_oracle_count: usize,
) -> (
    WhirProvingKey,
    WhirVerifyingKey,
    Digest32,
    Digest32,
    Digest32,
    Vec<WhirNativeOracleSpec>,
    Vec<Vec<BabyBear>>,
    Vec<WhirNativeEvalRequest>,
    Symbt3TupleLeafMultiOracleProof,
) {
    let (pk, vk) = WhirSnark::setup(&relation());
    let proof_relation_id = digest(b"m1b-proof-relation");
    let public_statement_digest = digest(b"m1b-public-statement");
    let whir_param_digest = digest(b"m1b-whir-params");
    let specs = build_native_oracle_benchmark_specs(logical_oracle_count, 3).expect("M1b specs");
    let evaluations = build_native_oracle_benchmark_evals(&specs, 77).expect("M1b evals");
    let requests =
        build_native_oracle_benchmark_eval_requests(&specs, WhirNativeEvalClaimKind::DirectOpening);
    let proof = whir_commit_and_prove_same_domain_multi_oracle(
        &pk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &specs,
        &evaluations,
        &requests,
    )
    .expect("M1b tuple-leaf proof");
    (
        pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        specs,
        evaluations,
        requests,
        proof,
    )
}

#[test]
fn same_domain_tuple_leaf_two_oracles_verifies() {
    let (
        _pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        _specs,
        _evaluations,
        _requests,
        proof,
    ) = tuple_leaf_fixture(2);
    assert!(whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &proof,
        &proof.logical_eval_claims,
    ));
    assert_eq!(proof.counters.logical_oracle_count, 2);
    assert_eq!(proof.counters.whir_instance_count, 1);
    assert_eq!(proof.counters.root_count, 1);
    assert_eq!(proof.counters.query_schedule_count, 1);
    assert_eq!(proof.counters.transcript_count, 1);
    assert_eq!(proof.counters.native_oracle_pcs_opening_count, 1);
    assert_eq!(
        proof.counters.rlc_repetition_count,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT
    );
    assert_eq!(
        proof.counters.rlc_batching_bits_per_repetition,
        SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
    );
    assert_eq!(
        proof.counters.total_rlc_batching_bits,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
    );
    assert_eq!(
        proof.counters.effective_soundness_bits,
        proof.counters.total_rlc_batching_bits
    );
    assert_eq!(
        proof.counters.tuple_leaf_layout,
        SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT
    );
}

#[test]
fn same_domain_tuple_leaf_four_oracles_exposes_logical_claims_and_packed_value() {
    let (
        _pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        specs,
        evaluations,
        _requests,
        proof,
    ) = tuple_leaf_fixture(4);
    assert!(whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &proof,
        &proof.logical_eval_claims,
    ));
    assert_eq!(
        proof.packed_eval_claims.len(),
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT
    );
    assert_eq!(
        proof.logical_eval_claims.len(),
        specs.len() * SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT
    );
    for repetition_index in 0..SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT {
        let point = derive_same_domain_tuple_leaf_opening_point_for_repetition(
            repetition_index,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            proof.descriptor_digest,
            proof.tuple_leaf_layout_digest,
            WhirNativeEvalClaimKind::DirectOpening,
            specs[0].num_vars,
        );
        let start = repetition_index * specs.len();
        let claims = &proof.logical_eval_claims[start..start + specs.len()];
        for (claim, evaluations) in claims.iter().zip(evaluations.iter()) {
            assert_eq!(claim.value, mle_eval_bb(evaluations, &point));
        }
        let challenges = symbt3_tuple_leaf_packing_challenges_for_repetition(
            proof.mode,
            repetition_index,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            proof.descriptor_digest,
            proof.tuple_leaf_layout_digest,
            proof.logical_descriptors.len(),
            specs[0].num_vars,
        )
        .expect("M1b repetition packing challenges");
        let logical_values = claims.iter().map(|claim| claim.value).collect::<Vec<_>>();
        assert_eq!(
            proof.packed_eval_claims[repetition_index].value,
            symbt3_tuple_leaf_pack_values(&challenges, &logical_values).unwrap()
        );
    }
}

#[test]
fn same_domain_tuple_leaf_byte_accounting_sections_sum_to_total() {
    let (_, _, _, _, _, _, _, _, proof) = tuple_leaf_fixture(4);
    let sections = proof.accounting_byte_sections();
    let pcs_json_bytes =
        serde_json::to_vec(&proof.whir_pcs_proof).expect("tuple PCS proof serializes");
    let pcs_compact_bytes = whir_pcs_compact_canonical_bytes(&proof.whir_pcs_proof)
        .expect("tuple PCS proof compact-serializes");
    let expected_total = proof.metadata_canonical_bytes().len() + 8 + pcs_compact_bytes.len();
    assert_eq!(sections.total_bytes, expected_total);
    assert_eq!(
        sections.total_bytes,
        sections.descriptor_layout_profile_metadata_bytes
            + sections.duplicated_main_k6a_context_bytes
            + sections.logical_eval_claim_bytes
            + sections.repeated_rlc_claim_bytes
            + sections.pcs_payload_length_prefix_bytes
            + sections.pcs_compact_canonical_payload_bytes
    );
    assert_eq!(sections.pcs_legacy_json_payload_bytes, pcs_json_bytes.len());
    assert_eq!(
        sections.pcs_legacy_json_payload_bytes,
        sections.pcs_merkle_root_path_payload_bytes
            + sections.pcs_query_value_payload_bytes
            + sections.pcs_transcript_payload_bytes
            + sections.pcs_json_framing_bytes
    );
    assert!(sections.pcs_merkle_root_path_payload_bytes > 0);
    assert!(sections.pcs_query_value_payload_bytes > 0);
    assert!(sections.repeated_rlc_claim_bytes > 0);
    assert_eq!(proof.counters.whir_instance_count, 1);
    assert_eq!(proof.counters.root_count, 1);
    assert_eq!(proof.counters.query_schedule_count, 1);
    assert_eq!(proof.counters.native_oracle_pcs_opening_count, 1);
}

fn mutate_first_json_number(value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::Number(number) => {
            let next = number.as_u64().unwrap_or(0).wrapping_add(1);
            *value = serde_json::Value::from(next);
            true
        }
        serde_json::Value::Array(values) => values.iter_mut().any(mutate_first_json_number),
        serde_json::Value::Object(fields) => fields.values_mut().any(mutate_first_json_number),
        _ => false,
    }
}

fn mutate_first_query_field_number(
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
    field: &str,
) -> WhirPcsProof<F, EF, WhirMmcs> {
    let mut value = serde_json::to_value(proof).expect("PCS proof JSON value");
    let mut mutated = false;
    if let Some(rounds) = value
        .get_mut("rounds")
        .and_then(serde_json::Value::as_array_mut)
    {
        for round in rounds {
            if let Some(queries) = round
                .get_mut("queries")
                .and_then(serde_json::Value::as_array_mut)
            {
                for query in queries {
                    if let Some(target) = query.get_mut(field) {
                        mutated = mutate_first_json_number(target);
                        if mutated {
                            break;
                        }
                    }
                }
            }
            if mutated {
                break;
            }
        }
    }
    if !mutated {
        if let Some(queries) = value
            .get_mut("final_queries")
            .and_then(serde_json::Value::as_array_mut)
        {
            for query in queries {
                if let Some(target) = query.get_mut(field) {
                    mutated = mutate_first_json_number(target);
                    if mutated {
                        break;
                    }
                }
            }
        }
    }
    assert!(mutated, "expected to mutate query field {field}");
    serde_json::from_value(value).expect("mutated PCS proof remains structurally valid")
}

#[test]
fn same_domain_tuple_leaf_compact_pcs_encoding_roundtrips_and_mutations_reject() {
    let (
        _pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        _specs,
        _evaluations,
        _requests,
        proof,
    ) = tuple_leaf_fixture(4);
    let compact =
        whir_pcs_compact_canonical_bytes(&proof.whir_pcs_proof).expect("compact PCS encoding");
    let decoded = whir_pcs_from_compact_canonical_bytes(&compact).expect("compact PCS decoding");
    assert_eq!(
        serde_json::to_value(&decoded).expect("decoded PCS JSON"),
        serde_json::to_value(&proof.whir_pcs_proof).expect("original PCS JSON")
    );
    let mut compact_roundtrip = proof.clone();
    compact_roundtrip.whir_pcs_proof = decoded;
    assert!(whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &compact_roundtrip,
        &compact_roundtrip.logical_eval_claims,
    ));

    let mut sibling_mutation = proof.clone();
    sibling_mutation.whir_pcs_proof =
        mutate_first_query_field_number(&sibling_mutation.whir_pcs_proof, "proof");
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &sibling_mutation,
        &sibling_mutation.logical_eval_claims,
    ));

    let mut opened_value_mutation = proof;
    opened_value_mutation.whir_pcs_proof =
        mutate_first_query_field_number(&opened_value_mutation.whir_pcs_proof, "values");
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &opened_value_mutation,
        &opened_value_mutation.logical_eval_claims,
    ));
}

#[test]
fn same_domain_tuple_leaf_rejects_mixed_domains_duplicate_ids_and_schedule_mix() {
    let (pk, _vk) = WhirSnark::setup(&relation());
    let proof_relation_id = digest(b"m1b-bad-relation");
    let public_statement_digest = digest(b"m1b-bad-public");
    let whir_param_digest = digest(b"m1b-bad-whir");
    let specs = build_native_oracle_benchmark_specs(2, 3).expect("M1b specs");
    let evaluations = build_native_oracle_benchmark_evals(&specs, 91).expect("M1b evals");
    let requests =
        build_native_oracle_benchmark_eval_requests(&specs, WhirNativeEvalClaimKind::DirectOpening);

    let mut mixed_num_vars = specs.clone();
    mixed_num_vars[1].num_vars = 4;
    assert!(whir_commit_and_prove_same_domain_multi_oracle(
        &pk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &mixed_num_vars,
        &evaluations,
        &requests,
    )
    .is_none());

    let mut duplicate_id = specs.clone();
    duplicate_id[1].oracle_id = duplicate_id[0].oracle_id;
    assert!(whir_commit_and_prove_same_domain_multi_oracle(
        &pk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &duplicate_id,
        &evaluations,
        &requests,
    )
    .is_none());

    let mut schedule_mix = specs.clone();
    schedule_mix[1].opening_schedule = WhirNativeOpeningSchedule::SamePoint;
    assert!(whir_commit_and_prove_same_domain_multi_oracle(
        &pk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &schedule_mix,
        &evaluations,
        &requests,
    )
    .is_none());
}

#[test]
fn same_domain_tuple_leaf_rejects_replays_and_mutations() {
    let (
        _pk,
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        _specs,
        _evaluations,
        _requests,
        proof,
    ) = tuple_leaf_fixture(4);
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        digest(b"m1b-stale-public"),
        whir_param_digest,
        &proof,
        &proof.logical_eval_claims,
    ));
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        digest(b"m1b-stale-whir"),
        &proof,
        &proof.logical_eval_claims,
    ));

    let mut descriptor_swap = proof.clone();
    descriptor_swap.logical_descriptors.swap(0, 1);
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &descriptor_swap,
        &descriptor_swap.logical_eval_claims,
    ));

    let mut logical_value_mutation = proof.clone();
    logical_value_mutation.logical_eval_claims[0].value += BabyBear::ONE;
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &logical_value_mutation,
        &logical_value_mutation.logical_eval_claims,
    ));

    let mut packed_value_mutation = proof.clone();
    packed_value_mutation.packed_eval_claims[0].value += BabyBear::ONE;
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &packed_value_mutation,
        &packed_value_mutation.logical_eval_claims,
    ));

    let mut domain_mutation = proof.clone();
    domain_mutation.packing_challenge_digest = digest(b"m1b-wrong-rlc-domain");
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &domain_mutation,
        &domain_mutation.logical_eval_claims,
    ));

    let mut layout_domain_mutation = proof.clone();
    layout_domain_mutation.tuple_leaf_layout_digest = digest(b"m1b-wrong-layout-domain");
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &layout_domain_mutation,
        &layout_domain_mutation.logical_eval_claims,
    ));

    let mut packed_repetition_swap = proof.clone();
    packed_repetition_swap.packed_eval_claims.swap(0, 1);
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &packed_repetition_swap,
        &packed_repetition_swap.logical_eval_claims,
    ));

    let mut logical_repetition_swap = proof.clone();
    let width = logical_repetition_swap.logical_descriptors.len();
    for offset in 0..width {
        logical_repetition_swap
            .logical_eval_claims
            .swap(offset, width + offset);
    }
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &logical_repetition_swap,
        &logical_repetition_swap.logical_eval_claims,
    ));

    let mut point_mutation = proof.clone();
    point_mutation.logical_eval_claims[0].point_digest = digest(b"m1b-wrong-point");
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &point_mutation,
        &point_mutation.logical_eval_claims,
    ));

    let mut claim_kind_mutation = proof.clone();
    claim_kind_mutation.logical_eval_claims[0].claim_kind = WhirNativeEvalClaimKind::MessageView;
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &claim_kind_mutation,
        &claim_kind_mutation.logical_eval_claims,
    ));

    let mut whir_instance_count_mutation = proof.clone();
    whir_instance_count_mutation.counters.whir_instance_count = 2;
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &whir_instance_count_mutation,
        &whir_instance_count_mutation.logical_eval_claims,
    ));

    let mut root_count_mutation = proof;
    root_count_mutation.counters.root_count = 2;
    assert!(!whir_verify_same_domain_multi_oracle(
        &vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &root_count_mutation,
        &root_count_mutation.logical_eval_claims,
    ));
}

#[test]
fn native_oracle_descriptor_digest_stability() {
    let (_, _, _, _, _, _, _, _, proof) = native_oracle_fixture();
    let digest_a = native_oracle_descriptor_digest(&proof.descriptors);
    let digest_b = native_oracle_descriptor_digest(&proof.descriptors);
    assert_eq!(digest_a, digest_b);
}

#[test]
fn native_oracle_descriptor_canonical_bytes_are_stable() {
    let (_, _, _, _, _, specs, _, _, proof) = native_oracle_fixture();
    assert_eq!(
        native_oracle_spec_digest(&specs),
        native_oracle_spec_digest(&specs)
    );
    assert_eq!(
        proof.descriptors[0].canonical_bytes(),
        proof.descriptors[0].canonical_bytes()
    );
    assert_ne!(proof.descriptors[0].canonical_bytes(), Vec::<u8>::new());
    assert_eq!(
        proof.descriptors[0].role.canonical_bytes(),
        WhirNativeOracleRole::Manifest.canonical_bytes()
    );
    assert_eq!(
        proof.descriptors[0].opening_schedule.canonical_bytes(),
        specs[0].opening_schedule.canonical_bytes()
    );
}

#[test]
fn native_oracle_eval_claim_canonical_bytes_are_stable() {
    let (_, _, _, _, _, _, _, requests, proof) = native_oracle_fixture();
    assert_eq!(
        requests[0].canonical_bytes(),
        WhirNativeEvalRequest {
            oracle_id: 1,
            claim_kind: WhirNativeEvalClaimKind::EqualitySide,
        }
        .canonical_bytes()
    );
    assert_eq!(
        proof.eval_claims[0].canonical_bytes(),
        proof.eval_claims[0].canonical_bytes()
    );
    assert_eq!(
        proof.eval_claims[0].claim_kind.canonical_bytes(),
        WhirNativeEvalClaimKind::EqualitySide.canonical_bytes()
    );
    assert_eq!(
        proof.native_oracle_eval_claims_digest,
        native_oracle_eval_claims_digest(&proof.eval_claims)
    );
}

#[test]
fn native_oracle_envelope_metadata_digest_is_stable() {
    let (_, _, _, _, _, _, _, _, proof) = native_oracle_fixture();
    let digest_a = native_multi_oracle_envelope_digest(&proof);
    let digest_b = native_multi_oracle_envelope_digest(&proof);
    assert_eq!(digest_a, digest_b);
    assert_eq!(digest_a, proof.native_multi_oracle_envelope_digest);
    assert_eq!(
        proof.metadata_canonical_bytes(),
        proof.metadata_canonical_bytes()
    );
}

#[test]
fn native_oracle_root_swap_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture_with_source(Some(vec![
            BabyBear::from_u32(4),
            BabyBear::from_u32(6),
            BabyBear::from_u32(9),
            BabyBear::from_u32(14),
        ]));
    assert_ne!(proof.descriptors[0].root, proof.descriptors[1].root);
    let lhs_root = proof.descriptors[0].root;
    proof.descriptors[0].root = proof.descriptors[1].root;
    proof.descriptors[1].root = lhs_root;
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_oracle_id_swap_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.descriptors[0].oracle_id = 9;
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_role_swap_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.descriptors[0].role = WhirNativeOracleRole::Source;
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_layout_digest_swap_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.descriptors[0].layout_digest = digest(b"wrong-layout");
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_num_vars_mismatch_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.descriptors[0].num_vars = 3;
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_opening_point_swap_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.eval_claims[0].point_digest = digest(b"wrong-point");
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_claimed_value_swap_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.eval_claims[0].value += BabyBear::ONE;
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_claim_kind_swap_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.eval_claims[0].claim_kind = WhirNativeEvalClaimKind::DirectOpening;
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_mutating_descriptor_canonical_bytes_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    let before = proof.descriptors[0].canonical_bytes();
    proof.descriptors[0].layout_digest[0] ^= 0x5a;
    assert_ne!(before, proof.descriptors[0].canonical_bytes());
    proof.native_oracle_descriptor_digest = native_oracle_descriptor_digest(&proof.descriptors);
    refresh_envelope_digest(&mut proof);
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_mutating_eval_claim_canonical_bytes_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    let before = proof.eval_claims[0].canonical_bytes();
    proof.eval_claims[0].value += BabyBear::ONE;
    assert_ne!(before, proof.eval_claims[0].canonical_bytes());
    proof.native_oracle_eval_claims_digest = native_oracle_eval_claims_digest(&proof.eval_claims);
    refresh_envelope_digest(&mut proof);
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_root_policy_mismatch_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, proof) =
        native_oracle_fixture();
    assert!(whir_verify_oracle_openings_with_root_policy(
        &vk,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        relation_id,
        statement_digest,
        whir_digest,
        &proof.descriptors,
        &proof,
        &proof.eval_claims,
    ));
    assert!(!whir_verify_oracle_openings_with_root_policy(
        &vk,
        NativeOracleRootPolicy::DebugDevelopmentOnly,
        relation_id,
        statement_digest,
        whir_digest,
        &proof.descriptors,
        &proof,
        &proof.eval_claims,
    ));
}

#[test]
fn native_oracle_debug_root_policy_rejected_by_authority_profiles() {
    let (pk, vk, relation_id, statement_digest, whir_digest, specs, evals, requests, _) =
        native_oracle_fixture();
    let debug_proof = whir_commit_and_prove_oracles_with_root_policy(
        &pk,
        NativeOracleRootPolicy::DebugDevelopmentOnly,
        relation_id,
        statement_digest,
        whir_digest,
        &specs,
        &evals,
        &requests,
    )
    .expect("debug native oracle proof");

    assert!(whir_verify_oracle_openings_for_profile(
        &vk,
        NativeOracleVerificationProfile::Development,
        relation_id,
        statement_digest,
        whir_digest,
        &debug_proof.descriptors,
        &debug_proof,
        &debug_proof.eval_claims,
    ));
    assert!(!whir_verify_oracle_openings_for_profile(
        &vk,
        NativeOracleVerificationProfile::ProductAuthority,
        relation_id,
        statement_digest,
        whir_digest,
        &debug_proof.descriptors,
        &debug_proof,
        &debug_proof.eval_claims,
    ));
    assert!(!whir_verify_oracle_openings_for_profile(
        &vk,
        NativeOracleVerificationProfile::NativeManifestAuthority,
        relation_id,
        statement_digest,
        whir_digest,
        &debug_proof.descriptors,
        &debug_proof,
        &debug_proof.eval_claims,
    ));
    assert!(!whir_verify_oracle_openings_for_profile(
        &vk,
        NativeOracleVerificationProfile::NativeMessageAuthority,
        relation_id,
        statement_digest,
        whir_digest,
        &debug_proof.descriptors,
        &debug_proof,
        &debug_proof.eval_claims,
    ));
}

#[test]
fn native_oracle_replay_under_different_root_policy_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
    refresh_envelope_digest(&mut proof);
    assert!(!whir_verify_oracle_openings_for_profile(
        &vk,
        NativeOracleVerificationProfile::Development,
        relation_id,
        statement_digest,
        whir_digest,
        &proof.descriptors,
        &proof,
        &proof.eval_claims,
    ));
}

#[test]
fn native_oracle_truncated_descriptors_reject() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.descriptors.pop();
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_appended_descriptor_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    let mut extra = proof.descriptors[1].clone();
    extra.oracle_id = 3;
    proof.descriptors.push(extra);
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_replay_under_different_public_statement_digest_rejects() {
    let (_, vk, relation_id, _statement_digest, whir_digest, _, _, _, proof) =
        native_oracle_fixture();
    assert!(!verify_fixture(
        &vk,
        relation_id,
        digest(b"different-public-statement"),
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_replay_under_different_whir_param_digest_rejects() {
    let (_, vk, relation_id, statement_digest, _whir_digest, _, _, _, proof) =
        native_oracle_fixture();
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        digest(b"different-whir-params"),
        &proof
    ));
}

#[test]
fn native_oracle_duplicate_oracle_id_rejects() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.descriptors[1].oracle_id = proof.descriptors[0].oracle_id;
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}

#[test]
fn native_oracle_unsorted_descriptors_reject() {
    let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
        native_oracle_fixture();
    proof.descriptors.reverse();
    assert!(!verify_fixture(
        &vk,
        relation_id,
        statement_digest,
        whir_digest,
        &proof
    ));
}
