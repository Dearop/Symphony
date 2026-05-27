#[derive(Debug, Clone)]
pub struct NativeManifestSourceMembershipProof {
    pub batch_manifest_root: Digest32,
    pub native_proof: WhirNativeMultiOracleProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3ManifestSourceComponentValues {
    pub component_id: u32,
    pub kind: Symbt3ManifestComponentKind,
    pub visibility: Symbt3ManifestVisibility,
    pub layout_digest: Digest32,
    pub manifest_values: Vec<BabyBear>,
    pub source_values: Vec<BabyBear>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3ManifestComponentPublicView {
    pub component_id: u32,
    pub kind: Symbt3ManifestComponentKind,
    pub visibility: Symbt3ManifestVisibility,
    pub layout_digest: Digest32,
    pub value_count: usize,
    pub manifest_component_root: Digest32,
    pub source_component_root: Digest32,
    pub public_manifest_values: Vec<BabyBear>,
    pub public_source_values: Vec<BabyBear>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3CommittedPrivateManifestPublicStatement {
    pub manifest_policy: ManifestCommitmentPolicy,
    pub source_policy: SourceCommitmentPolicy,
    pub zk_status: Symbt3ZkStatus,
    pub root_policy: NativeOracleRootPolicy,
    pub manifest_layout_digest: Digest32,
    pub source_layout_digest: Digest32,
    pub manifest_oracle_root: Digest32,
    pub source_oracle_root: Digest32,
    pub batch_manifest_root: Digest32,
    pub components: Vec<Symbt3ManifestComponentPublicView>,
}

#[derive(Debug, Clone)]
pub struct Symbt3CommittedPrivateManifestMembershipProof {
    pub public_statement: Symbt3CommittedPrivateManifestPublicStatement,
    pub membership_proof: NativeManifestSourceMembershipProof,
}

#[derive(Debug, Clone)]
pub struct Symbt3CommittedPrivateManifestVerifyReport {
    pub ok: bool,
    pub native_report: WhirNativeOracleVerifyReport,
    pub committed_private_component_count: usize,
    pub committed_private_public_bytes: usize,
    pub public_statement_bytes: usize,
}

pub fn symbt3_manifest_component_values_root(
    role: WhirNativeOracleRole,
    component_id: u32,
    kind: Symbt3ManifestComponentKind,
    visibility: Symbt3ManifestVisibility,
    layout_digest: Digest32,
    values: &[BabyBear],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_MANIFEST_COMPONENT_VALUES_ROOT_V1");
    push_bytes(&mut bytes, &role.canonical_bytes());
    push_u32(&mut bytes, component_id);
    push_bytes(&mut bytes, &kind.canonical_bytes());
    push_bytes(&mut bytes, &visibility.canonical_bytes());
    push_digest(&mut bytes, &layout_digest);
    push_babybear_vec(&mut bytes, values);
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_manifest_oracle_layout_digest(
    role: WhirNativeOracleRole,
    components: &[Symbt3ManifestComponentPublicView],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_MANIFEST_ORACLE_LAYOUT_DIGEST_V1");
    push_bytes(&mut bytes, &role.canonical_bytes());
    push_u64(&mut bytes, components.len() as u64);
    for component in components {
        push_u32(&mut bytes, component.component_id);
        push_bytes(&mut bytes, &component.kind.canonical_bytes());
        push_bytes(&mut bytes, &component.visibility.canonical_bytes());
        push_digest(&mut bytes, &component.layout_digest);
        push_u64(&mut bytes, component.value_count as u64);
    }
    digest_bytes(&bytes)
}
