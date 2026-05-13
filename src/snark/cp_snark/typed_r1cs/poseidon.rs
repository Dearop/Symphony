#[derive(Debug, Clone)]
struct Poseidon2Constants {
    external_initial: Vec<[u32; WIDTH]>,
    external_terminal: Vec<[u32; WIDTH]>,
    internal: Vec<u32>,
}

fn constants_for_domain(domain: &[u8]) -> Poseidon2Constants {
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(b"symphony-poseidon2-babybear-public-digest-v1");
    seed_hasher.update((domain.len() as u64).to_le_bytes());
    seed_hasher.update(domain);
    let seed: [u8; 32] = seed_hasher.finalize().into();

    let mut rng = ChaCha20Rng::from_seed(seed);
    let external_initial = (0..HALF_FULL_ROUNDS)
        .map(|_| sample_state(&mut rng))
        .collect();
    let external_terminal = (0..HALF_FULL_ROUNDS)
        .map(|_| sample_state(&mut rng))
        .collect();
    let internal = (0..PARTIAL_ROUNDS)
        .map(|_| sample_babybear(&mut rng))
        .collect();
    Poseidon2Constants {
        external_initial,
        external_terminal,
        internal,
    }
}

fn sample_state(rng: &mut ChaCha20Rng) -> [u32; WIDTH] {
    let elems: [BabyBear; WIDTH] = rng.sample(StandardUniform);
    elems.map(|v| v.as_canonical_u32())
}

fn sample_babybear(rng: &mut ChaCha20Rng) -> u32 {
    let elem: BabyBear = rng.sample(StandardUniform);
    elem.as_canonical_u32()
}

pub fn poseidon2_babybear_digest_elems(domain: &[u8], input: &[BabyBear]) -> [BabyBear; OUT] {
    let constants = constants_for_domain(domain);
    let mut state = [0u32; WIDTH];
    let input: Vec<u32> = input.iter().map(|v| v.as_canonical_u32()).collect();
    sponge_permute_input(&constants, &mut state, &input);
    core::array::from_fn(|idx| BabyBear::from_u32(state[idx]))
}

pub fn generate_poseidon2_digest_r1cs(
    domain: &[u8],
    input_len: usize,
) -> (R1CSMatrices, Poseidon2DigestR1csLayout) {
    let layout = Poseidon2DigestR1csLayout {
        input_len,
        off_one: 0,
        off_input: 1,
        off_output: 1 + input_len,
        num_public: 1 + input_len + OUT,
        num_variables: 0,
    };
    let constants = constants_for_domain(domain);
    let mut builder = Builder::new(layout.num_public, layout.off_one);
    let mut state: [Lin; WIDTH] = core::array::from_fn(|_| Lin::zero());
    let mut pos = 0usize;

    loop {
        let mut absorbed = 0usize;
        for i in 0..RATE {
            if pos < input_len {
                state[i] = Lin::var(layout.off_input + pos);
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    circuit_permutation(&mut builder, &constants, &mut state);
                }
                for (idx, item) in state.iter().enumerate().take(OUT) {
                    builder.constrain_eq(item.clone(), Lin::var(layout.off_output + idx));
                }
                let mut final_layout = layout;
                final_layout.num_variables = builder.next_var;
                return (builder.into_r1cs(final_layout.num_public), final_layout);
            }
        }
        circuit_permutation(&mut builder, &constants, &mut state);
    }
}

pub fn generate_poseidon2_private_digest_r1cs(
    domain: &[u8],
    input_len: usize,
) -> (R1CSMatrices, Poseidon2PrivateDigestR1csLayout) {
    let layout = Poseidon2PrivateDigestR1csLayout {
        input_len,
        off_one: 0,
        off_output: 1,
        off_input: 1 + OUT,
        num_public: 1 + OUT,
        num_variables: 0,
    };
    let constants = constants_for_domain(domain);
    let mut builder = Builder::new(layout.num_public, layout.off_one);
    builder.next_var = layout.off_input + input_len;
    let mut state: [Lin; WIDTH] = core::array::from_fn(|_| Lin::zero());
    let mut pos = 0usize;

    loop {
        let mut absorbed = 0usize;
        for i in 0..RATE {
            if pos < input_len {
                state[i] = Lin::var(layout.off_input + pos);
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    circuit_permutation(&mut builder, &constants, &mut state);
                }
                for (idx, item) in state.iter().enumerate().take(OUT) {
                    builder.constrain_eq(item.clone(), Lin::var(layout.off_output + idx));
                }
                let mut final_layout = layout;
                final_layout.num_variables = builder.next_var;
                return (builder.into_r1cs(final_layout.num_public), final_layout);
            }
        }
        circuit_permutation(&mut builder, &constants, &mut state);
    }
}

fn poseidon2_digest_permutation_count(input_len: usize) -> usize {
    input_len.div_ceil(RATE)
}

fn poseidon2_digest_aux_len(input_len: usize) -> usize {
    let sboxes_per_permutation = 2 * HALF_FULL_ROUNDS * WIDTH + PARTIAL_ROUNDS;
    poseidon2_digest_permutation_count(input_len) * sboxes_per_permutation * 4
}

fn poseidon2_direct_digest_constraints_count(input_len: usize) -> usize {
    poseidon2_digest_aux_len(input_len) + OUT
}

fn digest_template_input_lins(domain: &[u8], block: &TypedCpDigestBlockLayout) -> Vec<Lin> {
    let input_bytes = poseidon_digest_input_byte_template(domain, block.body_len);
    assert_eq!(block.input_len, input_bytes.len().div_ceil(3) + 1);
    assert!(
        input_bytes.len() < BB_P as usize,
        "typed CP digest body is too large for BabyBear length sentinel"
    );

    let mut inputs = Vec::with_capacity(block.input_len);
    for input_idx in 0..block.input_len {
        if input_idx + 1 == block.input_len {
            inputs.push(Lin::constant(0, input_bytes.len() as u32));
            continue;
        }

        let mut input = Lin::zero();
        for byte_offset in 0..3 {
            let source_idx = input_idx * 3 + byte_offset;
            let coeff = 1u32 << (8 * byte_offset);
            match input_bytes.get(source_idx).copied() {
                Some(DigestInputByte::Const(value)) => {
                    input = input.add(&Lin::constant(0, value as u32).scale(coeff));
                }
                Some(DigestInputByte::Body(body_idx)) => {
                    input = input.add(&Lin::var(block.off_body_bytes + body_idx).scale(coeff));
                }
                None => {}
            }
        }
        inputs.push(input);
    }
    inputs
}

fn generate_poseidon2_direct_digest_r1cs(
    domain: &[u8],
    block: &TypedCpDigestBlockLayout,
    num_public: usize,
) -> (R1CSMatrices, usize) {
    let input_lins = digest_template_input_lins(domain, block);
    let constants = constants_for_domain(domain);
    let mut builder = Builder::new(num_public, 0);
    builder.next_var = block.off_private_witness;
    let mut state: [Lin; WIDTH] = core::array::from_fn(|_| Lin::zero());
    let mut pos = 0usize;

    loop {
        let mut absorbed = 0usize;
        for item in state.iter_mut().take(RATE) {
            if pos < input_lins.len() {
                *item = input_lins[pos].clone();
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    circuit_permutation(&mut builder, &constants, &mut state);
                }
                for (idx, item) in state.iter().enumerate().take(OUT) {
                    builder.constrain_eq(item.clone(), Lin::var(block.off_public_output + idx));
                }
                let aux_end = builder.next_var;
                let num_variables = (block.off_body_bits + block.body_len * 8).max(aux_end);
                let r1cs = builder.into_r1cs_with_num_variables(num_public, num_variables);
                return (r1cs, aux_end);
            }
        }
        circuit_permutation(&mut builder, &constants, &mut state);
    }
}

pub fn encode_poseidon2_digest_instance(input: &[BabyBear], digest: &[BabyBear; OUT]) -> Vec<u8> {
    let mut out = Vec::with_capacity((1 + input.len() + OUT) * 8);
    out.extend_from_slice(&1i64.to_le_bytes());
    for elem in input {
        out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
    }
    for elem in digest {
        out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
    }
    out
}

pub fn encode_poseidon2_private_digest_instance(digest: &[BabyBear; OUT]) -> Vec<u8> {
    let mut out = Vec::with_capacity((1 + OUT) * 8);
    out.extend_from_slice(&1i64.to_le_bytes());
    for elem in digest {
        out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
    }
    out
}

pub fn encode_poseidon2_private_digest_witness(domain: &[u8], input: &[BabyBear]) -> Vec<u8> {
    let mut out = Vec::new();
    for elem in input {
        out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
    }
    out.extend_from_slice(&encode_poseidon2_digest_witness(domain, input));
    out
}

pub fn encode_poseidon2_digest_witness(domain: &[u8], input: &[BabyBear]) -> Vec<u8> {
    let constants = constants_for_domain(domain);
    let mut z_values = Vec::<u32>::new();
    let mut state = [0u32; WIDTH];
    let input_u32: Vec<u32> = input.iter().map(|v| v.as_canonical_u32()).collect();
    sponge_permute_input_recording(&constants, &mut state, &input_u32, &mut z_values);

    let mut out = Vec::with_capacity(z_values.len() * 8);
    for value in z_values {
        out.extend_from_slice(&(value as i64).to_le_bytes());
    }
    out
}

fn append_digest_body_binding_witness(out: &mut Vec<u8>, body: &[u8]) {
    for &byte in body {
        out.extend_from_slice(&(byte as i64).to_le_bytes());
    }
    for &byte in body {
        for bit in 0..8 {
            out.extend_from_slice(&(((byte >> bit) & 1) as i64).to_le_bytes());
        }
    }
}

pub fn poseidon2_digest32_from_body(domain: &[u8], body: &[u8]) -> Digest32 {
    let input = poseidon_digest_input_elems(domain, body);
    serialize_poseidon_digest_elems(poseidon2_babybear_digest_elems(domain, &input))
}

fn typed_beta_base5_components(byte: u8) -> (usize, usize, usize) {
    let d0 = (byte % 5) as usize;
    let d1 = ((byte / 5) % 5) as usize;
    let quotient = (byte / 25) as usize;
    debug_assert!(quotient < TYPED_BETA_QUOTIENT_SELECTOR_VALUES);
    (d0, d1, quotient)
}

pub fn poseidon_challenge_to_beta(challenge: &[u8]) -> Option<RingElement> {
    if challenge.len() != TYPED_BETA_CHALLENGE_BYTES || D != TYPED_BETA_CHALLENGE_BYTES * 2 {
        return None;
    }
    let mut coeffs = [0i64; D];
    for (byte_idx, &byte) in challenge.iter().enumerate() {
        let (d0, d1, _) = typed_beta_base5_components(byte);
        coeffs[2 * byte_idx] = d0 as i64 - 2;
        coeffs[2 * byte_idx + 1] = d1 as i64 - 2;
    }
    Some(RingElement { coeffs })
}

pub fn poseidon_challenges_to_betas(challenges: &[Vec<u8>]) -> Option<Vec<RingElement>> {
    challenges
        .iter()
        .map(|challenge| poseidon_challenge_to_beta(challenge))
        .collect()
}

pub fn poseidon_fs_commit_body(message: &[u8], opening: &Digest32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + message.len() + opening.len());
    body.extend_from_slice(&(message.len() as u64).to_le_bytes());
    body.extend_from_slice(message);
    body.extend_from_slice(opening);
    body
}

pub fn poseidon_fs_root_body(commitments: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(commitments.len() as u64).to_le_bytes());
    for commitment in commitments {
        body.extend_from_slice(&(commitment.len() as u64).to_le_bytes());
        body.extend_from_slice(commitment);
    }
    body
}

pub fn poseidon_fold_root_body(inputs: &[FoldInput]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
    for input in inputs {
        body.extend_from_slice(&(input.commitment_bytes.len() as u64).to_le_bytes());
        body.extend_from_slice(&input.commitment_bytes);
        body.extend_from_slice(&(input.public_input.len() as u64).to_le_bytes());
        for &value in &input.public_input {
            body.extend_from_slice(&value.to_le_bytes());
        }
        body.extend_from_slice(&(input.eval_values_bytes.len() as u64).to_le_bytes());
        body.extend_from_slice(&input.eval_values_bytes);
    }
    body
}

pub fn poseidon_challenge_digest_body(challenges: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(challenges.len() as u64).to_le_bytes());
    for challenge in challenges {
        body.extend_from_slice(&(challenge.len() as u64).to_le_bytes());
        body.extend_from_slice(challenge);
    }
    body
}

pub fn poseidon_transcript_seed_body(
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(public_inputs.len() as u64).to_le_bytes());
    for public_input in public_inputs {
        body.extend_from_slice(&(public_input.len() as u64).to_le_bytes());
        for &value in public_input {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    body.extend_from_slice(&(r1cs_m as u64).to_le_bytes());
    body.extend_from_slice(&(r1cs_n as u64).to_le_bytes());
    body.extend_from_slice(&(r1cs_pub as u64).to_le_bytes());
    body
}

pub fn poseidon_challenge_body(
    index: usize,
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
    fs_commitments: &[Vec<u8>],
) -> Vec<u8> {
    let transcript = crate::cp_relation_core::cp_relation_transcript_bytes(
        public_inputs,
        r1cs_m,
        r1cs_n,
        r1cs_pub,
        fs_commitments,
    );
    let mut body = Vec::with_capacity(8 + transcript.len());
    body.extend_from_slice(&(index as u64).to_le_bytes());
    body.extend_from_slice(&transcript);
    body
}

#[derive(Debug, Clone, Copy)]
enum DigestInputByte {
    Const(u8),
    Body(usize),
}

fn poseidon_digest_input_len(domain: &[u8], body_len: usize) -> usize {
    let byte_len = b"symphony-v2".len() + 8 + domain.len() + 8 + body_len;
    byte_len.div_ceil(3) + 1
}

fn poseidon_digest_input_byte_template(domain: &[u8], body_len: usize) -> Vec<DigestInputByte> {
    let mut bytes = Vec::with_capacity(b"symphony-v2".len() + 8 + domain.len() + 8 + body_len);
    bytes.extend(b"symphony-v2".iter().copied().map(DigestInputByte::Const));
    bytes.extend(
        (domain.len() as u64)
            .to_le_bytes()
            .into_iter()
            .map(DigestInputByte::Const),
    );
    bytes.extend(domain.iter().copied().map(DigestInputByte::Const));
    bytes.extend(
        (body_len as u64)
            .to_le_bytes()
            .into_iter()
            .map(DigestInputByte::Const),
    );
    bytes.extend((0..body_len).map(DigestInputByte::Body));
    bytes
}

