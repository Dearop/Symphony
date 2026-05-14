//! Serialization for WHIR context (R1CS + parameters).
//!
//! Uses the same binary format as Spartan (header "WHIR" instead of "SPRT")
//! so that the WHIR backend can access R1CS matrices during prove/verify.

use crate::commitment::AjtaiParams;
use crate::params::D;
use crate::r1cs::{R1CSMatrices, SparseMatrix};
use crate::ring::RingElement;
use crate::snark::cp_snark::CpR1csLayout;

const TYPED_CP_CONTEXT_MAGIC: &[u8; 4] = b"TCP1";

/// WHIR-specific context bundled into the relation description.
#[derive(Debug, Clone)]
pub struct WhirContext {
    pub r1cs: R1CSMatrices,
    pub q: u64,
    pub d: usize,
    pub n_pub: usize,
    pub is_output_snark: bool,
    /// True when this context carries the CP-SNARK R1CS (folding constraints).
    pub is_cp_snark: bool,
    pub typed_cp: Option<WhirTypedCpContext>,
}

/// Extra public setup material needed to encode a typed CP witness.
#[derive(Debug, Clone)]
pub struct WhirTypedCpContext {
    pub ajtai: AjtaiParams,
    pub original_r1cs: R1CSMatrices,
    pub cp_layout: CpR1csLayout,
    pub lambda_pj: usize,
    pub ell_h: usize,
    pub k_g: usize,
}

/// Serialize a WhirContext to bytes.
pub fn serialize_context(ctx: &WhirContext) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(b"WHIR");
    buf.extend_from_slice(&ctx.q.to_le_bytes());
    buf.extend_from_slice(&(ctx.d as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.n_pub as u64).to_le_bytes());
    buf.push(if ctx.is_output_snark { 1 } else { 0 });
    buf.push(if ctx.is_cp_snark { 1 } else { 0 });

    buf.extend_from_slice(&(ctx.r1cs.num_constraints as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.r1cs.num_variables as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.r1cs.num_public as u64).to_le_bytes());

    serialize_sparse_matrix(&mut buf, &ctx.r1cs.a);
    serialize_sparse_matrix(&mut buf, &ctx.r1cs.b);
    serialize_sparse_matrix(&mut buf, &ctx.r1cs.c);
    if let Some(typed_cp) = &ctx.typed_cp {
        buf.extend_from_slice(TYPED_CP_CONTEXT_MAGIC);
        serialize_typed_cp_context(&mut buf, typed_cp);
    }

    buf
}

/// Deserialize a WhirContext from bytes.
pub fn deserialize_context(data: &[u8]) -> Option<WhirContext> {
    if data.len() < 4 || &data[..4] != b"WHIR" {
        return None;
    }
    let mut pos = 4;

    let q = read_u64(data, &mut pos)?;
    let d = read_u64(data, &mut pos)? as usize;
    let n_pub = read_u64(data, &mut pos)? as usize;
    let is_output_snark = *data.get(pos)? != 0;
    pos += 1;
    let is_cp_snark = *data.get(pos)? != 0;
    pos += 1;

    let num_constraints = read_u64(data, &mut pos)? as usize;
    let num_variables = read_u64(data, &mut pos)? as usize;
    let r1cs_num_public = read_u64(data, &mut pos)? as usize;

    let a = deserialize_sparse_matrix(data, &mut pos, num_constraints, num_variables)?;
    let b = deserialize_sparse_matrix(data, &mut pos, num_constraints, num_variables)?;
    let c = deserialize_sparse_matrix(data, &mut pos, num_constraints, num_variables)?;
    let typed_cp = if pos == data.len() {
        None
    } else {
        if pos + 4 > data.len() || &data[pos..pos + 4] != TYPED_CP_CONTEXT_MAGIC {
            return None;
        }
        pos += 4;
        let typed_cp = deserialize_typed_cp_context(data, &mut pos)?;
        if pos != data.len() {
            return None;
        }
        Some(typed_cp)
    };

    Some(WhirContext {
        r1cs: R1CSMatrices {
            a,
            b,
            c,
            num_constraints,
            num_variables,
            num_public: r1cs_num_public,
        },
        q,
        d,
        n_pub,
        is_output_snark,
        is_cp_snark,
        typed_cp,
    })
}

pub fn typed_cp_context_from_descriptor(
    descriptor: &crate::snark::TypedCpSetupDescriptor,
) -> WhirTypedCpContext {
    WhirTypedCpContext {
        ajtai: descriptor.ajtai.clone(),
        original_r1cs: descriptor.original_r1cs.clone(),
        cp_layout: descriptor.cp_layout.clone(),
        lambda_pj: descriptor.params.lambda_pj,
        ell_h: descriptor.params.ell_h,
        k_g: descriptor.params.k_g(),
    }
}

fn serialize_typed_cp_context(buf: &mut Vec<u8>, ctx: &WhirTypedCpContext) {
    buf.extend_from_slice(&(ctx.cp_layout.ell_np as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.cp_layout.kappa as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.cp_layout.n_in as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.original_r1cs.num_constraints as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.lambda_pj as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.ell_h as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.k_g as u64).to_le_bytes());
    serialize_ajtai(buf, &ctx.ajtai);
    buf.extend_from_slice(&(ctx.original_r1cs.num_constraints as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.original_r1cs.num_variables as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.original_r1cs.num_public as u64).to_le_bytes());
    serialize_sparse_matrix(buf, &ctx.original_r1cs.a);
    serialize_sparse_matrix(buf, &ctx.original_r1cs.b);
    serialize_sparse_matrix(buf, &ctx.original_r1cs.c);
}

fn deserialize_typed_cp_context(data: &[u8], pos: &mut usize) -> Option<WhirTypedCpContext> {
    let ell_np = read_u64(data, pos)? as usize;
    let kappa = read_u64(data, pos)? as usize;
    let n_in = read_u64(data, pos)? as usize;
    let cp_m = read_u64(data, pos)? as usize;
    let lambda_pj = read_u64(data, pos)? as usize;
    let ell_h = read_u64(data, pos)? as usize;
    let k_g = read_u64(data, pos)? as usize;
    let ajtai = deserialize_ajtai(data, pos)?;
    let num_constraints = read_u64(data, pos)? as usize;
    let num_variables = read_u64(data, pos)? as usize;
    let num_public = read_u64(data, pos)? as usize;
    let a = deserialize_sparse_matrix(data, pos, num_constraints, num_variables)?;
    let b = deserialize_sparse_matrix(data, pos, num_constraints, num_variables)?;
    let c = deserialize_sparse_matrix(data, pos, num_constraints, num_variables)?;
    Some(WhirTypedCpContext {
        ajtai,
        original_r1cs: R1CSMatrices {
            a,
            b,
            c,
            num_constraints,
            num_variables,
            num_public,
        },
        cp_layout: CpR1csLayout::new(ell_np, kappa, n_in, cp_m),
        lambda_pj,
        ell_h,
        k_g,
    })
}

fn serialize_ajtai(buf: &mut Vec<u8>, ajtai: &AjtaiParams) {
    buf.extend_from_slice(&(ajtai.kappa as u64).to_le_bytes());
    buf.extend_from_slice(&(ajtai.n as u64).to_le_bytes());
    buf.extend_from_slice(&ajtai.q.to_le_bytes());
    for row in &ajtai.a {
        for elem in row {
            serialize_ring_element(buf, elem);
        }
    }
}

fn deserialize_ajtai(data: &[u8], pos: &mut usize) -> Option<AjtaiParams> {
    let kappa = read_u64(data, pos)? as usize;
    let n = read_u64(data, pos)? as usize;
    let q = read_u64(data, pos)?;
    let ntt = crate::ring::ntt::NttContext::new(q);
    let mut a = Vec::with_capacity(kappa);
    for _ in 0..kappa {
        let mut row = Vec::with_capacity(n);
        for _ in 0..n {
            row.push(deserialize_ring_element(data, pos)?);
        }
        a.push(row);
    }
    let a_ntt = a
        .iter()
        .map(|row| row.iter().map(|elem| ntt.forward(elem)).collect())
        .collect();
    Some(AjtaiParams {
        a,
        a_ntt,
        ntt,
        kappa,
        n,
        q,
    })
}

fn serialize_ring_element(buf: &mut Vec<u8>, elem: &RingElement) {
    for &coeff in &elem.coeffs {
        buf.extend_from_slice(&coeff.to_le_bytes());
    }
}

fn deserialize_ring_element(data: &[u8], pos: &mut usize) -> Option<RingElement> {
    let mut coeffs = [0i64; D];
    for coeff in &mut coeffs {
        *coeff = read_i64(data, pos)?;
    }
    Some(RingElement { coeffs })
}

fn serialize_sparse_matrix(buf: &mut Vec<u8>, mat: &SparseMatrix) {
    buf.extend_from_slice(&(mat.entries.len() as u64).to_le_bytes());
    for &(row, col, val) in &mat.entries {
        buf.extend_from_slice(&(row as u64).to_le_bytes());
        buf.extend_from_slice(&(col as u64).to_le_bytes());
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

fn deserialize_sparse_matrix(
    data: &[u8],
    pos: &mut usize,
    num_rows: usize,
    num_cols: usize,
) -> Option<SparseMatrix> {
    let nnz = read_u64(data, pos)? as usize;
    let mut mat = SparseMatrix::new(num_rows, num_cols);
    for _ in 0..nnz {
        let row = read_u64(data, pos)? as usize;
        let col = read_u64(data, pos)? as usize;
        let val = read_i64(data, pos)?;
        if val != 0 {
            mat.entries.push((row, col, val));
        }
    }
    Some(mat)
}

fn read_u64(data: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos + 8 > data.len() {
        return None;
    }
    let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().ok()?);
    *pos += 8;
    Some(val)
}

fn read_i64(data: &[u8], pos: &mut usize) -> Option<i64> {
    if *pos + 8 > data.len() {
        return None;
    }
    let val = i64::from_le_bytes(data[*pos..*pos + 8].try_into().ok()?);
    *pos += 8;
    Some(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut r1cs = R1CSMatrices::new(2, 3, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 1, 1);
        r1cs.c.insert(0, 2, 1);
        r1cs.a.insert(1, 0, 3);
        r1cs.b.insert(1, 2, -2);
        r1cs.c.insert(1, 1, 5);

        let ctx = WhirContext {
            r1cs,
            q: 65537,
            d: 64,
            n_pub: 1,
            is_output_snark: true,
            is_cp_snark: false,
            typed_cp: None,
        };

        let bytes = serialize_context(&ctx);
        let ctx2 = deserialize_context(&bytes).expect("deserialize failed");

        assert_eq!(ctx2.q, ctx.q);
        assert_eq!(ctx2.d, ctx.d);
        assert_eq!(ctx2.n_pub, ctx.n_pub);
        assert_eq!(ctx2.is_output_snark, ctx.is_output_snark);
        assert_eq!(ctx2.is_cp_snark, ctx.is_cp_snark);
        assert_eq!(ctx2.r1cs.num_constraints, ctx.r1cs.num_constraints);
        assert_eq!(ctx2.r1cs.num_variables, ctx.r1cs.num_variables);
        assert_eq!(ctx2.r1cs.a.entries.len(), ctx.r1cs.a.entries.len());
    }

    #[test]
    fn invalid_header() {
        assert!(deserialize_context(b"XXXX").is_none());
        assert!(deserialize_context(b"").is_none());
        assert!(deserialize_context(b"SPRT").is_none());
    }
}
