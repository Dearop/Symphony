//! Serialization for Spartan context (R1CS + parameters).
//!
//! The context is stored in `RelationDescription::context` so that
//! the Spartan backend can access the R1CS matrices during prove/verify.

use crate::r1cs::{R1CSMatrices, SparseMatrix};

/// Spartan-specific context bundled into the relation description.
#[derive(Debug, Clone)]
pub struct SpartanContext {
    pub r1cs: R1CSMatrices,
    pub q: u64,
    pub d: usize,
    pub n_pub: usize,
    pub is_output_snark: bool,
}

/// Serialize a SpartanContext to bytes.
pub fn serialize_context(ctx: &SpartanContext) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header
    buf.extend_from_slice(b"SPRT");
    buf.extend_from_slice(&ctx.q.to_le_bytes());
    buf.extend_from_slice(&(ctx.d as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.n_pub as u64).to_le_bytes());
    buf.push(if ctx.is_output_snark { 1 } else { 0 });

    // R1CS dimensions
    buf.extend_from_slice(&(ctx.r1cs.num_constraints as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.r1cs.num_variables as u64).to_le_bytes());
    buf.extend_from_slice(&(ctx.r1cs.num_public as u64).to_le_bytes());

    // Serialize each matrix
    serialize_sparse_matrix(&mut buf, &ctx.r1cs.a);
    serialize_sparse_matrix(&mut buf, &ctx.r1cs.b);
    serialize_sparse_matrix(&mut buf, &ctx.r1cs.c);

    buf
}

/// Deserialize a SpartanContext from bytes.
pub fn deserialize_context(data: &[u8]) -> Option<SpartanContext> {
    if data.len() < 4 || &data[..4] != b"SPRT" {
        return None;
    }
    let mut pos = 4;

    let q = read_u64(data, &mut pos)?;
    let d = read_u64(data, &mut pos)? as usize;
    let n_pub = read_u64(data, &mut pos)? as usize;
    let is_output_snark = *data.get(pos)? != 0;
    pos += 1;

    let num_constraints = read_u64(data, &mut pos)? as usize;
    let num_variables = read_u64(data, &mut pos)? as usize;
    let r1cs_num_public = read_u64(data, &mut pos)? as usize;

    let a = deserialize_sparse_matrix(data, &mut pos, num_constraints, num_variables)?;
    let b = deserialize_sparse_matrix(data, &mut pos, num_constraints, num_variables)?;
    let c = deserialize_sparse_matrix(data, &mut pos, num_constraints, num_variables)?;

    Some(SpartanContext {
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
    })
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

        let ctx = SpartanContext {
            r1cs,
            q: 65537,
            d: 64,
            n_pub: 1,
            is_output_snark: true,
        };

        let bytes = serialize_context(&ctx);
        let ctx2 = deserialize_context(&bytes).expect("deserialize failed");

        assert_eq!(ctx2.q, ctx.q);
        assert_eq!(ctx2.d, ctx.d);
        assert_eq!(ctx2.n_pub, ctx.n_pub);
        assert_eq!(ctx2.is_output_snark, ctx.is_output_snark);
        assert_eq!(ctx2.r1cs.num_constraints, ctx.r1cs.num_constraints);
        assert_eq!(ctx2.r1cs.num_variables, ctx.r1cs.num_variables);
        assert_eq!(ctx2.r1cs.a.entries.len(), ctx.r1cs.a.entries.len());
    }

    #[test]
    fn invalid_header() {
        assert!(deserialize_context(b"XXXX").is_none());
        assert!(deserialize_context(b"").is_none());
    }
}
