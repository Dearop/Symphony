//! Shared test helpers and constants.

#![allow(dead_code)]

pub const Q: u64 = 257;

pub fn ctx() -> symphony::ring::extension::ExtFieldContext {
    symphony::ring::extension::ExtFieldContext::new(Q)
}

pub fn simple_r1cs() -> (symphony::r1cs::R1CSMatrices, Vec<i64>) {
    let m = 2;
    let n = 3;
    let mut r1cs = symphony::r1cs::R1CSMatrices::new(m, n, 1);
    r1cs.a.insert(0, 1, 1);
    r1cs.b.insert(0, 1, 1);
    r1cs.c.insert(0, 2, 1);
    let z = vec![1i64, 3, 9];
    (r1cs, z)
}

pub fn multi_r1cs() -> (symphony::r1cs::R1CSMatrices, Vec<i64>) {
    let m = 4;
    let n = 4;
    let mut r1cs = symphony::r1cs::R1CSMatrices::new(m, n, 1);
    r1cs.a.insert(0, 1, 1);
    r1cs.b.insert(0, 2, 1);
    r1cs.c.insert(0, 3, 1);
    r1cs.a.insert(1, 1, 1);
    r1cs.b.insert(1, 0, 1);
    r1cs.c.insert(1, 1, 1);
    let z = vec![1i64, 3, 5, 15];
    (r1cs, z)
}
