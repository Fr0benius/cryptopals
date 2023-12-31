use num_bigint::BigUint;

use crate::num::to_hash;

pub fn challenge33() {
    let p = BigUint::parse_bytes(
        b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
        16,
    )
    .unwrap();
    let g: BigUint = 2u32.into();
    let a: BigUint = 12345u32.into();
    let b: BigUint = 691234u32.into();
    let a_exp = g.modpow(&a, &p);
    let b_exp = g.modpow(&b, &p);
    let a_key = to_hash(&a_exp.modpow(&b, &p));
    let b_key = to_hash(&b_exp.modpow(&a, &p));
    assert_eq!(&a_key, &b_key);
}

#[test]
fn test_challenges() {
    challenge33();
}
