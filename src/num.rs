use num_bigint::BigUint;

use crate::mac::sha1;

/// Turns a big integer into a key by sha1 hashing.
pub fn to_hash(x: &BigUint) -> [u8; 20] {
    sha1(&x.to_bytes_be())
}
