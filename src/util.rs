pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(&x, &y)| (x ^ y).count_ones() as usize)
        .sum()
}

/// PKCS#7 padding.
/// Adds between 1 and block_size bytes to the end of the message.
/// Each byte is equal to the number of bytes added.
pub fn pad_in_place(s: &mut Vec<u8>, block_size: usize) {
    assert!(block_size <= u8::MAX as usize);
    let remaining = block_size - s.len() % block_size;
    s.resize(s.len() + remaining, remaining as u8);
}

pub fn pad(s: &[u8], block_size: usize) -> Vec<u8> {
    let mut res = s.to_vec();
    pad_in_place(&mut res, block_size);
    res
}

/// Inverse PKCS#7 padding
pub fn unpad_in_place(s: &mut Vec<u8>) {
    let n = s.len();
    assert!(n > 0);
    let pad_length = s[n - 1] as usize;
    assert!(pad_length <= n);
    s.truncate(n - pad_length);
}

pub fn unpad(s: &[u8]) -> Vec<u8> {
    let mut res = s.to_vec();
    unpad_in_place(&mut res);
    res
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn hamming_distance_test() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37)
    }

    #[test]
    fn pad_test() {
        assert_eq!(
            pad(b"YELLOW SUBMARINE", 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
        assert_eq!(
            unpad(b"YELLOW SUBMARINE\x04\x04\x04\x04"),
            b"YELLOW SUBMARINE"
        );
    }
}
