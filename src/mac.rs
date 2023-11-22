pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let s = pad_with_length(msg, msg.len() * 8, true);
    sha1_with_parameters(
        &s,
        0x67452301u32,
        0xEFCDAB89u32,
        0x98BADCFEu32,
        0x10325476u32,
        0xC3D2E1F0u32,
    )
}

/// Takes the SHA1 hash of a message and computes the SHA1 of the same message, extended with extra
/// characters after the message and padding.
/// Requires knowing the total length of the combined message
/// (original message + padding + suffix)
pub fn extend_sha1(hash: &[u8], suffix: &[u8], total_len: usize) -> [u8; 20] {
    assert_eq!(hash.len(), 20);
    let s = pad_with_length(suffix, total_len * 8, true);
    let h0 = u32::from_be_bytes(hash[0..4].try_into().unwrap());
    let h1 = u32::from_be_bytes(hash[4..8].try_into().unwrap());
    let h2 = u32::from_be_bytes(hash[8..12].try_into().unwrap());
    let h3 = u32::from_be_bytes(hash[12..16].try_into().unwrap());
    let h4 = u32::from_be_bytes(hash[16..20].try_into().unwrap());
    sha1_with_parameters(&s, h0, h1, h2, h3, h4)
}

/// Pads the message with a 1-bit, some number of 0-bits, and a number representing the message
/// length in bits. Output is guaranteed to have length divisible by 64 bytes (512 bits).
/// If "be" is true, the length will be in big-endian format, otherwise little-endian.
pub fn pad_with_length(msg: &[u8], ml: usize, be: bool) -> Vec<u8> {
    let mut s = msg.to_vec();
    s.push(0x80);
    let rem = (2 * 64 - 8 - s.len() % 64) % 64;
    s.resize(s.len() + rem, 0);
    if be {
        s.extend_from_slice(&ml.to_be_bytes());
    } else {
        s.extend_from_slice(&ml.to_le_bytes());
    }
    assert_eq!(s.len() % 64, 0);
    s
}

fn sha1_with_parameters(
    s: &[u8],
    mut h0: u32,
    mut h1: u32,
    mut h2: u32,
    mut h3: u32,
    mut h4: u32,
) -> [u8; 20] {
    let mut w = [0u32; 80];
    for chunk in s.chunks(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6u32),
                _ => unreachable!(),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut res = [0u8; 20];
    res[0..4].copy_from_slice(&h0.to_be_bytes());
    res[4..8].copy_from_slice(&h1.to_be_bytes());
    res[8..12].copy_from_slice(&h2.to_be_bytes());
    res[12..16].copy_from_slice(&h3.to_be_bytes());
    res[16..20].copy_from_slice(&h4.to_be_bytes());
    res
}

pub fn md4(msg: &[u8]) -> [u8; 16] {
    let s = pad_with_length(msg, msg.len() * 8, false);
    md4_with_parameters(&s, 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
}

/// Similar to extend_sha1, but for md4
pub fn extend_md4(hash: &[u8], suffix: &[u8], total_len: usize) -> [u8; 16] {
    assert_eq!(hash.len(), 16);
    let s = pad_with_length(suffix, total_len * 8, false);
    let h0 = u32::from_le_bytes(hash[0..4].try_into().unwrap());
    let h1 = u32::from_le_bytes(hash[4..8].try_into().unwrap());
    let h2 = u32::from_le_bytes(hash[8..12].try_into().unwrap());
    let h3 = u32::from_le_bytes(hash[12..16].try_into().unwrap());
    md4_with_parameters(&s, h0, h1, h2, h3)
}

fn md4_with_parameters(s: &[u8], mut h0: u32, mut h1: u32, mut h2: u32, mut h3: u32) -> [u8; 16] {
    let mut w = [0u32; 16];
    for chunk in s.chunks(64) {
        for i in 0..16 {
            w[i] = u32::from_le_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let f = |x: u32, y: u32, z: u32| (x & y) | ((!x) & z);
        let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
        let h = |x: u32, y: u32, z: u32| x ^ y ^ z;

        let params = [
            [0, 3, 1, 7, 2, 11, 3, 19],
            [4, 3, 5, 7, 6, 11, 7, 19],
            [8, 3, 9, 7, 10, 11, 11, 19],
            [12, 3, 13, 7, 14, 11, 15, 19],
        ];

        for p in params {
            a = a
                .wrapping_add(f(b, c, d))
                .wrapping_add(w[p[0]])
                .rotate_left(p[1] as u32);
            d = d
                .wrapping_add(f(a, b, c))
                .wrapping_add(w[p[2]])
                .rotate_left(p[3] as u32);
            c = c
                .wrapping_add(f(d, a, b))
                .wrapping_add(w[p[4]])
                .rotate_left(p[5] as u32);
            b = b
                .wrapping_add(f(c, d, a))
                .wrapping_add(w[p[6]])
                .rotate_left(p[7] as u32);
        }
        let params = [
            [0, 3, 4, 5, 8, 9, 12, 13],
            [1, 3, 5, 5, 9, 9, 13, 13],
            [2, 3, 6, 5, 10, 9, 14, 13],
            [3, 3, 7, 5, 11, 9, 15, 13],
        ];
        for p in params {
            let z = 0x5A827999u32;
            a = a
                .wrapping_add(g(b, c, d))
                .wrapping_add(w[p[0]])
                .wrapping_add(z)
                .rotate_left(p[1] as u32);
            d = d
                .wrapping_add(g(a, b, c))
                .wrapping_add(w[p[2]])
                .wrapping_add(z)
                .rotate_left(p[3] as u32);
            c = c
                .wrapping_add(g(d, a, b))
                .wrapping_add(w[p[4]])
                .wrapping_add(z)
                .rotate_left(p[5] as u32);
            b = b
                .wrapping_add(g(c, d, a))
                .wrapping_add(w[p[6]])
                .wrapping_add(z)
                .rotate_left(p[7] as u32);
        }
        let params = [
            [0, 3, 8, 9, 4, 11, 12, 15],
            [2, 3, 10, 9, 6, 11, 14, 15],
            [1, 3, 9, 9, 5, 11, 13, 15],
            [3, 3, 11, 9, 7, 11, 15, 15],
        ];
        for p in params {
            let z = 0x6ED9EBA1u32;
            a = a
                .wrapping_add(h(b, c, d))
                .wrapping_add(w[p[0]])
                .wrapping_add(z)
                .rotate_left(p[1] as u32);
            d = d
                .wrapping_add(h(a, b, c))
                .wrapping_add(w[p[2]])
                .wrapping_add(z)
                .rotate_left(p[3] as u32);
            c = c
                .wrapping_add(h(d, a, b))
                .wrapping_add(w[p[4]])
                .wrapping_add(z)
                .rotate_left(p[5] as u32);
            b = b
                .wrapping_add(h(c, d, a))
                .wrapping_add(w[p[6]])
                .wrapping_add(z)
                .rotate_left(p[7] as u32);
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
    }
    let mut res = [0u8; 16];
    res[0..4].copy_from_slice(&h0.to_le_bytes());
    res[4..8].copy_from_slice(&h1.to_le_bytes());
    res[8..12].copy_from_slice(&h2.to_le_bytes());
    res[12..16].copy_from_slice(&h3.to_le_bytes());
    res
}

/// Prefix MAC - hash(key + message)
pub fn generate_sha1_mac(msg: &[u8], key: &[u8]) -> [u8; 20] {
    let mut s = key.to_vec();
    s.extend_from_slice(msg);
    sha1(&s)
}

pub fn generate_sha1_hmac(msg: &[u8], key: &[u8]) -> [u8; 20] {
    let block_key = {
        let mut s = if key.len() > 64 {
            sha1(key).to_vec()
        } else {
            key.to_vec()
        };
        s.resize(64, 0u8);
        s
    };
    let inner: Vec<u8> = block_key
        .iter()
        .map(|&c| c ^ 0x36)
        .chain(msg.iter().copied())
        .collect();
    let outer: Vec<u8> = block_key
        .iter()
        .map(|&c| c ^ 0x5c)
        .chain(sha1(&inner))
        .collect();
    sha1(&outer)
}

pub fn verify_sha1_mac(msg: &[u8], key: &[u8], mac: &[u8]) -> bool {
    generate_sha1_mac(msg, key) == mac
}

pub fn generate_md4_mac(msg: &[u8], key: &[u8]) -> [u8; 16] {
    let mut s = key.to_vec();
    s.extend_from_slice(msg);
    md4(&s)
}

pub fn verify_md4_mac(msg: &[u8], key: &[u8], mac: &[u8]) -> bool {
    generate_md4_mac(msg, key) == mac
}

#[cfg(test)]
pub mod tests {
    use crate::convert::to_hex;

    use super::*;

    #[test]
    fn test_sha1() {
        assert_eq!(
            to_hex(&sha1(b"The quick brown fox jumps over the lazy dog")),
            "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"
        );
        assert_eq!(
            to_hex(&sha1(b"The quick brown fox jumps over the lazy cog")),
            "DE9F2C7FD25E1B3AFAD3E85A0BD17D9B100DB4B3"
        );
        assert_eq!(
            to_hex(&sha1(b"")),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
    }
    #[test]
    fn test_extend_sha1() {
        let orig_message = b"The quick brown fox";
        let orig_hash = sha1(orig_message);

        let padded_orig = pad_with_length(orig_message, orig_message.len() * 8, true);
        let suffix = b" the lazy dog";
        let combined = {
            let mut s = padded_orig.clone();
            s.extend_from_slice(suffix);
            s
        };
        let extended_hash = extend_sha1(&orig_hash, suffix, combined.len());
        assert_eq!(extended_hash, sha1(&combined));
    }
    #[test]
    fn test_md4() {
        assert_eq!(
            to_hex(&md4(b"The quick brown fox jumps over the lazy dog")),
            "1BEE69A46BA811185C194762ABAEAE90"
        );
        assert_eq!(
            to_hex(&md4(b"The quick brown fox jumps over the lazy cog")),
            "B86E130CE7028DA59E672D56AD0113DF"
        );
        assert_eq!(to_hex(&md4(b"")), "31D6CFE0D16AE931B73C59D7E0C089C0");
    }
}
