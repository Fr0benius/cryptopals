pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let s = pad_with_length(msg, msg.len() * 8);
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
    let s = pad_with_length(suffix, total_len * 8);
    let h0 = u32::from_be_bytes(hash[0..4].try_into().unwrap());
    let h1 = u32::from_be_bytes(hash[4..8].try_into().unwrap());
    let h2 = u32::from_be_bytes(hash[8..12].try_into().unwrap());
    let h3 = u32::from_be_bytes(hash[12..16].try_into().unwrap());
    let h4 = u32::from_be_bytes(hash[16..20].try_into().unwrap());
    sha1_with_parameters(&s, h0, h1, h2, h3, h4)
}

pub fn pad_with_length(msg: &[u8], ml: usize) -> Vec<u8> {
    let mut s = msg.to_vec();
    s.push(0x80);
    let rem = (2 * 64 - 8 - s.len() % 64) % 64;
    s.resize(s.len() + rem, 0);
    s.extend_from_slice(&ml.to_be_bytes());
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

pub fn generate_mac(msg: &[u8], key: &[u8]) -> [u8; 20] {
    let mut s = key.to_vec();
    s.extend_from_slice(msg);
    sha1(&s)
}

pub fn verify_mac(msg: &[u8], key: &[u8], mac: &[u8]) -> bool {
    generate_mac(msg, key) == mac
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

        let padded_orig = pad_with_length(orig_message, orig_message.len() * 8);
        let suffix = b" the lazy dog";
        let combined = {
            let mut s = padded_orig.clone();
            s.extend_from_slice(suffix);
            s
        };
        let extended_hash = extend_sha1(&orig_hash, suffix, combined.len());
        assert_eq!(extended_hash, sha1(&combined));
    }
}
