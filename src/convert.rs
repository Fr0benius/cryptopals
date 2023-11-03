/// Converts a base 16 character to a number
fn hex_to_num(c: u8) -> u8 {
    if c.is_ascii_digit() {
        return c - b'0';
    } else if (b'A'..=b'F').contains(&c) {
        return c - b'A' + 10;
    } else if (b'a'..=b'f').contains(&c) {
        return c - b'a' + 10;
    }
    unreachable!()
}

//// Converts a number in the range [0, 16) to a hex character
fn num_to_hex(n: u8) -> char {
    if (0..10).contains(&n) {
        (b'0' + n) as char
    } else {
        (b'A' + (n - 10)) as char
    }
}

pub fn from_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "Hex string must have even length");
    let mut res = Vec::with_capacity(hex.len() / 2);
    for w in hex.as_bytes().chunks_exact(2) {
        res.push((hex_to_num(w[0]) << 4) + hex_to_num(w[1]));
    }
    res
}

pub fn to_hex(bstr: &[u8]) -> String {
    bstr.iter().copied().map(num_to_hex).collect()
}

//// Converts a number in the range [0, 64) to a b64 character
fn num_to_base64(n: u8) -> char {
    match n {
        _ if n < 26 => (b'A' + n) as char,
        _ if n < 52 => (b'a' + (n - 26)) as char,
        _ if n < 62 => (b'0' + (n - 52)) as char,
        62 => '+',
        63 => '/',
        _ => unimplemented!("Out of range"),
    }
}

//// Converts a b64 character into the corresponding number
fn base64_to_num(c: u8) -> u8 {
    match c {
        _ if c.is_ascii_uppercase() => c - b'A',
        _ if c.is_ascii_lowercase() => 26 + (c - b'a'),
        _ if c.is_ascii_digit() => 52 + (c - b'0'),
        b'+' => 62,
        b'/' => 63,
        _ => unimplemented!("Invalid base64 character: {}", c as char),
    }
}

/// Takes a base64 ASCII string with optional padding and decodes into a bytestring
/// Skips whitespace
pub fn from_base64(b64: &[u8]) -> Vec<u8> {
    let mut buf;
    let mut iter = b64.iter().filter(|c| !c.is_ascii_whitespace());
    let mut res = vec![];
    loop {
        let mut k = 0;
        buf = [0u8; 4];
        while k < 4 {
            if let Some(&c) = iter.next() {
                if c == b'=' {
                    break;
                }
                buf[k] = base64_to_num(c);
                k += 1;
            } else {
                break;
            }
        }
        if k == 0 {
            break;
        }
        assert!(k >= 2, "Base64 string cannot have a chunk of size 1");
        res.push((buf[0] << 2) | (buf[1] >> 4));
        if k >= 3 {
            res.push(((buf[1] & 0x0F) << 4) | (buf[2] >> 2));
        }
        if k >= 4 {
            res.push(((buf[2] & 0x03) << 6) | buf[3]);
        }
    }
    res
}

/// Takes a bytestring and encodes as base64. Output is padded and always has length divisible by 4.
pub fn to_base64(bstr: &[u8]) -> String {
    let mut res = vec![];
    for w in bstr.chunks(3) {
        let a = w[0];
        let b = if w.len() >= 2 { w[1] } else { 0 };
        let c = if w.len() >= 3 { w[2] } else { 0 };
        res.push(num_to_base64((a >> 2) & 0x3F));
        res.push(num_to_base64(((a & 0x03) << 4) + ((b >> 4) & 0x3F)));
        if w.len() >= 2 {
            res.push(num_to_base64(((b & 0x0F) << 2) + ((c >> 6) & 0x3F)));
        } else {
            res.push('=');
        }
        if w.len() >= 3 {
            res.push(num_to_base64(c & 0x3F));
        } else {
            res.push('=');
        }
    }
    res.into_iter().collect()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn base64_small_test() {
        assert_eq!(to_base64(b"Man"), "TWFu");
        assert_eq!(from_base64(b"TWFu"), b"Man");
        assert_eq!(to_base64(b"Ma"), "TWE=");
        assert_eq!(from_base64(b"TWE="), b"Ma");
        assert_eq!(from_base64(b"TWE"), b"Ma");
        assert_eq!(to_base64(b"M"), "TQ==");
        assert_eq!(from_base64(b"TQ=="), b"M");
        assert_eq!(from_base64(b"TQ"), b"M");
    }

    #[test]
    fn base64_medium_test() {
        let s = from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(to_base64(&s), b64);
        assert_eq!(&from_base64(b64.as_bytes()), &s);
    }
}
