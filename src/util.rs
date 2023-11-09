use std::collections::HashMap;

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

/// Find the length of the padding, if valid.
/// If invalid, return 0;
pub fn padding_length(s: &[u8]) -> usize {
    let n = s.len();
    let pad_length = s[n - 1] as usize;
    if pad_length == 0 || pad_length > n {
        return 0;
    }
    if !(s[n - pad_length..].iter().all(|&c| c == s[n - 1])) {
        return 0;
    }
    pad_length
}

/// Inverse PKCS#7 padding
pub fn unpad_in_place(s: &mut Vec<u8>) {
    let n = s.len();
    assert!(n > 0);
    let pad_length = padding_length(s);
    assert!(pad_length != 0);
    s.truncate(n - pad_length);
}

pub fn unpad(s: &[u8]) -> Vec<u8> {
    let mut res = s.to_vec();
    unpad_in_place(&mut res);
    res
}

/// Encodes a byte slice into URL form.
/// Only treats some characters as special.
pub fn url_encode(s: &[u8]) -> Vec<u8> {
    let mut res = vec![];
    for &c in s {
        match c {
            b' ' => res.extend_from_slice(b"%20"),
            b'%' => res.extend_from_slice(b"%25"),
            b'&' => res.extend_from_slice(b"%26"),
            b';' => res.extend_from_slice(b"%3B"),
            b'=' => res.extend_from_slice(b"%3D"),
            _ => res.push(c),
        }
    }
    res
}

/// Decodes a byte slice from URL form.
/// Only treats some characters as special.
/// Panics on invalid %-code.
pub fn url_decode(s: &[u8]) -> Vec<u8> {
    let n = s.len();
    let mut res = vec![];
    let mut i = 0;
    while i < n {
        if s[i] == b'%' {
            assert!(i < n - 1, "invalid %-code");
            match &s[i + 1..=i + 2] {
                b"20" => res.push(b' '),
                b"25" => res.push(b'%'),
                b"26" => res.push(b'&'),
                b"3B" => res.push(b';'),
                b"3D" => res.push(b'='),
                _ => panic!("invalid %-code"),
            }
            i += 3;
        } else {
            res.push(s[i]);
            i += 1;
        }
    }
    res
}

/// Parses a key-value cookie string of the form "foo=bar&baz=qux&zap=zazzle"
/// Returns a map of keys to values.
/// Keys and values are url-decoded. Panics on decoding error or malformed string.
pub fn parse_cookie(s: &[u8], separator: u8) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut res = HashMap::new();
    for kv in s.split(|&c| c == separator) {
        let kv: Vec<_> = kv.split(|&c| c == b'=').collect();
        assert_eq!(kv.len(), 2, "Each kv-pair must be of the form X=Y");
        res.insert(url_decode(kv[0]), url_decode(kv[1]));
    }
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

    #[test]
    fn url_encoding_test() {
        let raw = b"foo@bar.com&role=admin%";
        let encoded = b"foo@bar.com%26role%3Dadmin%25";
        assert_eq!(&url_encode(raw), encoded);
        assert_eq!(&url_decode(encoded), raw);
    }
    #[test]
    fn parse_cookie_test() {
        let cookie = b"foo=bar&baz=qux&zap=zazzle&%25%26=a%3Db";
        let map = HashMap::from([
            (b"foo".to_vec(), b"bar".to_vec()),
            (b"baz".to_vec(), b"qux".to_vec()),
            (b"zap".to_vec(), b"zazzle".to_vec()),
            (b"%&".to_vec(), b"a=b".to_vec()),
        ]);
        assert_eq!(parse_cookie(cookie, b'&'), map);
    }
}
