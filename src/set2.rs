use crate::{
    ciphers::{decrypt_aes_128_cbc, encrypt_aes_128_cbc},
    convert::from_base64,
    oracles::{solve_secret_suffix, EcbOrCbc, Oracle, SecretSuffix, UserProfile},
    util::{pad, parse_cookie, unpad},
};

pub fn challenge9() {
    assert_eq!(
        pad(b"YELLOW SUBMARINE", 20),
        b"YELLOW SUBMARINE\x04\x04\x04\x04"
    );
}

pub fn challenge10() {
    let cipher = from_base64(include_str!("../data/challenge10.txt").as_bytes());
    let expected = include_str!("../data/funky_music.txt").as_bytes();
    let key = b"YELLOW SUBMARINE";
    let plain = decrypt_aes_128_cbc(&cipher, key, &[0u8; 16]);
    assert_eq!(plain, expected);
    let re_encrypted = encrypt_aes_128_cbc(&plain, key, &[0u8; 16]);
    assert_eq!(re_encrypted, cipher);
}

pub fn challenge11() {
    let mut oracle = EcbOrCbc::new(12345);
    for _ in 0..10 {
        let plain = vec![b'x'; 64];
        let cipher = oracle.query(&plain);
        let is_ecb = cipher[16..32] == cipher[32..48];
        assert!(oracle.is_ecb() == is_ecb);
    }
}

pub fn challenge12() {
    let mut oracle = SecretSuffix::new();
    // Confirm it's ECB
    {
        let test_cipher = oracle.query(&[b'a'; 16 * 3]);
        assert_eq!(&test_cipher[..16], &test_cipher[16..16 * 2]);
    }
    let message = solve_secret_suffix(&mut oracle);
    let expected = from_base64(
        b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK",
    );
    assert_eq!(expected, message);
}

pub fn challenge13() {
    let mut oracle = UserProfile::new();
    let mut cipher: Vec<u8> = vec![];
    // email=xyz@gmail.com&uid=XX&role=
    cipher.extend(&oracle.query(b"xyz@gmail.com")[..32]);
    // admin&uid=xx&rol
    cipher.extend(&oracle.query(b"xyz@gmail.admin")[16..32]);
    // =user
    cipher.extend(&oracle.query(b"xyzz@gmail.admin")[32..48]);
    let dict = oracle.parse(&cipher);
    assert_eq!(dict[&b"email".to_vec()], b"xyz@gmail.com");
    assert_eq!(dict[&b"role".to_vec()], b"admin");
    assert_eq!(dict[&b"rolle".to_vec()], b"user");
}

pub fn challenge14() {
    let mut oracle = SecretSuffix::with_prefix();
    let message = solve_secret_suffix(&mut oracle);
    let expected = from_base64(
        b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK",
    );
    assert_eq!(expected, message);
}

pub fn challenge15() {
    assert_eq!(unpad(b"ICE ICE BABY\x04\x04\x04\x04"), b"ICE ICE BABY");
    let res = std::panic::catch_unwind(|| unpad(b"ICE ICE BABY\x05\x05\x05\x05"));
    assert!(res.is_err());
}

pub fn challenge16() {
    let secret_key = b"MANNY && GLOTTIS";
    let pref = b"comment1=cooking%20MCs;userdata=";
    let suf = b";comment2=%20like%20a%20pound%20of%20bacon";
    let wanted = b"xxxxx;role=admin";
    let plain = {
        let mut v = pref.to_vec();
        v.extend_from_slice(&[1; 32]);
        v.extend_from_slice(suf);
        v
    };
    let mut cipher = encrypt_aes_128_cbc(&plain, secret_key, &[0; 16]);
    for i in 0..16 {
        cipher[32 + i] ^= wanted[i] ^ 1;
    }
    let hacked_plain = decrypt_aes_128_cbc(&cipher, secret_key, &[0; 16]);
    assert!(hacked_plain.windows(16).any(|w| w == wanted));
    let dict = parse_cookie(&hacked_plain, b';');
    assert!(dict[&b"role".to_vec()] == b"admin");
}

#[test]
fn test_challenges() {
    challenge9();
    challenge10();
    challenge11();
    challenge12();
    challenge13();
    challenge14();
    challenge15();
    challenge16();
}
