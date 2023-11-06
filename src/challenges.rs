use std::collections::HashSet;

use crate::{
    ciphers::{
        decrypt_aes_128_cbc, decrypt_aes_128_ecb, decrypt_caesar, encrypt_aes_128_cbc, fixed_xor,
        multiple_decrypt_caesar, repeating_xor,
    },
    convert::{from_base64, from_hex, to_base64},
    oracles::{EcbOrCbc, Oracle, SecretSuffix, UserProfile, solve_secret_suffix},
    util::{hamming_distance, pad},
};

pub fn challenge1() {
    let s = from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(to_base64(&s), b64)
}

pub fn challenge2() {
    let a = from_hex("1c0111001f010100061a024b53535009181c");
    let b = from_hex("686974207468652062756c6c277320657965");
    let c = from_hex("746865206b696420646f6e277420706c6179");
    assert_eq!(fixed_xor(&a, &b), c)
}

pub fn challenge3() {
    let buf = from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let (decrypted, _) = decrypt_caesar(&buf);
    assert_eq!(decrypted, b"Cooking MC's like a pound of bacon");
}

pub fn challenge4() {
    let data = include_str!("../data/challenge4.txt");
    let texts: Vec<Vec<u8>> = data.lines().map(from_hex).collect();
    let (decrypted, _) = multiple_decrypt_caesar(texts.iter().map(|s| s.as_slice()));
    assert_eq!(decrypted, b"Now that the party is jumping\n");
}

pub fn challenge5() {
    let plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let expected = from_hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    assert_eq!(plain.len(), expected.len());
    let key = b"ICE";
    let cipher = repeating_xor(plain.as_bytes(), key);
    assert_eq!(cipher, expected);
}

pub fn challenge6() {
    let cipher = from_base64(include_str!("../data/challenge6.txt").as_bytes());
    let expected = include_str!("../data/funky_music.txt").as_bytes();
    let mut best_keysize = 0;
    let mut best_score = f64::MAX;
    for keysize in 2..=40 {
        let score = hamming_distance(&cipher[0..keysize * 20], &cipher[keysize..keysize * 21])
            as f64
            / keysize as f64;
        if score < best_score {
            best_keysize = keysize;
            best_score = score;
        }
    }
    let (plain, _) = crate::ciphers::decrypt_vigenere_fixed(&cipher, best_keysize);
    assert_eq!(plain, expected);
}

// to write bytes to a file:
// std::fs::write("/Users/zhulik/Coding/cryptopals/data/funky_music.txt", &plain).unwrap();
pub fn challenge7() {
    let cipher = from_base64(include_str!("../data/challenge7.txt").as_bytes());
    let expected = include_str!("../data/funky_music.txt").as_bytes();
    let key = b"YELLOW SUBMARINE";
    let plain = decrypt_aes_128_ecb(&cipher, key);
    assert_eq!(plain, expected);
}

pub fn challenge8() {
    let ciphers: Vec<_> = include_str!("../data/challenge8.txt")
        .lines()
        .map(from_hex)
        .collect();
    let good = ciphers.into_iter().enumerate().all(|(i, line)| {
        let set: HashSet<_> = line.chunks(16).collect();
        // Line 133 is ECB encoded
        if i == 132 {
            set.len() < 10
        } else {
            set.len() == 10
        }
    });
    assert!(good)
}

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
        assert_eq!(
            &test_cipher[..16],
            &test_cipher[16..16 * 2]
        );
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

#[test]
fn test_challenges() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
    challenge5();
    challenge6();
    challenge7();
    challenge8();
    challenge9();
    challenge10();
    challenge11();
    challenge12();
    challenge13();
    challenge14();
}
