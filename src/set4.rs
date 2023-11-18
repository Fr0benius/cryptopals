use crate::{
    ciphers::{decrypt_aes_128_cbc, encrypt_aes_128_cbc, encrypt_aes_128_ctr, fixed_xor},
    oracles::ra_ctr::RandomAccessCTR,
    util::parse_cookie,
};

pub fn challenge25() {
    let plain = include_str!("../data/funky_music.txt").as_bytes();
    let mut server = RandomAccessCTR::new(b"Yellow Submarine", plain);
    let cipher = server.ciphertext();
    let n = cipher.len();
    server.edit(0, &vec![0; n]);
    let keystream = server.ciphertext();
    let recovered = fixed_xor(&cipher, &keystream);
    assert_eq!(&plain, &recovered);
}

pub fn challenge26() {
    let secret_key = b"MANNY && GLOTTIS";
    let pref = b"comment1=cooking%20MCs;userdata=";
    let suf = b";comment2=%20like%20a%20pound%20of%20bacon";
    let plain = {
        let mut v = pref.to_vec();
        v.extend_from_slice(&[0; 32]);
        v.extend_from_slice(suf);
        v
    };
    let mut cipher = encrypt_aes_128_ctr(&plain, secret_key, &[0; 8]);
    let wanted = b";role=admin;a=";
    for i in 0..wanted.len() {
        cipher[pref.len() + i] ^= wanted[i];
    }
    let hacked_plain = encrypt_aes_128_ctr(&cipher, secret_key, &[0; 8]);
    let dict = parse_cookie(&hacked_plain, b';');
    assert_eq!(dict[&b"role".to_vec()], b"admin");
}

pub fn challenge27() {
    let secret_key = b"MANNY && GLOTTIS";
    let plain = [b'a'; 16 * 5];
    let cipher = encrypt_aes_128_cbc(&plain, secret_key, secret_key);
    let mut attack = cipher[..16].to_vec();
    attack.extend_from_slice(&[0; 16]);
    attack.extend_from_within(0..16);
    attack.extend_from_slice(&cipher[48..]);
    let res = decrypt_aes_128_cbc(&attack, secret_key, secret_key);
    assert!(res.iter().any(|&c| c >= 128));
    let cracked_key = fixed_xor(&res[..16], &res[32..48]);
    assert_eq!(&cracked_key, secret_key);
}

#[test]
fn test_challenges() {
    challenge25();
    challenge26();
    challenge27();
}
