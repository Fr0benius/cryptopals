use crate::{
    ciphers::{encrypt_aes_128_ctr, decrypt_vigenere_fixed},
    convert::from_base64,
    oracles::padding_attack::{attack, PadAttackServer},
};

pub fn challenge17() {
    let mut server = PadAttackServer::new();
    for _ in 0..5 {
        let (cipher, iv) = server.encrypt();
        assert!(server.check_padding(&cipher, &iv));

        let plain = attack(&mut server, &cipher, &iv);
        assert_eq!(&plain, &server.last_plaintext());
    }
}

pub fn challenge18() {
    let cipher =
        from_base64(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    let plain = encrypt_aes_128_ctr(&cipher, b"YELLOW SUBMARINE", &[0u8; 8]);
    assert_eq!(
        &plain,
        b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    );
    let re_encrypted = encrypt_aes_128_ctr(&plain, b"YELLOW SUBMARINE", &[0u8; 8]);
    assert_eq!(&re_encrypted, &cipher);
}

pub fn challenge19() {
    // placeholder - this challenge involves manual tinkering.
    // Using letter frequency, similar to challenge 20 below
    // It turned out to be the poem "Easter, 1916" by Yeats.
}

pub fn challenge20() {
    let data: Vec<Vec<u8>> = 
        include_str!("../data/challenge20.txt")
        .lines()
        .map(|line| from_base64(line.as_bytes()))
        .collect();
    let min_len = data.iter().map(|s| s.len()).min().unwrap();
    let mut tot = vec![];
    for s in &data {
        tot.extend_from_slice(&s[..min_len]);
    }

    let (mut decrypted, _) = decrypt_vigenere_fixed(&tot, min_len);
    for w in decrypted.chunks_mut(min_len) {
        // The first character needs a little tweaking
        w[0] ^= b'n' ^ b'I';
    }
    let res: Vec<u8> = 
        include_str!("../data/challenge20out.txt")
        .bytes()
        .filter(|&c| c != b'\n')
        .collect();
    assert_eq!(&decrypted, &res);
}

#[test]
fn test_challenges() {
    challenge17();
    challenge18();
    challenge19();
    challenge20();
}
