use crate::{oracles::padding_attack::{PadAttackServer, attack}, ciphers::encrypt_aes_128_ctr, convert::from_base64};

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
    let cipher = from_base64(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    let plain = encrypt_aes_128_ctr(&cipher, b"YELLOW SUBMARINE", &[0u8; 8]);
    assert_eq!(&plain, b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
    let re_encrypted = encrypt_aes_128_ctr(&plain, b"YELLOW SUBMARINE", &[0u8; 8]);
    assert_eq!(&re_encrypted, &cipher);
}

#[test]
fn test_challenges() {
    challenge17();
    challenge18();
}
