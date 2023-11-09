use crate::oracles::padding_attack::{PadAttackServer, attack};

pub fn challenge17() {
    let mut server = PadAttackServer::new();
    for _ in 0..5 {
        let (cipher, iv) = server.encrypt();
        assert!(server.check_padding(&cipher, &iv));

        let plain = attack(&mut server, &cipher, &iv);
        assert_eq!(&plain, &server.last_plaintext());
    }
}

#[test]
fn test_challenges() {
    challenge17();
}
