use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    ciphers::{decrypt_vigenere_fixed, encrypt_aes_128_ctr},
    convert::from_base64,
    mersenne::MT19937,
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
    let data: Vec<Vec<u8>> = include_str!("../data/challenge20.txt")
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
    let res: Vec<u8> = include_str!("../data/challenge20out.txt")
        .bytes()
        .filter(|&c| c != b'\n')
        .collect();
    assert_eq!(&decrypted, &res);
}

pub fn challenge21() {
    let rng = MT19937::new(1234);
    let nums: Vec<_> = rng.take(10).collect();
    assert_eq!(
        &nums,
        &[
            467891853, 2399847013, 2482137157, 3512589365, 2895582026, 2265913763, 3373089432,
            3312965625, 3349970575, 1855041653
        ]
    );
}

pub fn challenge22() {
    let mut rng = MT19937::new(1234);
    let offset = (rng.next().unwrap() % 960 + 40) as u64;
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - offset;
    let mut rng = MT19937::new(seed as u32);
    let n = rng.next().unwrap();
    let hacked_seed = {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut seed = 0;
        for o in 0..2000 {
            seed = now - o;
            let mut rng = MT19937::new(seed as u32);
            let m = rng.next().unwrap();
            if n == m {
                break;
            }
        }
        seed
    };
    assert_eq!(hacked_seed, seed);
}

#[test]
fn test_challenges() {
    challenge17();
    challenge18();
    challenge19();
    challenge20();
    challenge21();
    challenge22();
}
