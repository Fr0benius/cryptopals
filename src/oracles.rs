use std::collections::HashMap;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    ciphers::{encrypt_aes_128_cbc, encrypt_aes_128_ecb, decrypt_aes_128_ecb},
    util::{url_encode, parse_cookie},
};

pub trait Oracle {
    fn query(&mut self, plain: &[u8]) -> Vec<u8>;
}

/// Oracle for challenge 11.
/// Adds fuzzing to the text by prefixing and suffixing 5 random bytes
/// then encrypts it either with CBC or ECB mode, chosen at random.
/// Uses a secret but consistent key.
/// Returns the ciphertext and the mode used (true for ECB)
pub struct EcbOrCbc {
    is_ecb: bool,
    secret_key: [u8; 16],
    rng: ChaCha8Rng,
}

impl EcbOrCbc {
    pub fn new(seed: u64) -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut secret_key = [0; 16];
        rng.fill(&mut secret_key);
        Self {
            is_ecb: false,
            secret_key,
            rng,
        }
    }
    pub fn is_ecb(&self) -> bool {
        self.is_ecb
    }
}

impl Oracle for EcbOrCbc {
    fn query(&mut self, plain: &[u8]) -> Vec<u8> {
        self.is_ecb = self.rng.gen();
        let mut text: Vec<u8> = vec![];
        let pref: usize = self.rng.gen_range(5..=10);
        let suf: usize = self.rng.gen_range(5..=10);
        for _ in 0..pref {
            text.push(self.rng.gen());
        }
        text.extend_from_slice(plain);
        for _ in 0..suf {
            text.push(self.rng.gen());
        }
        if self.is_ecb {
            encrypt_aes_128_ecb(&text, &self.secret_key)
        } else {
            let mut iv = [0u8; 16];
            self.rng.fill(&mut iv);
            encrypt_aes_128_cbc(&text, &self.secret_key, &iv)
        }
    }
}

pub struct UserProfile {
    uid: u64,
    secret_key: [u8; 16],
}

impl Oracle for UserProfile {
    fn query(&mut self, email: &[u8]) -> Vec<u8> {
        let mut plain = b"email=".to_vec();
        plain.extend_from_slice(&url_encode(email));
        plain.extend_from_slice(format!("&uid={}&role=user", self.uid).as_bytes());
        self.uid += 1;
        encrypt_aes_128_ecb(&plain, &self.secret_key)
    }
}

impl UserProfile {
    pub fn new() -> Self {
        Self { uid: 10 , secret_key: *b"YELLOW SUBMARINE"}
    }
    pub fn parse(&self, encrypted_token: &[u8]) -> HashMap<Vec<u8>, Vec<u8>> {
        let plain = decrypt_aes_128_ecb(encrypted_token, &self.secret_key);
        parse_cookie(&plain)
    }
}
