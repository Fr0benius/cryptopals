pub mod padding_attack;
pub mod ra_ctr;

use crate::{
    ciphers::{decrypt_aes_128_ecb, encrypt_aes_128_cbc, encrypt_aes_128_ecb},
    convert::from_base64,
    util::{parse_cookie, url_encode},
};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;

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

/// Oracle for challenge 12.
/// Adds a constant unknown suffix to the input, then encrypts in ECB mode.
/// Uses a secret but consistent key.
pub struct SecretSuffix {
    secret_key: [u8; 16],
    secret_message: Vec<u8>,
    prefix: Vec<u8>,
}

impl Oracle for SecretSuffix {
    fn query(&mut self, plain: &[u8]) -> Vec<u8> {
        let mut text = self.prefix.clone();
        text.extend_from_slice(plain);
        text.extend_from_slice(&self.secret_message);
        encrypt_aes_128_ecb(&text, &self.secret_key)
    }
}

impl SecretSuffix {
    pub fn new() -> Self {
        Self {
            secret_key: *b"MANNY && GLOTTIS",
            secret_message: from_base64(
                b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK",
            )
            .to_vec(),
            prefix: vec![],
        }
    }
    pub fn with_prefix() -> Self {
        let mut oracle = Self::new();
        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        let len = rng.gen::<usize>() % 32 + 16;
        for _ in 0..len {
            oracle.prefix.push(rng.gen());
        }
        oracle
    }
}

pub fn solve_secret_suffix(oracle: &mut SecretSuffix) -> Vec<u8> {
    // find block size and prefix+suffix length
    let (block_size, total_secret_length) = {
        let prev_len = oracle.query(&[]).len();
        let mut s = vec![b'a'];
        let block_size;
        let total_secret_length;
        loop {
            let len = oracle.query(&s).len();
            if len > prev_len {
                block_size = len - prev_len;
                total_secret_length = prev_len - s.len();
                break;
            }
            s.push(b'a');
        }
        (block_size, total_secret_length)
    };
    assert_eq!(block_size, 16);

    // find prefix length
    let mut prefix_length = 0;
    'outer: for k in 2 * block_size.. {
        let cipher = oracle.query(&vec![0; k]);
        for i in 0..cipher.len() / block_size - 1 {
            if cipher[block_size * i..block_size * (i + 1)]
                == cipher[block_size * (i + 1)..block_size * (i + 2)]
            {
                prefix_length = block_size * (i + 2) - k;
                break 'outer;
            }
        }
    }

    assert_eq!(prefix_length, oracle.prefix.len());
    let message_length = total_secret_length - prefix_length;
    assert_eq!(message_length, oracle.secret_message.len());

    let pref_pad_len = block_size - prefix_length % block_size;
    let prefix_padding = vec![0u8; pref_pad_len];
    let offset = prefix_length + pref_pad_len;

    // Attack!
    let mut message = vec![0u8; message_length];
    for k in 0..message_length {
        let mut test_bytes = prefix_padding.clone();
        if k >= block_size - 1 {
            test_bytes.extend_from_slice(&message[k - (block_size - 1)..k]);
        } else {
            test_bytes.extend_from_slice(&vec![0; block_size - 1 - k]);
            test_bytes.extend_from_slice(&message[..k]);
        };
        test_bytes.resize(pref_pad_len + 2 * block_size - 1 - k % block_size, 0);
        for byte in 0..=255 {
            test_bytes[pref_pad_len + block_size - 1] = byte;
            let cipher = oracle.query(&test_bytes);
            let block_start = prefix_length + test_bytes.len() + k - (block_size - 1);
            if cipher[offset..offset + block_size] == cipher[block_start..block_start + block_size]
            {
                message[k] = byte;
                break;
            }
        }
    }
    message
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
        Self {
            uid: 10,
            secret_key: *b"YELLOW SUBMARINE",
        }
    }
    pub fn parse(&self, encrypted_token: &[u8]) -> HashMap<Vec<u8>, Vec<u8>> {
        let plain = decrypt_aes_128_ecb(encrypted_token, &self.secret_key);
        parse_cookie(&plain, b'&')
    }
}
