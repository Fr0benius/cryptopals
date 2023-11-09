use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use crate::{
    ciphers::{decrypt_aes_128_cbc, encrypt_aes_128_cbc},
    convert::from_base64, util::unpad_in_place,
};

const TEXTS_B64: &[&[u8]] = &[
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

pub struct PadAttackServer {
    rng: ChaChaRng,
    secret_key: [u8; 16],
    last_plaintext: Vec<u8>,
}

impl PadAttackServer {
    pub fn new() -> Self {
        let mut rng = ChaChaRng::seed_from_u64(54321);
        let mut secret_key = [0; 16];
        rng.fill(&mut secret_key);
        Self {
            rng,
            secret_key,
            last_plaintext: vec![],
        }
    }

    pub fn last_plaintext(&self) -> &[u8] {
        &self.last_plaintext
    }

    /// Encrypts one of the plaintexts at random.
    /// Uses a random IV.
    /// Returns the ciphertext and IV used.
    pub fn encrypt(&mut self) -> (Vec<u8>, [u8; 16]) {
        let idx = self.rng.gen::<usize>() % TEXTS_B64.len();
        self.last_plaintext = from_base64(TEXTS_B64[idx]);
        let iv = {
            let mut v = [0u8; 16];
            self.rng.fill(&mut v);
            v
        };
        (
            encrypt_aes_128_cbc(&self.last_plaintext, &self.secret_key, &iv),
            iv,
        )
    }

    /// Attempts to decrypt the cipher with the given IV.
    /// Returns whether the plaintext has correct padding.
    pub fn check_padding(&self, cipher: &[u8], iv: &[u8]) -> bool {
        // Temporarily get rid of the normal panic hook (printing out an error message/stack trace)
        std::panic::set_hook(Box::new(|_| ()));
        let res = std::panic::catch_unwind(|| decrypt_aes_128_cbc(cipher, &self.secret_key, iv));
        // Restore the original panic hook
        let _ = std::panic::take_hook();
        res.is_ok()
    }
}

/// Given a ciphertext and IV, compute the plaintext by using the server's padding oracle
pub fn attack(server: &mut PadAttackServer, cipher: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_size = iv.len();
    let n = cipher.len();
    let mut plain = vec![0u8; n];
    for bl in (0..n / block_size).rev() {
        let mut test = iv.to_vec();
        test.extend_from_slice(&cipher[..(bl + 1) * block_size]);
        let start = bl * block_size;
        assert_eq!(start + 2 * block_size, test.len());

        for i in (0..block_size).rev() {
            for byte in 0..=255 {
                test[start + i] ^= byte;
                if !server.check_padding(&test[block_size..], &test[..block_size]) {
                    test[start + i] ^= byte;
                    continue;
                }
                // extra check for first character, in the rare case we didn't get 0x01
                let mut good = true;
                if i == block_size - 1 {
                    test[start + i - 1] ^= 1;
                    if !server.check_padding(&test[block_size..], &test[..block_size]) {
                        // unreachable!();
                        good = false;
                    }
                    test[start + i - 1] ^= 1;
                }
                if !good {
                    test[start + i] ^= byte;
                    continue;
                }
                let pad_byte = (block_size - i) as u8;
                plain[start + i] = pad_byte ^ byte;
                // prepare padding for previous byte
                for j in i..block_size {
                    test[start + j] ^= pad_byte ^ (pad_byte + 1);
                }
                break;
            }
        }
    }
    unpad_in_place(&mut plain);
    plain
}

