use openssl::symm::{Cipher, Crypter, Mode};

use crate::{
    freq::{dist, load_expected_freq},
    util::{pad, unpad_in_place},
};

/// Returns the xor of equal-length slices 'a' and 'b'.
pub fn fixed_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

/// Returns the xor of 'a' with 'b' repeated cyclically.
pub fn repeating_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter()
        .zip(b.iter().cycle())
        .map(|(&x, &y)| x ^ y)
        .collect()
}

/// Decrypts a single-character xor cipher by choosing the one that produces the best frequency
/// distribution. Returns the decrypted text and the score.
pub fn decrypt_caesar(a: &[u8]) -> (Vec<u8>, f64) {
    let mut best = vec![];
    let mut best_score = f64::MAX;
    let expected = load_expected_freq();
    for x in 0..=255 {
        let tmp = repeating_xor(a, &[x]);
        if !(tmp.iter().all(|&c| c < 128)) {
            continue;
        }
        let mut freq = [0.0; 128];
        for &k in &tmp {
            freq[k as usize] += 1.0;
        }
        for x in &mut freq {
            *x /= a.len() as f64;
        }
        let s = dist(&freq, &expected);
        if s < best_score {
            best = tmp;
            best_score = s
        }
    }
    (best, best_score)
}

/// Attempts to decrypt a list of texts, returns the one with the best score.
pub fn multiple_decrypt_caesar<'a, I>(texts: I) -> (Vec<u8>, f64)
where
    I: Iterator<Item = &'a [u8]>,
{
    let mut best = vec![];
    let mut best_score = f64::MAX;
    for a in texts {
        let (tmp, s) = decrypt_caesar(a);
        if s < best_score {
            best = tmp;
            best_score = s
        }
    }
    (best, best_score)
}

/// Attempts to decrypt a Vigenere-encrypted text with a fixed keysize
/// Returns the best candidate and score
pub fn decrypt_vigenere_fixed(s: &[u8], keysize: usize) -> (Vec<u8>, f64) {
    let mut blocks = vec![vec![]; keysize];
    let n = s.len();
    for i in 0..n {
        blocks[i % keysize].push(s[i]);
    }
    let mut avg_score = 0.0;
    let mut decrypted = vec![0u8; n];
    for k in 0..keysize {
        let (dec_block, score) = decrypt_caesar(&blocks[k]);
        avg_score += score / keysize as f64;
        for i in 0..blocks[k].len() {
            decrypted[i * keysize + k] = dec_block[i];
        }
    }
    (decrypted, avg_score)
}

/// Decrypt a text with aes 128 in ECB mode.
pub fn decrypt_aes_128_ecb(s: &[u8], key: &[u8]) -> Vec<u8> {
    let block_size = key.len();
    assert!(s.len() % block_size == 0);
    let aes = openssl::symm::Cipher::aes_128_ecb();
    openssl::symm::decrypt(aes, key, None, s).unwrap()
}

/// Encrypt a text with aes 128 in ECB mode.
pub fn encrypt_aes_128_ecb(s: &[u8], key: &[u8]) -> Vec<u8> {
    let aes = openssl::symm::Cipher::aes_128_ecb();
    openssl::symm::encrypt(aes, key, None, s).unwrap()
}

/// Decrypts a single block of bytes
pub fn decrypt_aes_128_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    // for some reason (having to do with padding/finalization) we can't use the regular decrypt
    // function. Have to use the lower-level Crypter API.
    let block_size = key.len();
    assert_eq!(block.len(), block_size);
    let mut plain = vec![0u8; 2 * block_size];
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    decrypter.update(block, &mut plain).unwrap();
    plain[..block_size].to_vec()
}

/// Decrypt a text with aes 128 in CBC mode.
/// Manual implementation by decrypting block by block.
/// Removes padding in the output.
pub fn decrypt_aes_128_cbc(s: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_size = key.len();
    assert!(s.len() % block_size == 0);
    let mut res = vec![];
    let mut prev_block = iv.to_vec();
    for block in s.chunks(16) {
        let plain = decrypt_aes_128_block(block, key);
        res.extend_from_slice(&fixed_xor(&plain, &prev_block));
        prev_block = block.to_vec();
    }
    unpad_in_place(&mut res);
    res
}

/// Encrypts a single block of bytes
pub fn encrypt_aes_128_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    let block_size = key.len();
    assert_eq!(block.len(), block_size);
    let mut plain = vec![0u8; 2 * block_size];
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    encrypter.update(block, &mut plain).unwrap();
    plain[..block_size].to_vec()
}

/// Encrypt a text with aes 128 in CBC mode.
/// Manual implementation by encrypting block by block.
/// Pads the input using PKCS#7 algorithm.
pub fn encrypt_aes_128_cbc(s: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_size = key.len();
    let mut res = vec![];
    let mut prev_block = iv.to_vec();
    for block in pad(s, block_size).chunks(16) {
        let cipher = encrypt_aes_128_block(&fixed_xor(block, &prev_block), key);
        res.extend_from_slice(&cipher);
        prev_block = cipher;
    }
    res
}

pub struct CTR {
    secret_key: [u8; 16],
    counter: [u8; 16],
}

impl Iterator for CTR {
    type Item = [u8; 16];

    fn next(&mut self) -> Option<Self::Item> {
        let res = encrypt_aes_128_block(&self.counter, &self.secret_key);
        for i in 8..16 {
            if self.counter[i] < u8::MAX {
                self.counter[i] += 1;
                break;
            }
            self.counter[i] = 0;
        }
        Some(res.try_into().unwrap())
    }
}

impl CTR {
    pub fn new(secret_key: &[u8], nonce: &[u8]) -> Self {
        let mut counter = [0; 16];
        counter[..8].copy_from_slice(&nonce[..8]);
        Self {
            secret_key: secret_key.try_into().expect("secret key must be 16 bytes"),
            counter,
        }
    }
}

/// Encrypts a text in ctr mode. Can also be used for decryption.
/// Requires a 16-byte secret key and an 8-byte nonce.
pub fn encrypt_aes_128_ctr(cipher: &[u8], secret_key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let ctr = CTR::new(secret_key, nonce);
    let mut res = vec![];
    for (w, k) in cipher.chunks(16).zip(ctr) {
        res.extend(w.iter().zip(k).map(|(&a, b)| a ^ b));
    }
    res
}
#[cfg(test)]
pub mod tests {
    use crate::convert::from_base64;

    use super::*;

    #[test]
    fn decrypt_vigenere_fixed_test() {
        let raw_data = include_str!("../data/challenge6.txt");
        let text = from_base64(raw_data.as_bytes());
        let expected = include_str!("../data/funky_music.txt");
        let (decrypted, _) = decrypt_vigenere_fixed(&text, 29);
        assert_eq!(decrypted, expected.as_bytes());
    }
}
