use std::cmp::min;

use crate::ciphers::encrypt_aes_128_ctr;

pub struct RandomAccessCTR {
    secret_key: [u8; 16],
    plain: Vec<u8>,
}

impl RandomAccessCTR {
    pub fn new(secret_key: &[u8], plain: &[u8]) -> Self {
        Self {
            secret_key: secret_key.try_into().unwrap(),
            plain: plain.to_vec(),
        }
    }
    pub fn ciphertext(&self) -> Vec<u8> {
        encrypt_aes_128_ctr(&self.plain, &self.secret_key, &[b'2'; 8])
    }
    pub fn edit(&mut self, offset: usize, new_text: &[u8]) {
        assert!(offset <= self.plain.len());
        let m = min(new_text.len(), self.plain.len() - offset);
        self.plain[offset..offset+m].copy_from_slice(&new_text[0..m]);
    }
}
