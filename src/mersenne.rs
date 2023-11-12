const N: usize = 624;
const M: usize = 397;
const W: u32 = 32;
const F: u32 = 1812433253;
const B: u32 = 0x9D2C5680;
const C: u32 = 0xEFC60000;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const T: u32 = 15;
const U: u32 = 11;
const L: u32 = 18;
const R: u32 = 31;

pub struct MT19937 {
    state: [u32; N],
    index: usize,
}

impl Iterator for MT19937 {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= N {
            self.twist();
        }
        let y = temper(self.state[self.index]);
        self.index += 1;
        Some(y)
    }
}

impl MT19937 {
    pub fn new(seed: u32) -> Self {
        let mut state = [0; N];
        state[0] = seed;
        for i in 1..N {
            state[i] = (state[i - 1] ^ (state[i - 1] >> (W - 2)))
                .wrapping_mul(F)
                .wrapping_add(i as u32);
        }
        Self { state, index: N }
    }

    pub fn from_state(state: [u32; N]) -> Self {
        Self { state, index: N }
    }

    fn twist(&mut self) {
        let lower_mask: u32 = (1 << R) - 1;
        let upper_mask: u32 = !lower_mask;
        for i in 0..N {
            let x = (self.state[i] & upper_mask) | (self.state[(i + 1) % N] & lower_mask);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= x;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }
        self.index = 0
    }
}

fn temper(mut y: u32) -> u32 {
    y = y ^ ((y >> U) & D);
    y = y ^ ((y << S) & B);
    y = y ^ ((y << T) & C);
    y = y ^ (y >> L);
    y
}

fn inv_xor_lsh(mut x: u32, sh: u32, mask: u32) -> u32 {
    let mut res = 0;
    while x != 0 {
        res ^= x;
        x = (x << sh) & mask;
    }
    res
}
fn inv_xor_rsh(mut x: u32, sh: u32, mask: u32) -> u32 {
    let mut res = 0;
    while x != 0 {
        res ^= x;
        x = (x >> sh) & mask;
    }
    res
}

pub fn untemper(mut y: u32) -> u32 {
    y = inv_xor_rsh(y, L, D);
    y = inv_xor_lsh(y, T, C);
    y = inv_xor_lsh(y, S, B);
    y = inv_xor_rsh(y, U, D);
    y
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn temper_test() {
        let x = 0xDEADBEEF;
        assert_eq!(untemper(temper(x)), x);
        assert_eq!(temper(untemper(x)), x);
    }
}
