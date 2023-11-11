const W: usize = 32;
const N: usize = 624;
const M: usize = 397;
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
        let mut y = self.state[self.index];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

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

    fn twist(&mut self) {
        let lower_mask: u32 = (1 << R) - 1;
        let upper_mask: u32 = !lower_mask;
        for i in 0..N {
            let x = (self.state[i] & upper_mask) | (self.state[(i + 1) % N] & lower_mask);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                // lowest bit of x is 1
                x_a ^= x;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }
        self.index = 0
    }
}
