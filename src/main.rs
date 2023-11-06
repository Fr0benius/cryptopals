#![allow(clippy::approx_constant)]
#![allow(clippy::new_without_default)]

pub mod ciphers;
pub mod convert;
pub mod freq;
pub mod util;
pub mod set1;
pub mod oracles;

fn main() {
    set1::challenge16();
}
