#![allow(clippy::approx_constant)]
#![allow(clippy::new_without_default)]

pub mod ciphers;
pub mod convert;
pub mod freq;
pub mod util;
pub mod oracles;
pub mod mersenne;

pub mod set1;
pub mod set2;
pub mod set3;
pub mod set4;

fn main() {
    set4::challenge27();
}
