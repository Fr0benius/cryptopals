#![allow(clippy::approx_constant)]

pub mod ciphers;
pub mod convert;
pub mod freq;
pub mod util;
pub mod challenges;
pub mod oracles;

fn main() {
    challenges::challenge12();
}
