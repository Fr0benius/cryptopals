#![allow(clippy::approx_constant)]
#![allow(clippy::new_without_default)]

pub mod ciphers;
pub mod convert;
pub mod freq;
pub mod util;
pub mod challenges;
pub mod oracles;

fn main() {
    challenges::challenge13();
}
