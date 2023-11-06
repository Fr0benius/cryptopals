#![allow(clippy::approx_constant)]
#![allow(clippy::new_without_default)]

pub mod ciphers;
pub mod convert;
pub mod freq;
pub mod util;
pub mod oracles;

pub mod set1;
pub mod set2;

fn main() {
    set2::challenge16();
}
