#![allow(clippy::approx_constant)]
#![allow(clippy::new_without_default)]

pub mod ciphers;
pub mod convert;
pub mod freq;
pub mod util;
pub mod oracles;

pub mod set1;
pub mod set2;
pub mod set3;
pub mod mersenne;

fn main() {
    // set3::challenge20();
    let rng = mersenne::MT19937::new(1234);
    for k in rng.take(10) {
        println!("{}", k);
    }
    println!("{}", u32::MAX);
}
