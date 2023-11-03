// Taken from https://raw.githubusercontent.com/piersy/ascii-char-frequency-english/main/ascii_freq.txt
const RAW_ASCII_DATA: &str = include_str!("../data/ascii_freq.txt");
const RAW_LETTER_DATA: &str = include_str!("../data/letter_freq.txt");

type AsciiFreq = [f64; 128];

pub fn load_expected_freq() -> AsciiFreq {
    let mut freqs = [0.0; 128];
    for line in RAW_ASCII_DATA.lines() {
        let mut iter = line.split(':');
        let c: usize = iter.next().unwrap().parse().unwrap();
        let f: f64 = iter.next().unwrap().parse().unwrap();
        freqs[c] = f;
    }
    freqs
}

pub fn load_expected_letter_freq() -> AsciiFreq {
    let mut freqs = [0.0; 128];
    for line in RAW_LETTER_DATA.lines() {
        let mut iter = line.trim().split(':');
        let c: usize = iter.next().unwrap().as_bytes()[0] as usize;
        assert!((c as u8).is_ascii_alphabetic());
        let f: f64 = iter.next().unwrap().parse().unwrap();
        freqs[c] = f;
    }
    freqs
}

pub fn dist(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(&x, &y)| (x - y).abs()).sum()
}
