use rand::Rng;
use rand_chacha::ChaCha8Rng;

pub struct Server {
    rng: ChaCha8Rng,
    base_time_micros: i64,
    var_time_micros: i64,
}

impl Server {
    pub fn new(rng: ChaCha8Rng, base_time_micros: i64, var_time_micros: i64) -> Self { Self { rng, base_time_micros, var_time_micros } }

    /// Compares two slices, character by character.
    /// Returns the (mock) total time taken for the comparison
    /// This is simulated by taking the base time and adding random noise.
    pub fn insecure_compare(&mut self, a: &[u8], b: &[u8]) -> (bool, i64) {
        let mut total_time = 0;
        for (&x, &y) in a.iter().zip(b) {
            total_time += self.base_time_micros
                + self
                    .rng
                    .gen_range(-self.var_time_micros..=self.var_time_micros);
            if x != y {
                return (false, total_time);
            }
        }
        (true, total_time)
    }
}
