pub struct Rng {
    state: u64,
}

impl Rng {
    #[inline]
    pub fn new(seed: u64) -> Self {
        Rng { state: seed }
    }

    #[inline]
    pub fn for_trial(base: u64, index: u64) -> Self {
        let mut z = base ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Rng { state: z ^ (z >> 31) }
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    #[inline]
    pub fn below(&mut self, n: u32) -> u32 {
        self.next_u32() % n
    }

    #[inline]
    pub fn boolean(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    #[inline]
    pub fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        &slice[self.below(slice.len() as u32) as usize]
    }

    pub fn operand(&mut self) -> u64 {
        const EDGES: [u64; 21] = [
            0,
            1,
            2,
            0x7f,
            0x80,
            0xff,
            0x100,
            0x7fff,
            0x8000,
            0xffff,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_ffff,
            0x1_0000_0000,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            0xffff_ffff_ffff_ffff,
            0xdead_beef,
            0xcafe_babe_dead_beef,
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
        ];
        match self.below(4) {
            0 => self.next_u64(),
            1 => self.next_u64() & 0xff,
            2 => *self.pick(&EDGES),
            _ => {
                let bits = self.below(63) + 1;
                self.next_u64() & ((1u64 << bits) - 1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trial_streams_are_independent_rather_than_shifted() {
        const G: u64 = 0x9E37_79B9_7F4A_7C15;
        let draws = |mut r: Rng| -> Vec<u64> { (0..8).map(|_| r.next_u64()).collect() };

        let one = draws(Rng::new(1 ^ 100u64.wrapping_mul(G)));
        let two = draws(Rng::new(1 ^ 102u64.wrapping_mul(G)));
        assert_eq!(one[2..], two[..6], "the old derivation really was a shift");

        let one = draws(Rng::for_trial(1, 100));
        let two = draws(Rng::for_trial(1, 102));
        assert!(
            one.iter().all(|v| !two.contains(v)),
            "two nearby trials share draws: {one:x?} vs {two:x?}"
        );

        assert_eq!(draws(Rng::for_trial(7, 42)), draws(Rng::for_trial(7, 42)));
        assert_ne!(draws(Rng::for_trial(7, 42)), draws(Rng::for_trial(8, 42)));
    }
}
