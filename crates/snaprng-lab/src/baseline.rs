//! Naive RNG baselines representing what production code looks like *without*
//! snapshot awareness. These exist solely to be measured against `SnapRng`:
//! every baseline is expected to produce collisions after a simulated clone.

use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng, TryCryptoRng, TryRng};

/// A plain ChaCha20 RNG with no tripwires — the exact pattern found in code
/// that constructs one CSPRNG at startup and stores it in a long-lived struct.
#[derive(Clone)]
pub struct NaiveChaCha {
    inner: ChaCha20Rng,
}

impl NaiveChaCha {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("platform entropy available");
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Byte-for-byte state copy — precisely what a VM memory snapshot does.
    pub fn snapshot_clone(&self) -> Self {
        self.clone()
    }
}

impl Default for NaiveChaCha {
    fn default() -> Self {
        Self::new()
    }
}

impl TryRng for NaiveChaCha {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.inner.next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.inner.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for NaiveChaCha {}

/// A deliberately weak counter "RNG" modeling code that derives nonces from a
/// process-local counter — a surprisingly common pattern. Snapshotting it
/// replays the entire counter interval.
#[derive(Clone)]
pub struct CounterRng {
    state: u64,
}

impl CounterRng {
    pub fn new() -> Self {
        Self { state: 0 }
    }
    pub fn snapshot_clone(&self) -> Self {
        self.clone()
    }
}

impl Default for CounterRng {
    fn default() -> Self {
        Self::new()
    }
}

impl TryRng for CounterRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.state = self.state.wrapping_add(1);
        Ok(self.state as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.state = self.state.wrapping_add(1);
        Ok(self.state)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            self.state = self.state.wrapping_add(1);
            let bytes = self.state.to_le_bytes();
            let take = chunk.len();
            chunk.copy_from_slice(&bytes[..take]);
        }
        Ok(())
    }
}

impl TryCryptoRng for CounterRng {}
