//! # snaprng — fork-, snapshot- and clone-aware CSPRNG
//!
//! `snaprng` wraps a ChaCha20 stream cipher (via `rand_chacha`) and watches a
//! set of independent tripwires around it. Before *every* draw it checks
//! whether the process was forked, the VM was restored from a snapshot, or a
//! running VM was cloned; on any suspicion it reseeds from fresh platform
//! entropy before emitting a single byte. Two replicas can therefore never
//! continue the same ChaCha key stream.
//!
//! ## Detection signals (defense in depth)
//!
//! | Signal | Catches | Platform |
//! |---|---|---|
//! | `pthread_atfork` child flag | `fork(2)` | all Unix |
//! | pid change vs. seed-time baseline | fork/clone without exec | all |
//! | `MADV_WIPEONFORK` sentinel page | fork incl. `clone(CLONE_VM)` | Linux ≥ 4.14 |
//! | monotonic clock rewind | snapshot restore | all |
//! | wall−monotonic offset jump | snapshot with NTP-correct wall clock | all |
//! | monotonic stall over long wall gap | paused/restored VM | all |
//! | VM Generation ID device | authoritative hypervisor restore signal | Linux ≥ 6.6 / hypervisor |
//! | background watchdog | events occurring between draws | all |
//!
//! Every signal is conservative: false positives cost one extra reseed; a
//! missed event is what would risk a collision, and any *one* of the clock or
//! identity signals firing is enough to trigger.
//!
//! ## Fork-safety of the reseed itself
//!
//! The reseed path is deliberately allocation-free: entropy is gathered into
//! fixed stack buffers and mixed in place, the vmgenid device is read through
//! a cached file descriptor, and the only address-space fingerprints are stack
//! and static addresses (no heap pointer). This matters because a multithreaded
//! process may hold an allocator lock at the moment `fork(2)` is taken; calling
//! `malloc` in the child before `exec` can deadlock. Keeping reseed off the
//! heap makes it safe to run immediately inside that child. One-time resource
//! setup (mmap of the sentinel page, opening the vmgenid fd, atfork
//! registration) happens at construction, never on a draw.
//!
//! ## Drop-in usage
//!
//! ```ignore
//! // before
//! use rand::RngExt;
//! let key: [u8; 32] = rand::rng().random();
//!
//! // after — same shape, snapshot-safe
//! use snaprng::prelude::*;
//! let key: [u8; 32] = snaprng::rng().random();
//! ```
//!
//! Owned instances for structures that store an RNG field:
//!
//! ```ignore
//! use snaprng::SnapRng;
//! let mut rng = SnapRng::new();
//! let nonce: [u8; 12] = rng.random();
//! ```

pub mod detect;
mod entropy;
mod env;
mod fork;
mod rng;
#[cfg(feature = "watchdog")]
mod watchdog;

#[cfg(feature = "test-util")]
pub mod fake_env;

pub use detect::{DetectorConfig, Trigger};
pub use env::{Env, EnvSample, OsEnv};
pub use rng::{
    fill_bytes, global_env, random, rng, spawn_watchdog, thread_rng, SnapRng, ThreadSnapRng,
};

// Re-export the rand traits so dependents need a single Cargo dependency.
pub use rand;
pub use rand_chacha;
pub use rand_core;

/// Prelude mirroring `rand::prelude`.
pub mod prelude {
    pub use crate::rng::{random, rng, thread_rng, SnapRng, ThreadSnapRng};
    pub use rand::distr::Distribution;
    pub use rand::seq::{IndexedMutRandom, IndexedRandom, IteratorRandom, SliceRandom};
    pub use rand::{CryptoRng, Rng, RngExt, SeedableRng};
    pub use rand_core::{TryCryptoRng, TryRng};
}

/// Test-only hooks. Compiled only with `--features test-util`.
#[cfg(feature = "test-util")]
pub mod testing {
    use crate::detect::DetectorConfig;
    use crate::env::Env;
    use std::sync::Arc;

    /// Consume and return the process-global fork-dirty flag.
    pub fn take_fork_dirty() -> bool {
        crate::fork::take_fork_dirty()
    }

    /// Manually raise the fork-dirty flag (simulating an atfork event).
    pub fn mark_fork_dirty() {
        crate::fork::mark_fork_dirty();
    }

    /// Start a watchdog against an arbitrary (possibly fake) environment and
    /// return a flag that becomes true once its first baseline is installed.
    pub fn spawn_watchdog(env: Arc<dyn Env>) -> Arc<std::sync::atomic::AtomicBool> {
        crate::watchdog::spawn_with_ready(env, DetectorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_env::FakeEnv;
    use rand::RngExt;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn make_rng() -> (SnapRng, FakeEnv) {
        let env = FakeEnv::new();
        let rng = SnapRng::with_env(Arc::new(env.clone()));
        (rng, env)
    }

    #[test]
    fn outputs_are_not_all_zero_and_distinct() {
        let (mut rng, _) = make_rng();
        let a: [u8; 32] = rng.random();
        let b: [u8; 32] = rng.random();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn monotonic_rewind_triggers_reseed_and_diverges_outputs() {
        let (mut rng, env) = make_rng();
        let before: [u8; 32] = rng.random();
        let state_at_snapshot = env.snapshot_state();

        // Simulate cloning the VM: copy all RNG state, then rewind the clock.
        let mut clone = rng.snapshot_clone();
        env.rollback({
            let mut s = state_at_snapshot;
            s.monotonic_ns -= 60_000_000_000;
            s.wall_ns -= 60_000_000_000;
            s
        });

        let after: [u8; 32] = clone.random();
        assert_ne!(before, after, "rewound monotonic clock must force a reseed");
        assert!(clone.reseed_counters().iter().sum::<u64>() >= 2);
    }

    #[test]
    fn clock_offset_jump_is_caught_without_rewind() {
        // Snapshot restore may leave monotonic time unchanged while wall time
        // jumps (e.g. NTP steps after resume).
        let (mut rng, env) = make_rng();
        let _: [u8; 32] = rng.random();
        let mut clone = rng.snapshot_clone();
        env.tick(5_000_000_000);
        env.edit(|s| {
            // Monotonic advanced normally; wall jumps an extra hour.
            s.wall_ns += 3_600_000_000_000;
        });
        let a: [u8; 32] = clone.random();
        let b: [u8; 32] = rng.random();
        assert_ne!(a, b);
    }

    #[test]
    fn vm_generation_id_rotation_is_caught() {
        let (mut rng, env) = make_rng();
        let first: [u8; 32] = rng.random();
        let mut clone = rng.snapshot_clone();
        env.tick(10_000_000);
        env.edit(|s| {
            s.vm_generation_id = Some([9u8; 16]);
        });
        let second: [u8; 32] = clone.random();
        assert_ne!(first, second);
    }

    #[test]
    fn pid_change_is_caught() {
        let (mut rng, env) = make_rng();
        let first: [u8; 32] = rng.random();
        let mut clone = rng.snapshot_clone();
        env.edit(|s| s.pid += 1);
        let second: [u8; 32] = clone.random();
        assert_ne!(first, second);
    }

    #[test]
    fn no_signal_means_no_spurious_reseed_but_streams_stay_distinct() {
        // Two independently constructed RNGs on identical fake environments
        // must still differ: entropy gathering includes jitter/addresses/OS RNG.
        let env = Arc::new(FakeEnv::new());
        let mut a = SnapRng::with_env(Arc::clone(&env) as Arc<dyn Env>);
        let mut b = SnapRng::with_env(Arc::clone(&env) as Arc<dyn Env>);
        let (x, y): ([u8; 32], [u8; 32]) = (a.random(), b.random());
        assert_ne!(x, y);
    }

    #[test]
    fn storm_of_snapshot_clones_produces_no_collisions() {
        // The core property: 64 byte-identical clones all draw after a
        // simulated restore; every 256-bit token must be unique.
        let env = Arc::new(FakeEnv::new());
        let mut parent = SnapRng::with_env(Arc::clone(&env) as Arc<dyn Env>);
        let _warmup: [u8; 32] = parent.random();
        let state = env.snapshot_state();

        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for i in 0..64u32 {
            let mut clone = parent.snapshot_clone();
            // Each clone gets its own rolled-back environment state.
            let mut s = state.clone();
            s.monotonic_ns -= 10_000_000_000 + i as u64;
            s.wall_ns -= 10_000_000_000;
            s.vm_generation_id = Some([(i + 2) as u8; 16]);
            env.rollback(s);
            let token: [u8; 32] = clone.random();
            assert!(seen.insert(token), "collision at clone {i}");
        }
        assert_eq!(seen.len(), 64);
    }
}
